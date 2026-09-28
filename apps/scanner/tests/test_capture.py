"""What a run records: errors filed where they belong, results in the API's shape."""

import json
import logging
import zlib
from types import SimpleNamespace

from cloudguard_scanner.capture import ErrorCapture, RunOutcome, canonical, encode, serialize


def _record(
    message: str,
    pathname: str = "/srv/app.py",
    level: int = logging.ERROR,
    name: str = "root",
) -> logging.LogRecord:
    return logging.LogRecord(name, level, pathname, 1, message, None, None)


def test_a_service_error_is_filed_under_its_service() -> None:
    capture = ErrorCapture(["storage_ensure_minimum_tls_version_12"])
    capture.emit(
        _record(
            "sub-1 -- HttpResponseError[74]: AuthorizationFailed",
            "/venv/site-packages/prowler/providers/azure/services/storage/storage_service.py",
        )
    )
    assert capture.services == {"storage": ["sub-1 -- HttpResponseError[74]: AuthorizationFailed"]}
    assert capture.checks == {}


def test_a_check_that_raised_is_filed_under_the_check() -> None:
    check = "storage_ensure_minimum_tls_version_12"
    capture = ErrorCapture([check])
    # The check runner's wording, and the scan loop's.
    capture.emit(_record(f"{check} -- KeyError[12]: 'tls'", "/prowler/lib/check/check.py"))
    capture.emit(_record("other_check - ValueError[3]: x", "/prowler/lib/scan/scan.py"))
    assert capture.checks == {check: f"{check} -- KeyError[12]: 'tls'"}
    assert capture.other == ["other_check - ValueError[3]: x"]


def test_messages_per_service_are_bounded() -> None:
    capture = ErrorCapture([])
    path = "/prowler/providers/aws/services/s3/s3_service.py"
    for index in range(20):
        capture.emit(_record(f"AccessDenied {index}", path))
    assert len(capture.services["s3"]) == 5


def test_warnings_are_not_captured() -> None:
    capture = ErrorCapture([])
    logger = logging.getLogger("capture-test")
    logger.addHandler(capture)
    try:
        logger.warning("not an error")
    finally:
        logger.removeHandler(capture)
    assert capture.summary() == {"fatal": None, "services": {}, "checks": {}, "other": []}


def test_a_refusal_logged_as_a_warning_is_captured() -> None:
    # How Prowler logs an Azure resource group it could not list.
    capture = ErrorCapture([])
    capture.emit(
        _record(
            "Subscription ID: sub -- Resource Group: rg -- HttpResponseError[60]: "
            "(AuthorizationFailed) The client does not have authorization",
            "/prowler/providers/azure/services/vm/vm_service.py",
            level=logging.WARNING,
        )
    )
    assert list(capture.services) == ["vm"]


def test_a_benign_warning_is_not_captured() -> None:
    capture = ErrorCapture([])
    capture.emit(
        _record(
            "eu-west-1 -- ClientError[88]: Operation is not supported in this region",
            "/prowler/providers/aws/services/glue/glue_service.py",
            level=logging.WARNING,
        )
    )
    assert capture.summary()["services"] == {}


def test_an_error_from_shared_code_is_filed_under_the_service_that_called_it() -> None:
    # The base class that builds every Azure service's clients logs from
    # lib/service/service.py; the service is found a few frames up.
    capture = ErrorCapture([])
    source = (
        "def build(capture, record):\n"
        "    capture.emit(record)\n"
    )
    namespace: dict[str, object] = {}
    # Compiled under a service's path, to stand in for that service's frame.
    exec(
        compile(source, "/prowler/providers/azure/services/keyvault/keyvault_service.py", "exec"),
        namespace,
    )
    record = _record(
        "ClientAuthenticationError[12]: token",
        "/prowler/providers/azure/lib/service/service.py",
    )
    namespace["build"](capture, record)  # type: ignore[operator]
    assert list(capture.services) == ["keyvault"]
    assert capture.other == []


def test_the_scanners_own_records_are_not_prowlers() -> None:
    capture = ErrorCapture([])
    capture.emit(_record("scanner.lease_renew_failed", name="cloudguard_scanner"))
    assert capture.summary()["other"] == []


def test_serialize_keeps_what_a_finding_needs_and_not_the_service_object() -> None:
    finding = SimpleNamespace(
        check_id="s3_bucket_public_access",
        status=SimpleNamespace(value="FAIL"),
        status_extended="Bucket x is public.",
        resource_uid="arn:aws:s3:::x",
        resource_name="x",
        region="eu-west-1",
        resource_tags={"env": "prod"},
        resource_details="d" * 5000,
        resource_metadata={"Policy": "the whole bucket policy"},
    )
    result = serialize(finding)
    assert result["status"] == "FAIL"
    assert result["resource_uid"] == "arn:aws:s3:::x"
    assert len(result["resource_details"]) == 2000
    assert "resource_metadata" not in result


def test_encoding_matches_the_apis() -> None:
    """The API decompresses with zlib and parses canonical JSON
    (apps/api/app/core/payloads.py). Pinned here because the two sides share
    no code."""
    payload = {"b": [1, 2], "a": {"z": 1, "y": None}}
    encoded = encode(payload)
    assert canonical(payload) == b'{"a":{"y":null,"z":1},"b":[1,2]}'
    assert json.loads(zlib.decompress(encoded.compressed)) == payload
    assert encoded.byte_size == len(canonical(payload))


def test_outcome_says_partial_when_anything_went_unread() -> None:
    assert RunOutcome(requested=["a"], completed=["a"]).outcome == "COMPLETE"
    assert RunOutcome(requested=["a", "b"], completed=["a"]).outcome == "PARTIAL"
    assert (
        RunOutcome(requested=["a"], completed=["a"], errors={"services": {"s3": ["x"]}}).outcome
        == "PARTIAL"
    )
    assert RunOutcome(requested=["a"], errors={"fatal": "denied"}).outcome == "FAILED"
    # An error Prowler logged that belongs to no service or check is still
    # something it could not do.
    assert RunOutcome(requested=["a"], completed=["a"], errors={"other": ["x"]}).outcome == (
        "PARTIAL"
    )
