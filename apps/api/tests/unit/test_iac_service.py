"""From a finding's rule to a diff of the customer's file (DECISIONS.md §184).

The engine is tested on its own in ``test_iac_terraform``; this is the seam
between it and the rules -- which arguments a rule asks for, on which resource
types -- and the answer the API gives, including the ones that are not a diff.
"""

from dataclasses import replace
from pathlib import Path

import pytest

from app.remediation import Comparison
from app.remediation.iac.terraform import CHECKED_RELEASES
from app.remediation.spec import ExpectedState
from app.rules.registry import get_rule
from app.services.iac import propose_terraform_fix, upload_filename

ACCOUNT = """\
resource "azurerm_storage_account" "logs" {
  name            = "prodlogs"
  min_tls_version = "TLS1_0"
}
"""


def propose(rule_id: str, source: str = ACCOUNT, name: str | None = "prodlogs", **kw):
    rule = get_rule(rule_id)
    assert rule is not None
    return propose_terraform_fix(rule, name, filename="main.tf", source=source, **kw)


def test_a_fix_the_file_can_take_is_a_diff() -> None:
    # AZ-STO-003: HTTPS only, and TLS 1.2 or better.
    out = propose("AZ-STO-003")
    assert out.outcome == "patched"
    assert out.decline_reason is None
    assert out.diff is not None and out.diff.startswith("--- a/main.tf\n")
    assert [(e.attribute, e.before, e.after) for e in out.edits] == [
        ("https_traffic_only_enabled", None, "true"),
        ("min_tls_version", '"TLS1_0"', '"TLS1_2"'),
    ]


def test_a_setting_better_than_asked_is_left_alone() -> None:
    # AZ-STO-002 asks for TLS 1.2 and also accepts 1.3.
    source = ACCOUNT.replace('"TLS1_0"', '"TLS1_3"')
    out = propose("AZ-STO-002", source=source)
    assert out.outcome == "patched"
    assert [e.attribute for e in out.edits] == ["https_traffic_only_enabled"]


def test_a_decline_is_data_with_its_reason() -> None:
    out = propose("AZ-STO-003", name="elsewhere")
    assert out.outcome == "declined"
    assert out.decline_reason == "no_match"
    assert out.detail
    assert out.diff is None
    assert out.edits == []


def test_a_rule_without_terraform_arguments_is_not_editable() -> None:
    # AZ-ID-001 is a directory setting: there is no resource to edit.
    out = propose("AZ-ID-001")
    assert (out.outcome, out.decline_reason) == ("declined", "not_editable")


def test_a_finding_without_one_resource_is_not_editable() -> None:
    out = propose("AZ-STO-003", name=None)
    assert (out.outcome, out.decline_reason) == ("declined", "not_editable")


def test_an_aws_rule_is_not_editable_while_aws_is_unverified() -> None:
    out = propose("AWS-STO-001")
    assert (out.outcome, out.decline_reason) == ("declined", "not_editable")


def test_an_upload_is_read_as_utf8() -> None:
    assert propose("AZ-STO-003", source=ACCOUNT.encode()).outcome == "patched"


def test_an_upload_that_is_not_text_declines_rather_than_being_mangled() -> None:
    out = propose("AZ-STO-003", source=b"\xff\xfe" + ACCOUNT.encode("utf-16-le"))
    assert (out.outcome, out.decline_reason) == ("declined", "parse_error")


def test_an_oversized_upload_is_refused_on_its_size_not_its_encoding() -> None:
    # The route reads one byte past the cap, which can split a character.
    out = propose("AZ-STO-003", source=ACCOUNT.encode() + "é".encode() * 200_000)
    assert out.decline_reason == "too_large"


@pytest.mark.parametrize(
    ("given", "kept"),
    [
        ("storage.tf", "storage.tf"),
        ("../../etc/passwd", "passwd"),
        ("C:\\infra\\prod\\main.tf", "main.tf"),
        ("a\nb.tf", "ab.tf"),
        ("", "main.tf"),
        (None, "main.tf"),
    ],
)
def test_the_filename_in_the_diff_is_a_plain_name(given: str | None, kept: str) -> None:
    assert upload_filename(given) == kept


def test_a_rule_the_registry_no_longer_has_is_not_editable() -> None:
    out = propose_terraform_fix(None, "prodlogs", filename="main.tf", source=ACCOUNT)
    assert out.decline_reason == "not_editable"


def test_an_uploaded_file_matches_its_only_block_and_says_how() -> None:
    interpolated = ACCOUNT.replace('"prodlogs"', "var.account_name")
    out = propose("AZ-STO-003", source=interpolated, sole_block=True)
    assert (out.outcome, out.matched_by) == ("patched", "sole_block")


def test_matching_the_only_block_is_opt_in() -> None:
    interpolated = ACCOUNT.replace('"prodlogs"', "var.account_name")
    assert propose("AZ-STO-003", source=interpolated).decline_reason == "interpolated_name"


def test_a_name_match_says_so() -> None:
    assert propose("AZ-STO-003").matched_by == "name"
    assert propose("AZ-STO-003", name="elsewhere").matched_by is None


def test_the_answer_says_what_it_was_checked_against() -> None:
    out = propose("AZ-STO-003")
    assert out.provider_version is None
    assert out.checked_against == list(CHECKED_RELEASES)


def test_the_checked_releases_are_the_schema_fixtures() -> None:
    fixtures = Path(__file__).parents[1] / "fixtures/terraform"
    assert sorted(p.stem.removeprefix("azurerm-") for p in fixtures.glob("*.json")) == sorted(
        CHECKED_RELEASES
    )


def test_a_collection_state_is_never_written_even_when_declared() -> None:
    # NOT_EMPTY has no one value to write: ``terraform_hints`` renders it as
    # ``null``, which lifts the very restriction the rule asks for. The service
    # refuses it itself rather than trusting every spec to leave it out (§184).
    base = get_rule("AZ-STO-003")
    assert base is not None
    spec = replace(
        base.remediation_spec,
        expected=(
            ExpectedState(
                field="ip_rules",
                equals=None,
                comparison=Comparison.NOT_EMPTY,
                describes="Only named addresses reach the account",
                terraform_attribute="network_rules.ip_rules",
            ),
        ),
    )
    rule = type("CollectionRule", (type(base),), {"remediation_spec": spec})()
    out = propose_terraform_fix(rule, "prodlogs", filename="main.tf", source=ACCOUNT)
    assert (out.outcome, out.decline_reason) == ("declined", "not_editable")


def test_a_registry_argument_written_as_a_block_is_edited() -> None:
    # azurerm declares ``network_rule_set`` as an attribute that files write in
    # block form; the engine edits the value inside it.
    source = """\
resource "azurerm_container_registry" "images" {
  name = "prodimages"
  network_rule_set {
    default_action = "Allow"
  }
}
"""
    out = propose("AZ-ACR-002", source=source, name="prodimages")
    assert out.outcome == "patched"
    assert [(e.attribute, e.before, e.after) for e in out.edits] == [
        ("network_rule_set.default_action", '"Allow"', '"Deny"')
    ]


def test_http2_is_set_in_the_web_apps_site_config() -> None:
    source = """\
resource "azurerm_linux_web_app" "site" {
  name = "prodsite"
  site_config {
    always_on = true
  }
}
"""
    out = propose("AZ-WEB-010", source=source, name="prodsite")
    assert out.outcome == "patched"
    assert [(e.attribute, e.before, e.after) for e in out.edits] == [
        ("site_config.http2_enabled", None, "true")
    ]
