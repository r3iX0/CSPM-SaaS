"""ISO 27001, SOC 2, PCI DSS, NIST CSF 2.0 and CIS Controls v8.1, kept in full.

The catalogue lists a standard completely so a coverage figure has the whole standard as its
denominator, and a sealed audit package can say which controls a scan did not reach as well as
which it did (DECISIONS.md section 205). These tests hold the counts the published standards
have, and the rule that keeps a superseded version from being offered beside its successor.
"""

import re

import pytest

from app.compliance.catalog import FRAMEWORKS, get_framework
from app.compliance.crosswalk import compliance_mappings_for, crosswalk
from app.core.enums import Provider
from app.rules.registry import RULE_REGISTRY
from app.services.compliance import frameworks_for

STANDARDS = (
    "ISO_27001",
    "NIST_CSF_2.0",
    "SOC2",
    "PCI_DSS_4",
    "CIS_CONTROLS_8.1",
    "CSA_CCM_4.1",
    "NIST_800_171_R2",
    "DORA",
)

# Safeguards in each of the eighteen CIS Controls, as v8.1 publishes them.
CIS_SAFEGUARDS_PER_CONTROL = (5, 7, 14, 12, 6, 8, 7, 12, 7, 7, 5, 8, 11, 9, 7, 14, 9, 5)

# Controls in each of the seventeen CSA CCM v4.1 domains.
CCM_CONTROLS_PER_DOMAIN = {
    "A&A": 6,
    "AIS": 8,
    "BCR": 11,
    "CCC": 9,
    "CEK": 21,
    "DCS": 18,
    "DSP": 19,
    "GRC": 8,
    "HRS": 13,
    "I&S": 9,
    "IAM": 15,
    "IPY": 4,
    "LOG": 14,
    "SEF": 10,
    "STA": 16,
    "TVM": 12,
    "UEM": 14,
}

# Principal requirements in each of PCI DSS v4.0.1's twelve requirements.
PCI_PRINCIPALS_PER_REQUIREMENT = (5, 3, 7, 2, 4, 5, 3, 6, 5, 7, 6, 10)


def framework(framework_id: str):
    found = get_framework(framework_id)
    assert found is not None, framework_id
    return found


@pytest.mark.parametrize(
    ("framework_id", "count"),
    [
        ("ISO_27001", 93),
        ("NIST_CSF_2.0", 106),
        ("SOC2", 61),
        ("PCI_DSS_4", 64),
        ("CIS_CONTROLS_8.1", 153),
        ("CSA_CCM_4.1", 207),
        ("NIST_800_171_R2", 110),
        ("DORA", 27),
    ],
)
def test_each_standard_is_listed_in_full(framework_id: str, count: int) -> None:
    assert len(framework(framework_id).controls) == count


class TestIso27001:
    def test_annex_a_is_93_controls_in_four_themes(self) -> None:
        by_theme: dict[str, set[int]] = {}
        for control in framework("ISO_27001").controls:
            match = re.fullmatch(r"A\.(\d)\.(\d+)", control.id)
            assert match, control.id
            by_theme.setdefault(match.group(1), set()).add(int(match.group(2)))

        assert {theme: max(numbers) for theme, numbers in by_theme.items()} == {
            "5": 37,
            "6": 8,
            "7": 14,
            "8": 34,
        }
        assert all(numbers == set(range(1, max(numbers) + 1)) for numbers in by_theme.values())

    def test_the_physical_theme_is_beyond_a_scanner(self) -> None:
        physical = [c for c in framework("ISO_27001").controls if c.group == "Physical"]

        assert len(physical) == 14
        assert not any(c.technically_assessable for c in physical)


class TestNistCsf:
    def test_only_version_2_is_offered(self) -> None:
        """CSF 1.1 identifiers (`PR.AC-1`) are not offered beside 2.0's (`PR.AA-01`): the same
        name for two versions would split one rule's evidence across both."""
        assert get_framework("NIST_CSF") is None
        assert [f.id for f in FRAMEWORKS if f.id.startswith("NIST_CSF")] == ["NIST_CSF_2.0"]

    def test_every_identifier_is_a_2_0_subcategory(self) -> None:
        for control in framework("NIST_CSF_2.0").controls:
            assert re.fullmatch(r"(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}", control.id), control.id
            assert not control.title.startswith("[Withdrawn"), control.id

    def test_the_six_functions_are_present(self) -> None:
        groups = {c.group.split(" - ")[0] for c in framework("NIST_CSF_2.0").controls}

        assert groups == {"Govern", "Identify", "Protect", "Detect", "Respond", "Recover"}

    def test_every_rule_maps_to_it_with_ids_it_defines(self) -> None:
        defined = {c.id for c in framework("NIST_CSF_2.0").controls}
        for rule in RULE_REGISTRY:
            mapped = (rule.compliance_mappings or {}).get("NIST_CSF_2.0")
            assert mapped, f"{rule.rule_id} reaches no CSF 2.0 subcategory"
            assert set(mapped) <= defined, rule.rule_id


class TestCisControls:
    def test_eighteen_controls_with_their_published_safeguard_counts(self) -> None:
        per_control: dict[int, int] = {}
        for safeguard in framework("CIS_CONTROLS_8.1").controls:
            number = int(safeguard.id.split(".")[0])
            per_control[number] = per_control.get(number, 0) + 1

        assert per_control == dict(enumerate(CIS_SAFEGUARDS_PER_CONTROL, start=1))

    def test_only_the_latest_version_is_offered(self) -> None:
        assert [f.id for f in FRAMEWORKS if f.id.startswith("CIS_CONTROLS")] == ["CIS_CONTROLS_8.1"]

    def test_the_mapping_reaches_nearly_every_rule(self) -> None:
        """The crosswalk test already refuses an unknown control. This one holds that the
        hand-written mapping reaches most rules, so a rule left out is a decision and not a
        forgotten entry."""
        rule_ids = {rule.rule_id for rule in RULE_REGISTRY}
        mapped = {rule_id for rule_id, maps in crosswalk().items() if "CIS_CONTROLS_8.1" in maps}

        assert mapped <= rule_ids
        assert len(mapped) >= len(rule_ids) * 0.9

    def test_the_safeguards_no_scanner_reaches_are_marked(self) -> None:
        unassessable = {
            c.id for c in framework("CIS_CONTROLS_8.1").controls if not c.technically_assessable
        }

        assert {"9.5", "14.1", "17.4", "18.1"} <= unassessable


class TestCsaCcm:
    def test_seventeen_domains_with_their_published_control_counts(self) -> None:
        per_domain: dict[str, int] = {}
        for control in framework("CSA_CCM_4.1").controls:
            domain = control.id.split("-")[0]
            per_domain[domain] = per_domain.get(domain, 0) + 1

        assert per_domain == CCM_CONTROLS_PER_DOMAIN

    def test_only_the_latest_version_is_offered(self) -> None:
        assert [f.id for f in FRAMEWORKS if f.id.startswith("CSA_CCM")] == ["CSA_CCM_4.1"]


class TestNist800171:
    def test_fourteen_families_with_their_published_requirement_counts(self) -> None:
        per_family: dict[str, int] = {}
        for requirement in framework("NIST_800_171_R2").controls:
            family = ".".join(requirement.id.split(".")[:2])
            per_family[family] = per_family.get(family, 0) + 1

        assert per_family == {
            f"3.{number}": count
            for number, count in enumerate((22, 3, 9, 9, 11, 3, 6, 9, 2, 6, 3, 4, 16, 7), start=1)
        }

    def test_it_is_revision_2_because_cmmc_assesses_revision_2(self) -> None:
        """Revision 3 is NIST's latest, and CMMC Level 2 still assesses Revision 2. The
        scope note says which and why, so the choice is not silent."""
        catalogue = framework("NIST_800_171_R2")

        assert "Revision 3" in catalogue.scope_note
        assert "CMMC" in catalogue.scope_note
        assert get_framework("NIST_800_171_R3") is None


class TestDora:
    def test_it_lists_the_articles_that_bind_a_financial_entity(self) -> None:
        articles = [int(c.id.removeprefix("Art.")) for c in framework("DORA").controls]

        assert articles == [*range(5, 31), 45]

    def test_the_oversight_of_critical_providers_is_left_out_and_said(self) -> None:
        assert "31 to 44" in framework("DORA").scope_note


class TestPci:
    def test_every_principal_requirement_has_a_row(self) -> None:
        """A principal requirement is represented by itself, or by a sub-requirement listed
        beneath it, so none of the sixty-four is silently absent."""
        present = {
            ".".join(control.id.split(".")[:2]) for control in framework("PCI_DSS_4").controls
        }
        expected = {
            f"{requirement}.{principal}"
            for requirement, count in enumerate(PCI_PRINCIPALS_PER_REQUIREMENT, start=1)
            for principal in range(1, count + 1)
        }

        assert present == expected


@pytest.mark.parametrize("framework_id", STANDARDS)
class TestEveryStandard:
    def test_it_is_not_tied_to_a_cloud(self, framework_id: str) -> None:
        assert framework(framework_id).provider is None

    def test_it_is_offered_to_an_organization_on_either_cloud(self, framework_id: str) -> None:
        for providers in ({Provider.AZURE}, {Provider.AWS}, set()):
            assert framework_id in {f.id for f in frameworks_for(providers)}

    def test_it_says_what_it_does_not_claim(self, framework_id: str) -> None:
        catalogue = framework(framework_id)
        words = f"{catalogue.summary} {catalogue.scope_note}".lower()

        assert len(catalogue.scope_note) > 120
        assert "compliant" not in words
        assert "certified" not in words

    def test_it_lists_what_no_rule_covers_and_what_no_scanner_can(self, framework_id: str) -> None:
        catalogue = framework(framework_id)
        covered = {
            control_id
            for rule in RULE_REGISTRY
            for control_id in compliance_mappings_for(
                rule.rule_id, rule.compliance_mappings or {}
            ).get(framework_id, [])
        }

        assert covered
        assert [c for c in catalogue.controls if c.id not in covered]
        assert [c for c in catalogue.controls if not c.technically_assessable]
