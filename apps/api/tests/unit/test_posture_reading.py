"""The posture reading, built from what the queries return (DECISIONS.md section 235).

The dashboard, the stored history and the score movement each used to compute the
same numbers from the same rows, and the dashboard's delta subtracted one copy
from the other. ``reading_from`` is the arithmetic those readers now share, so
these tests need no database; the queries that feed it are covered where the
dashboard and the pipeline already run against Postgres.
"""

from uuid import uuid4

from app.core.enums import Level
from app.risk.scorer import default_scorer
from app.services.posture_reading import reading_from


def test_an_estate_with_nothing_open_is_a_perfect_score_and_an_empty_ledger() -> None:
    reading = reading_from(charges={}, severity_counts={}, attack_path_count=0)

    assert reading.security_score == 100
    assert reading.open_finding_count == 0
    assert reading.risk_bands == {}
    assert reading.findings_by_severity == {}
    assert reading.attack_path_count == 0
    assert reading.ledger == {}


def test_the_ledger_names_each_risk_by_the_band_it_was_charged_at() -> None:
    sure, unsure = uuid4(), uuid4()
    charges = {sure: (Level.CRITICAL, Level.CRITICAL), unsure: (Level.HIGH, Level.LOW)}

    reading = reading_from(charges=charges, severity_counts={}, attack_path_count=0)

    assert reading.ledger == {str(sure): "CRITICAL", str(unsure): "LOW"}


def test_open_findings_are_counted_from_findings_not_from_the_risks_that_group_them() -> None:
    """One risk grouping forty findings is still forty open findings."""
    charges = {uuid4(): (Level.HIGH, Level.HIGH)}

    reading = reading_from(
        charges=charges, severity_counts={"HIGH": 38, "MEDIUM": 2}, attack_path_count=3
    )

    assert reading.open_finding_count == 40
    assert reading.findings_by_severity == {"HIGH": 38, "MEDIUM": 2}
    assert reading.risk_bands == {"HIGH": 1}
    assert reading.attack_path_count == 3


def test_the_score_charges_what_can_be_shown_and_the_bands_show_what_ranks() -> None:
    """An unlabelled production database ranks high but is only charged for what is known."""
    charges = {uuid4(): (Level.HIGH, Level.LOW)}

    reading = reading_from(charges=charges, severity_counts={"HIGH": 1}, attack_path_count=0)

    assert reading.risk_bands == {"HIGH": 1}
    assert reading.security_score == default_scorer.security_score([Level.LOW])
    assert reading.security_score > default_scorer.security_score([Level.HIGH])
