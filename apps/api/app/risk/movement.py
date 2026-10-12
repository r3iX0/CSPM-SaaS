"""Why the security score moved: its change split into causes that add up to it (§235).

The score is ``100 * exp(-D / k)``, where ``D`` sums a deduction per open
finding risk by the band it is charged at (``RiskScorer.security_score``). A
movement is therefore the risks whose charge changed between two readings, and
each of those is given a cause by the caller. What is left here is the
arithmetic: a curve is not a sum, so the points cannot be had by scoring each
cause alone, and doing the causes one after another would give a different
answer for every order.

The split is made in the curve's own terms. ``ln S`` is linear in ``D``, so the
exact change ``S1 - S0`` is ``L * ln(S1 / S0)``, where ``L`` is the logarithmic
mean of the two scores, and each cause takes ``-L * dD_i / k`` of it. The parts
are exact, signed, independent of order, and sum to the change. The rounding to
whole points then lands on the causes nearest the next point, so they sum to the
delta the dashboard shows.

Pure: no database, no clock.
"""

import math
from collections.abc import Mapping
from enum import StrEnum

from app.core.enums import Level
from app.risk.config import RiskEngineConfig


class Cause(StrEnum):
    """What moved a risk's charge. The value is what the API returns."""

    NEW_FAILURES = "new_failures"
    FIXES_VERIFIED = "fixes_verified"
    RULES_CHANGED = "rules_changed"
    ASSETS_APPEARED = "assets_appeared"
    # Its findings went with a deleted connection or scan (§124).
    ASSETS_REMOVED = "assets_removed"
    ACCEPTANCES_EXPIRED = "acceptances_expired"
    ACCEPTED = "accepted"
    # A person changed its status: a false positive, or reopened by hand.
    BY_HAND = "by_hand"
    # The same finding, charged at another band: the asset's exposure,
    # criticality or sensitivity changed, or what reaches it did.
    CONTEXT_CHANGED = "context_changed"
    # Nothing recorded says why. Shown, never folded into another cause.
    UNEXPLAINED = "unexplained"


def charge_changes[K](
    before: Mapping[K, Level], after: Mapping[K, Level], config: RiskEngineConfig
) -> dict[K, float]:
    """Each risk whose deduction differs between two readings, by how much it rose."""
    deductions = config.score_deductions
    changed: dict[K, float] = {}
    for key in before.keys() | after.keys():
        now = deductions.get(after[key], 0) if key in after else 0
        then = deductions.get(before[key], 0) if key in before else 0
        if now != then:
            changed[key] = float(now - then)
    return changed


def total_deduction[K](levels: Mapping[K, Level], config: RiskEngineConfig) -> float:
    return float(sum(config.score_deductions.get(level, 0) for level in levels.values()))


def split(
    rises: Mapping[Cause, float],
    *,
    before: float,
    after: float,
    config: RiskEngineConfig,
    target: int,
) -> dict[Cause, tuple[int, float]]:
    """Each cause's share of the score's movement, as whole points and exactly.

    ``rises`` is each cause's summed rise in deduction; ``before`` and ``after``
    the total deductions of the two readings; ``target`` the movement the
    dashboard shows, from the two rounded scores. Whatever the curve does not
    account for -- a scoring change between the readings, beyond rounding -- is
    given to ``UNEXPLAINED`` rather than spread over causes it did not come from.
    """
    k = config.score_decay
    s0, s1 = 100.0 * math.exp(-before / k), 100.0 * math.exp(-after / k)
    mean = s0 if math.isclose(s0, s1) else (s1 - s0) / math.log(s1 / s0)
    exact = {cause: -mean * rise / k for cause, rise in rises.items() if rise}
    gap = target - sum(exact.values())
    if abs(gap) >= 1:
        exact[Cause.UNEXPLAINED] = exact.get(Cause.UNEXPLAINED, 0.0) + gap
    return {cause: (points, exact[cause]) for cause, points in _rounded(exact, target).items()}


def _rounded(exact: Mapping[Cause, float], target: int) -> dict[Cause, int]:
    """Whole points summing to ``target``, each moved off its nearest by at most one."""
    points = {cause: round(value) for cause, value in exact.items()}
    if not points:
        return {Cause.UNEXPLAINED: target} if target else {}
    short = target - sum(points.values())
    step = 1 if short > 0 else -1
    # The causes whose exact share is nearest the next point in the direction owed.
    order = sorted(points, key=lambda cause: (exact[cause] - points[cause]) * step, reverse=True)
    for index in range(abs(short)):
        points[order[index % len(order)]] += step
    return points
