"""The report's two drawings -- the score ring and the score trend -- as SVG,
because a PDF has no JavaScript.

The executive report's stated job is "how exposed are we, and is it getting
better". Until this existed it answered the second half with a single delta
against the previous reading -- and one number cannot tell a trend from a
wobble, which is the difference between a customer acting on a report and
filing it.

The trend is deliberately a sparkline and not a chart. There are no gridlines, no axis
labels and no legend: the reader is being shown a shape, and the numbers that
shape is made of are printed beside it. WeasyPrint renders inline SVG, so this
travels in the document rather than as an image anything has to fetch.
"""

from math import pi

VIEW_WIDTH = 560
VIEW_HEIGHT = 90
PADDING = 6

RING_SIZE = 120
RING_RADIUS = 50
RING_STROKE = 11


def score_ring_svg(score: int | None) -> str:
    """The security score as a ring filled to its share of 100.

    The number is printed inside it, so the ring only ever restates a figure
    the reader can already see -- it adds the proportion, never a second value.
    No severity colour: a score is not a finding, and painting 62 amber would
    say something about it the risk engine never concluded.

    No ``xmlns``: inline SVG in HTML needs none, and a report must contain no
    URL at all (``test_a_report_fetches_nothing_when_it_renders``).
    """
    if score is None:
        return ""
    value = min(max(int(score), 0), 100)
    centre = RING_SIZE / 2
    circumference = 2 * pi * RING_RADIUS
    filled = circumference * value / 100

    # A zero-length arc with round caps still paints a dot, which would read as
    # a score of one or two. Nothing is drawn for nothing.
    arc = (
        f'<circle cx="{centre}" cy="{centre}" r="{RING_RADIUS}" fill="none" '
        f'stroke="#1c1917" stroke-width="{RING_STROKE}" stroke-linecap="round" '
        f'stroke-dasharray="{filled:.1f} {circumference:.1f}" '
        f'transform="rotate(-90 {centre} {centre})" />'
        if value
        else ""
    )
    return (
        f'<svg class="ring" viewBox="0 0 {RING_SIZE} {RING_SIZE}" role="img" '
        f'aria-label="Security score {value} out of 100">'
        f'<circle cx="{centre}" cy="{centre}" r="{RING_RADIUS}" fill="none" '
        f'stroke="#e7e5e4" stroke-width="{RING_STROKE}" />'
        f"{arc}"
        f'<text x="{centre}" y="{centre + 9}" text-anchor="middle" font-size="32" '
        f'font-weight="700" fill="#1c1917">{value}</text>'
        f'<text x="{centre}" y="{centre + 26}" text-anchor="middle" font-size="10" '
        f'fill="#78716c">of 100</text>'
        f"</svg>"
    )


def score_trend_svg(history: list[dict]) -> str:
    """A sparkline of security score over time, oldest reading first.

    Returns an empty string when there is nothing worth drawing. A single
    reading is a dot, not a trend, and a line drawn through one point invites
    the reader to see a direction that has not been measured.
    """
    scores = [
        int(entry["security_score"])
        for entry in history
        if entry.get("security_score") is not None
    ]
    if len(scores) < 2:
        return ""

    # Always the full scale. Fitting the axis to the observed range would make
    # a wobble between 81 and 84 look like the same climb as 20 to 84 -- the
    # single most common way a sparkline lies.
    points = []
    span = len(scores) - 1
    usable_width = VIEW_WIDTH - 2 * PADDING
    usable_height = VIEW_HEIGHT - 2 * PADDING

    for index, score in enumerate(scores):
        x = PADDING + (usable_width * index / span)
        y = PADDING + usable_height * (1 - min(max(score, 0), 100) / 100)
        points.append((round(x, 1), round(y, 1)))

    line = " ".join(f"{x},{y}" for x, y in points)
    # Closed back along the baseline so the area under the line can be filled,
    # which is what makes the shape readable at this size in greyscale print.
    floor = VIEW_HEIGHT - PADDING
    area = f"{PADDING},{floor} {line} {VIEW_WIDTH - PADDING},{floor}"
    last_x, last_y = points[-1]

    return (
        f'<svg class="trend" viewBox="0 0 {VIEW_WIDTH} {VIEW_HEIGHT}" '
        f'role="img" '
        f'aria-label="Security score over the last {len(scores)} readings">'
        f'<polygon points="{area}" fill="#f5f5f4" />'
        f'<polyline points="{line}" fill="none" stroke="#44403c" stroke-width="1.6" />'
        f'<circle cx="{last_x}" cy="{last_y}" r="2.6" fill="#1c1917" />'
        f"</svg>"
    )
