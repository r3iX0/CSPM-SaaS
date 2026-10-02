"""A report is printed with a fetcher that loads nothing, so no name can cause a request.

The templates reference no external resource, and Jinja escapes everything a customer's cloud can
name. This holds the layer behind both: if a URL ever reached the document anyway, the print would
refuse it instead of fetching it from inside the network (DECISIONS.md §195). The first test runs
anywhere; the others need WeasyPrint's native libraries and skip without them.
"""

import sys
import types
from typing import Any

import pytest

from app.reports import render


def test_the_pdf_is_printed_with_a_fetcher_that_allows_no_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    class FakeFetcher:
        def __init__(self, **options: Any) -> None:
            seen["options"] = options

    class FakeHTML:
        def __init__(self, string: str, url_fetcher: Any) -> None:
            seen["fetcher"] = url_fetcher

        def write_pdf(self) -> bytes:
            return b"%PDF-fake"

    weasyprint = types.ModuleType("weasyprint")
    weasyprint.HTML = FakeHTML  # type: ignore[attr-defined]
    urls = types.ModuleType("weasyprint.urls")
    urls.URLFetcher = FakeFetcher  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "weasyprint", weasyprint)
    monkeypatch.setitem(sys.modules, "weasyprint.urls", urls)
    monkeypatch.setattr(render, "render_html", lambda report: "<p>report</p>")

    assert render.render_pdf({}) == b"%PDF-fake"
    assert seen["options"] == {"allowed_protocols": frozenset(), "allow_redirects": False}
    assert isinstance(seen["fetcher"], FakeFetcher)


def _weasyprint() -> Any:
    try:
        import weasyprint
    except (ImportError, OSError):
        pytest.skip("WeasyPrint's native libraries are not installed here")
    return weasyprint


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/hostname",
        "http://127.0.0.1:9/never",
        "https://169.254.169.254/latest/meta-data/",
        "data:text/plain;base64,aGVsbG8=",
    ],
)
def test_the_real_fetcher_refuses_every_scheme_it_is_asked_for(url: str) -> None:
    _weasyprint()
    from weasyprint.urls import URLFetcher

    fetcher = URLFetcher(allowed_protocols=frozenset(), allow_redirects=False)

    with pytest.raises(ValueError, match="disallowed protocol"):
        fetcher.fetch(url)


def test_a_document_that_names_a_url_still_prints_and_loads_nothing() -> None:
    weasyprint = _weasyprint()
    from weasyprint.urls import URLFetcher

    asked: list[str] = []

    class Watching(URLFetcher):
        def fetch(self, url: str, headers: Any = None) -> Any:
            asked.append(url)
            return super().fetch(url, headers)

    html = '<p>resource</p><img src="file:///etc/hostname"><img src="http://127.0.0.1:9/x">'
    pdf = weasyprint.HTML(
        string=html, url_fetcher=Watching(allowed_protocols=frozenset(), allow_redirects=False)
    ).write_pdf()

    assert pdf.startswith(b"%PDF")
    assert {"file:///etc/hostname", "http://127.0.0.1:9/x"} <= set(asked)
