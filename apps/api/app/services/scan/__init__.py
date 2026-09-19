"""The scan pipeline, as a package.

:class:`ScanPipeline` is the entry point the worker and the tests drive; the
modules beside it are the stages it runs (see ``pipeline.py``).
"""

from app.services.scan.pipeline import ScanPipeline

__all__ = ["ScanPipeline"]
