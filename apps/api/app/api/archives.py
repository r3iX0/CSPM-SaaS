"""Sending an audit package's archive: one build at a time, off the loop, streamed from disk.

Shared by the owner's download and the auditor's (DECISIONS.md sections 208 and 211), so the two
answer one limit between them. The archive is a file and not an envelope, for the reason a report
is: the caller is saving a document.
"""

from collections.abc import Iterator
from typing import IO

import anyio
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from app.services import audit_packages as service
from app.services.audit_packages import ArchiveInputs

# Archives are built one at a time. The build is CPU-bound and holds one payload in memory at a
# time, and one at a time bounds both however many people press download together.
ARCHIVE_BUILDS = anyio.CapacityLimiter(1)

_CHUNK = 64 * 1024


async def archive_response(session: AsyncSession, inputs: ArchiveInputs) -> StreamingResponse:
    """Commit the entry already written, let go of the connection, build, and stream.

    The entry is committed before the build, and the connection goes back to the pool: the build
    is slow, and held, the connection would idle through it and through the wait for its turn
    while every other request queued for one (DECISIONS.md section 158).
    """
    await session.commit()
    await session.close()

    spool, size = await anyio.to_thread.run_sync(
        service.build_archive, inputs, limiter=ARCHIVE_BUILDS
    )
    return StreamingResponse(
        _chunks(spool),
        media_type="application/zip",
        headers={
            "Content-Length": str(size),
            "Content-Disposition": f'attachment; filename="{service.archive_filename(inputs)}"',
        },
        background=BackgroundTask(spool.close),
    )


def _chunks(spool: IO[bytes]) -> Iterator[bytes]:
    while chunk := spool.read(_CHUNK):
        yield chunk
