"""A verified second factor is required of every session once it is set up.

Against the real database: ``app.has_verified_factor()`` reads Supabase's
``auth.mfa_factors`` (stubbed in CI by ``infrastructure/ci/postgres-roles.sql``)
for the caller named by the verified token, and the API refuses a one-factor
token for a user who has one (DECISIONS.md section 217).
"""

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.config import settings
from app.core.db import service_session
from app.main import app

pytestmark = pytest.mark.integration

ENROLLED = uuid.UUID("eeeeeeee-0000-0000-0000-0000000000f1")
PENDING = uuid.UUID("eeeeeeee-0000-0000-0000-0000000000f2")
PLAIN = uuid.UUID("eeeeeeee-0000-0000-0000-0000000000f3")


def _headers(user_id: uuid.UUID, *, aal: str) -> dict[str, str]:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(user_id),
            "email": f"{user_id.hex[-4:]}@example.com",
            "aud": settings.jwt_audience,
            "role": "authenticated",
            "aal": aal,
            "iat": now,
            "exp": now + timedelta(hours=1),
        },
        settings.supabase_jwt_secret,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def factors() -> AsyncIterator[None]:
    """One verified factor for ENROLLED, one never confirmed for PENDING."""
    async with service_session() as session:
        await session.execute(
            text(
                "INSERT INTO auth.mfa_factors (user_id, status) "
                "VALUES (:enrolled, 'verified'), (:pending, 'unverified')"
            ),
            {"enrolled": ENROLLED, "pending": PENDING},
        )
        await session.commit()
    yield
    async with service_session() as session:
        await session.execute(
            text("DELETE FROM auth.mfa_factors WHERE user_id IN (:enrolled, :pending)"),
            {"enrolled": ENROLLED, "pending": PENDING},
        )
        await session.commit()


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.usefixtures("factors")
class TestSecondFactor:
    async def test_one_factor_is_refused_once_a_factor_is_verified(self, client) -> None:
        response = await client.get("/api/v1/organizations", headers=_headers(ENROLLED, aal="aal1"))
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "MFA_REQUIRED"

    async def test_two_factors_are_let_through(self, client) -> None:
        response = await client.get("/api/v1/organizations", headers=_headers(ENROLLED, aal="aal2"))
        assert response.status_code == 200

    async def test_a_factor_never_confirmed_requires_nothing(self, client) -> None:
        response = await client.get("/api/v1/organizations", headers=_headers(PENDING, aal="aal1"))
        assert response.status_code == 200

    async def test_another_users_factor_requires_nothing_of_this_one(self, client) -> None:
        response = await client.get("/api/v1/organizations", headers=_headers(PLAIN, aal="aal1"))
        assert response.status_code == 200
