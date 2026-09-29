"""Requests to a URL a customer typed, made so they cannot reach anything inside.

A webhook URL is the one place a customer chooses where this service sends a
request, and the worker that sends it sits inside Railway's private network
beside Redis, PostgreSQL's pooler and the cloud metadata address. A URL naming
any of those -- directly, through a DNS name that resolves to one, or through a
redirect -- would turn a notification feature into a way to probe and call them
(server-side request forgery). So (DECISIONS.md section 164):

* **HTTPS on port 443, and nothing else.** No other scheme, no userinfo, no
  other port: every legitimate receiver listens there, and a free port is a
  free port scanner.
* **Every address the name resolves to must be public.** Private, loopback,
  link-local (the metadata address), shared, reserved and multicast ranges are
  refused, for IPv4 and IPv6 alike. One bad answer refuses the URL, because the
  connection could land on any of them.
* **The connection goes to the address that was checked.** A name that
  resolves to something public when checked and to 10.0.0.5 a moment later
  (DNS rebinding) would otherwise pass the check and still land inside. The
  request is sent to the checked IP, with the real name in the Host header and
  in TLS's server name, so the certificate is still verified against the name
  the customer gave.
* **Redirects are not followed**, and proxies from the environment are not
  used. A 3xx is an answer, recorded as a failure like any other.
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

# Short, because the receiver is somebody else's service and a slow one must
# not hold a worker for long; a delivery that times out is retried later.
TIMEOUT = httpx.Timeout(5.0, connect=3.0)

# The whole call -- lookup, connect, send, answer -- whatever each phase does.
# ``TIMEOUT`` alone is per phase, and httpx's read timeout restarts with every
# chunk: a receiver answering one byte every four seconds was never cut off,
# and held the delivery sweep until Celery's own limit (DECISIONS.md 164).
DEADLINE = 10.0

# How much of a refusal's body is read, and how much of it is kept in the
# delivery's error. Read as a stream and dropped past the first, so an endless
# answer costs a few kilobytes rather than the worker's memory.
READ_LIMIT = 4096
ERROR_EXCERPT = 300


class OutboundRefused(ValueError):
    """The URL may not be called: its form, or where it leads."""


@dataclass(frozen=True)
class Target:
    """A URL checked and pinned to an address that was checked."""

    url: str
    host: str
    address: str


@dataclass(frozen=True)
class Outcome:
    ok: bool
    status: int | None
    error: str | None


def check_form(url: str) -> tuple[str, str]:
    """The URL's host and path if its form is acceptable. Resolves nothing."""
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise OutboundRefused("The address must start with https://")
    if parts.username or parts.password:
        raise OutboundRefused("The address must not carry a username or password")
    try:
        port = parts.port
    except ValueError as exc:
        raise OutboundRefused("The address has a port that is not a number") from exc
    if port not in (None, 443):
        raise OutboundRefused("The address must use the standard HTTPS port")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host or host == "localhost" or host.endswith((".localhost", ".internal", ".local")):
        raise OutboundRefused("The address must name a public host")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        # A literal address is judged here, without a lookup.
        _require_public(literal)
    return host, parts.path or "/"


def _require_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    # An IPv4 address carried inside IPv6 is judged as the IPv4 it is.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast:
        raise OutboundRefused("The address leads somewhere private, which Cleave will not call")


async def _addresses(host: str) -> list[str]:
    """Every address ``host`` resolves to, without blocking the loop."""
    answers = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in answers})


async def resolve(url: str) -> Target:
    """Check the URL and every address its host resolves to; pin the first."""
    host, _ = check_form(url)
    try:
        addresses = await _addresses(host)
    except OSError as exc:
        raise OutboundRefused(f"{host} could not be resolved") from exc
    if not addresses:
        raise OutboundRefused(f"{host} could not be resolved")
    for address in addresses:
        _require_public(ipaddress.ip_address(address))
    return Target(url=url, host=host, address=addresses[0])


def pinned_url(target: Target) -> str:
    """The URL with its host replaced by the checked address."""
    parts = urlsplit(target.url)
    literal = ipaddress.ip_address(target.address)
    netloc = f"[{literal}]" if literal.version == 6 else str(literal)
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


async def post_json(
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Outcome:
    """POST ``body`` to ``url`` under every rule above, and say how it went.

    Never raises for the receiver's sake: a refusal, a timeout and a 500 are
    all an ``Outcome`` the caller records. ``transport`` is for tests.
    """
    try:
        async with asyncio.timeout(DEADLINE):
            return await _post(url, body, headers, transport)
    except TimeoutError:
        return Outcome(ok=False, status=None, error=f"No answer within {DEADLINE:g} seconds")


async def _post(
    url: str,
    body: bytes,
    headers: dict[str, str],
    transport: httpx.AsyncBaseTransport | None,
) -> Outcome:
    try:
        target = await resolve(url)
    except OutboundRefused as exc:
        return Outcome(ok=False, status=None, error=str(exc))

    try:
        async with (
            httpx.AsyncClient(
                timeout=TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                transport=transport,
            ) as client,
            client.stream(
                "POST",
                pinned_url(target),
                content=body,
                headers={
                    **headers,
                    "Host": target.host,
                    "Content-Type": "application/json",
                    "User-Agent": "Cleave-Webhooks/1",
                },
                extensions={"sni_hostname": target.host},
            ) as response,
        ):
            if 200 <= response.status_code < 300:
                # The status is the answer; the body is never read.
                return Outcome(ok=True, status=response.status_code, error=None)
            excerpt = await _excerpt(response)
    except httpx.HTTPError as exc:
        return Outcome(ok=False, status=None, error=type(exc).__name__)

    return Outcome(
        ok=False,
        status=response.status_code,
        error=f"HTTP {response.status_code}" + (f": {excerpt}" if excerpt else ""),
    )


async def _excerpt(response: httpx.Response) -> str:
    """The start of a refusal's body, read no further than ``READ_LIMIT``."""
    read = bytearray()
    if response.is_stream_consumed:
        # Already in memory (a response built rather than received).
        read.extend(response.content[:READ_LIMIT])
    else:
        # Raw rather than decoded: a compressed body is never inflated, so a
        # small answer cannot unpack into a large one here.
        async for chunk in response.aiter_raw():
            read.extend(chunk)
            if len(read) >= READ_LIMIT:
                break
    return bytes(read[:READ_LIMIT]).decode("utf-8", "replace")[:ERROR_EXCERPT].strip()
