"""Authentication must use the same mounted path as Starlette routing."""

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from north_mcp_python_sdk.auth import (
    NorthAuthBackend,
    NorthAuthenticationMiddleware,
    on_auth_error,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix", ["/north", "/gateway/north"])
@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/mcp", 401),
        ("/sse", 401),
        ("/messages/session", 401),
        ("/health", 200),
    ],
)
async def test_mounted_routes_preserve_authentication(prefix, path, status):
    async def endpoint(request):
        return JSONResponse({"ok": True})

    inner = Starlette(routes=[Route(path, endpoint)])
    protected = NorthAuthenticationMiddleware(
        inner,
        backend=NorthAuthBackend(trusted_issuers=["https://issuer.test"]),
        on_error=on_auth_error,
    )
    app = Starlette(routes=[Mount(prefix, app=protected)])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(prefix + path)

    assert response.status_code == status
    if status == 401:
        assert response.json() == {"error": "invalid authorization header"}
    else:
        assert response.json() == {"ok": True}
