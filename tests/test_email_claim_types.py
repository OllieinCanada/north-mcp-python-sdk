"""Malformed email claims must become authentication responses."""

import base64
import json
from unittest.mock import Mock

import httpx
import jwt
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from north_mcp_python_sdk.auth import (
    NorthAuthBackend,
    NorthAuthenticationMiddleware,
    on_auth_error,
)


def headers_for(email, legacy):
    token = jwt.encode(
        {"email": email, "iss": "https://issuer.test"},
        "test-signing-key-with-at-least-32-bytes",
    )
    if legacy:
        payload = json.dumps({"user_id_token": token}).encode()
        value = base64.b64encode(payload).decode()
        return {"Authorization": "Bearer " + value}
    return {"X-North-ID-Token": token}


async def response_for(headers, monkeypatch):
    async def endpoint(request):
        return JSONResponse({"ok": True})

    backend = NorthAuthBackend(trusted_issuers=["https://issuer.test"])
    verification = Mock()
    monkeypatch.setattr(backend, "_verify_token_signature", verification)
    app = NorthAuthenticationMiddleware(
        Starlette(routes=[Route("/mcp", endpoint)]),
        backend=backend,
        on_error=on_auth_error,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/mcp", headers=headers)
    verification.assert_called_once()
    return response


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize(
    "email", [123, True, ["not-a-string"], {"value": "private-placeholder"}]
)
async def test_malformed_email_claim_returns_401(monkeypatch, legacy, email):
    response = await response_for(headers_for(email, legacy), monkeypatch)

    assert response.status_code == 401
    assert response.json() == {"error": "invalid user id token"}
    assert "private-placeholder" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("email", [None, "user@example.test"])
async def test_optional_string_email_claim_still_works(
    monkeypatch, legacy, email
):
    response = await response_for(headers_for(email, legacy), monkeypatch)

    assert response.status_code == 200
    assert response.json() == {"ok": True}
