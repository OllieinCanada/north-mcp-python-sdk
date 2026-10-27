"""Blocking OIDC discovery must not run on the request event loop."""

import base64
from contextvars import ContextVar
from io import BytesIO
import json
import threading
from unittest.mock import Mock

import jwt
import pytest
from starlette.authentication import AuthenticationError
from starlette.requests import HTTPConnection

from north_mcp_python_sdk.auth import NorthAuthBackend

request_id = ContextVar("request_id", default=None)


def connection(token, legacy):
    if legacy:
        payload = json.dumps({"user_id_token": token}).encode()
        value = base64.b64encode(payload).decode()
        headers = [(b"authorization", ("Bearer " + value).encode())]
    else:
        headers = [(b"x-north-id-token", token.encode())]
    return HTTPConnection({"type": "http", "headers": headers})


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy", [False, True])
async def test_discovery_runs_off_event_loop_with_context(monkeypatch, legacy):
    event_loop_thread = threading.get_ident()
    calls = []
    claims = {"iss": "https://issuer.test", "email": "user@example.test"}

    def discovery(*args, **kwargs):
        calls.append((threading.get_ident(), request_id.get()))
        return BytesIO(b'{"jwks_uri":"https://issuer.test/jwks"}')

    monkeypatch.setattr("urllib.request.urlopen", discovery)
    monkeypatch.setattr("jwt.decode", Mock(return_value=claims))
    jwks = Mock()
    jwks.get_signing_key.return_value.key = "unused-test-key"
    monkeypatch.setattr(
        "north_mcp_python_sdk.auth.PyJWKClient", Mock(return_value=jwks)
    )
    token = jwt.encode(
        claims,
        "test-signing-key-with-at-least-32-bytes",
        headers={"kid": "key-1"},
    )
    backend = NorthAuthBackend(trusted_issuers=["https://issuer.test"])
    context_token = request_id.set("request-123")
    try:
        result = await backend.authenticate(connection(token, legacy))
    finally:
        request_id.reset(context_token)

    assert result is not None
    assert len(calls) == 1
    assert calls[0][0] != event_loop_thread
    assert calls[0][1] == "request-123"
    jwks.get_signing_key.assert_called_once_with("key-1")


@pytest.mark.asyncio
async def test_invalid_tokens_still_raise_authentication_errors():
    backend = NorthAuthBackend(trusted_issuers=["https://issuer.test"])
    with pytest.raises(AuthenticationError, match="invalid user id token"):
        await backend.authenticate(connection("invalid-token", False))


@pytest.mark.asyncio
async def test_requests_without_auth_configuration_still_work():
    backend = NorthAuthBackend()
    result = await backend.authenticate(
        HTTPConnection({"type": "http", "headers": []})
    )
    assert result is not None
