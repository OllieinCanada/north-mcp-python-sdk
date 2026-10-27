"""Reject JWTs missing key identifiers before any discovery requests."""

import base64
import json
import urllib.error
from unittest.mock import Mock

import jwt
import pytest
from starlette.authentication import AuthenticationError
from starlette.requests import HTTPConnection

from north_mcp_python_sdk.auth import NorthAuthBackend

ISSUER = "https://issuer.test"
KEY = "test-signing-key-with-at-least-32-bytes"


def connection(token, legacy):
    if legacy:
        payload = json.dumps({"user_id_token": token}).encode()
        name = "authorization"
        value = "Bearer " + base64.b64encode(payload).decode()
    else:
        name, value = "x-north-id-token", token
    return HTTPConnection(
        {"type": "http", "headers": [(name.encode(), value.encode())]}
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy", [False, True])
async def test_missing_key_id_does_not_contact_issuer(monkeypatch, legacy):
    discovery = Mock(side_effect=AssertionError("Unexpected discovery request"))
    monkeypatch.setattr("urllib.request.urlopen", discovery)
    backend = NorthAuthBackend(trusted_issuers=[ISSUER])
    token = jwt.encode({"iss": ISSUER, "email": "user@test"}, KEY)

    with pytest.raises(
        AuthenticationError, match="Token missing key identifier"
    ):
        await backend.authenticate(connection(token, legacy))

    discovery.assert_not_called()


@pytest.mark.asyncio
async def test_key_id_still_requires_issuer_verification(monkeypatch):
    discovery = Mock(side_effect=urllib.error.URLError("offline fixture"))
    monkeypatch.setattr("urllib.request.urlopen", discovery)
    backend = NorthAuthBackend(trusted_issuers=[ISSUER])
    token = jwt.encode(
        {"iss": ISSUER, "email": "user@test"}, KEY, headers={"kid": "key-1"}
    )

    with pytest.raises(
        AuthenticationError, match="unable to fetch issuer configuration"
    ):
        await backend.authenticate(connection(token, False))

    discovery.assert_called_once()
