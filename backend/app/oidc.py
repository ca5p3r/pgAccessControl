"""OpenID Connect sign-in: authorization code flow with PKCE, ID token validation, group -> role mapping."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from .config import Settings

_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384"]


class OIDCError(Exception):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def new_pkce() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    return verifier, _b64url(hashlib.sha256(verifier.encode()).digest())


class OIDCClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.s = settings
        self._transport = transport  # injectable for tests
        self._discovery: tuple[float, dict[str, Any]] | None = None
        self._jwks: tuple[float, dict[str, Any]] | None = None

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=10, transport=self._transport, follow_redirects=False)

    async def _get_json(self, url: str) -> dict[str, Any]:
        async with self._client() as c:
            r = await c.get(url)
        if r.status_code != 200:
            raise OIDCError(f"{url} returned HTTP {r.status_code}")
        return r.json()

    async def discovery(self) -> dict[str, Any]:
        if self._discovery and time.monotonic() - self._discovery[0] < 3600:
            return self._discovery[1]
        issuer = self.s.oidc_issuer.rstrip("/")
        doc = await self._get_json(f"{issuer}/.well-known/openid-configuration")
        if doc.get("issuer", "").rstrip("/") != issuer:
            raise OIDCError("The provider's issuer does not match OIDC_ISSUER")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if key not in doc:
                raise OIDCError(f"Provider metadata is missing {key}")
        self._discovery = (time.monotonic(), doc)
        return doc

    async def _keys(self, force: bool = False) -> dict[str, Any]:
        if not force and self._jwks and time.monotonic() - self._jwks[0] < 600:
            return self._jwks[1]
        jwks = await self._get_json((await self.discovery())["jwks_uri"])
        self._jwks = (time.monotonic(), jwks)
        return jwks

    async def authorize_url(self, *, state: str, nonce: str, challenge: str, redirect_uri: str) -> str:
        doc = await self.discovery()
        query = urlencode(
            {
                "response_type": "code", "client_id": self.s.oidc_client_id, "redirect_uri": redirect_uri,
                "scope": self.s.oidc_scopes, "state": state, "nonce": nonce,
                "code_challenge": challenge, "code_challenge_method": "S256",
            }
        )
        return f"{doc['authorization_endpoint']}{'&' if '?' in doc['authorization_endpoint'] else '?'}{query}"

    async def exchange(self, code: str, verifier: str, redirect_uri: str) -> dict[str, Any]:
        doc = await self.discovery()
        async with self._client() as c:
            r = await c.post(
                doc["token_endpoint"],
                data={
                    "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                    "client_id": self.s.oidc_client_id, "client_secret": self.s.oidc_client_secret,
                    "code_verifier": verifier,
                },
                headers={"Accept": "application/json"},
            )
        if r.status_code != 200:
            raise OIDCError(f"Token endpoint returned HTTP {r.status_code}")
        return r.json()

    async def validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OIDCError("Malformed ID token") from exc
        if header.get("alg") not in _ALGS:
            raise OIDCError(f"Unsupported ID token algorithm {header.get('alg')!r}")
        key = None
        for attempt in (False, True):  # a rotated key shows up as an unknown kid: refetch once
            keys = (await self._keys(force=attempt)).get("keys", [])
            kid = header.get("kid")
            match = [k for k in keys if k.get("kid") == kid] or (keys if not kid and len(keys) == 1 else [])
            if match:
                jwk = match[0]
                key = (ECAlgorithm if jwk.get("kty") == "EC" else RSAAlgorithm).from_jwk(jwk)
                break
        if key is None:
            raise OIDCError("No matching signing key")
        try:
            claims = jwt.decode(
                id_token, key, algorithms=[header["alg"]], audience=self.s.oidc_client_id,
                issuer=(await self.discovery())["issuer"], options={"require": ["exp", "iat", "sub"]}, leeway=30,
            )
        except jwt.PyJWTError as exc:
            raise OIDCError(f"ID token rejected: {exc}") from exc
        if not secrets.compare_digest(str(claims.get("nonce", "")).encode(), nonce.encode()):
            raise OIDCError("ID token nonce mismatch")
        return claims

    # -- identity -> app role ------------------------------------------------
    def username(self, claims: dict[str, Any]) -> str:
        for k in (self.s.oidc_username_claim, "preferred_username", "email", "sub"):
            v = claims.get(k)
            if isinstance(v, str) and v:
                return v
        return str(claims["sub"])

    def role_for(self, claims: dict[str, Any]) -> str | None:
        raw = claims.get(self.s.oidc_groups_claim, [])
        groups = set(raw.replace(",", " ").split()) if isinstance(raw, str) else {str(g) for g in raw}
        for role, configured in (("admin", self.s.oidc_admin_groups), ("operator", self.s.oidc_operator_groups), ("viewer", self.s.oidc_viewer_groups)):
            if groups & self.s.split_groups(configured):
                return role
        return self.s.oidc_default_role or None

