"""Single sign-on against a fake OpenID provider that signs ID tokens with a real RSA key."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from app.config import get_settings

ISSUER = "https://idp.test/realms/corp"
CLIENT_ID = "pgac"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = {**json.loads(RSAAlgorithm.to_jwk(KEY.public_key())), "kid": "k1", "use": "sig", "alg": "RS256"}


class FakeIdP:
    def __init__(self):
        self.claims: dict = {}
        self.sign_with = KEY
        self.token_requests: list[dict] = []
        self.fail_token = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/auth",
                "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/certs",
            })
        if url.endswith("/certs"):
            return httpx.Response(200, json={"keys": [JWK]})
        if url.endswith("/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            if self.fail_token:
                return httpx.Response(400, json={"error": "invalid_grant"})
            now = int(time.time())
            claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u-1", "iat": now, "exp": now + 300, **self.claims}
            token = jwt.encode(claims, self.sign_with, algorithm="RS256", headers={"kid": "k1"})
            return httpx.Response(200, json={"id_token": token, "access_token": "unused", "token_type": "Bearer"})
        return httpx.Response(404)


@pytest.fixture
def sso(monkeypatch):
    for k, v in {
        "AUTH_ENABLED": "true", "ADMIN_USERNAME": "root", "ADMIN_PASSWORD": "correct horse battery",
        "SECRET_KEY": "k" * 40, "OIDC_ISSUER": ISSUER, "OIDC_CLIENT_ID": CLIENT_ID, "OIDC_CLIENT_SECRET": "shh",
        "OIDC_ADMIN_GROUPS": "pg-admins", "OIDC_OPERATOR_GROUPS": "pg-ops, pg-dba", "OIDC_VIEWER_GROUPS": "everyone",
        "OIDC_REDIRECT_URI": "http://testserver/api/auth/oidc/callback",
    }.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    from app.main import create_app

    idp = FakeIdP()
    app = create_app()
    app.state.oidc._transport = httpx.MockTransport(idp.handler)
    with TestClient(app) as client:
        yield client, idp
    get_settings.cache_clear()


def start(client):
    """Begin sign-in: returns the redirect parameters the app sent to the provider."""
    r = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 302
    loc = urlparse(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{ISSUER}/auth"
    return {k: v[0] for k, v in parse_qs(loc.query).items()}


def finish(client, idp, params, **override):
    idp.claims = {"nonce": params["nonce"], **override.pop("claims", {})}
    return client.get("/api/auth/oidc/callback", params={"code": "abc", "state": override.pop("state", params["state"])})


def test_login_redirect_carries_pkce_state_and_nonce(sso):
    client, _ = sso
    p = start(client)
    assert p["response_type"] == "code" and p["client_id"] == CLIENT_ID and p["code_challenge_method"] == "S256"
    assert p["redirect_uri"] == "http://testserver/api/auth/oidc/callback" and "openid" in p["scope"]
    assert len(p["state"]) > 20 and len(p["nonce"]) > 20
    assert client.cookies.get("pgac_oidc")


def test_successful_sign_in_maps_groups_to_role(sso):
    client, idp = sso
    p = start(client)
    r = finish(client, idp, p, claims={"preferred_username": "dana", "groups": ["staff", "pg-ops"]})
    assert r.status_code == 200 and 'location.replace("/")' in r.text  # client-side redirect keeps the Strict cookie usable
    # PKCE: the verifier sent to the token endpoint matches the challenge sent to the browser
    sent = idp.token_requests[-1]
    assert base64.urlsafe_b64encode(hashlib.sha256(sent["code_verifier"].encode()).digest()).rstrip(b"=").decode() == p["code_challenge"]
    assert sent["client_secret"] == "shh" and sent["grant_type"] == "authorization_code"

    me = client.get("/api/auth/me").json()
    assert (me["username"], me["role"], me["source"], me["authenticated"]) == ("dana", "operator", "oidc", True)
    assert client.get("/api/roles").status_code == 200
    assert client.post("/api/roles", json={"name": "t_sso_ops"}).status_code == 201  # operators can create
    assert client.delete("/api/roles/t_sso_ops").status_code == 403  # but not delete
    # signed in via SSO is audited with the SSO user as actor
    log = client.get("/api/audit", params={"actor": "dana"}).json()["items"]
    assert any(e["action"] == "auth.login" and "SSO" in e["summary"] for e in log)
    # the one-time cookie is gone
    assert not client.cookies.get("pgac_oidc")


def test_highest_matching_group_wins_and_claim_fallbacks(sso):
    client, idp = sso
    r = finish(client, idp, start(client), claims={"email": "e@corp.test", "groups": ["everyone", "pg-ops", "pg-admins"]})
    me = client.get("/api/auth/me").json()
    assert me["role"] == "admin" and me["username"] == "e@corp.test"  # no preferred_username -> email
    client.cookies.clear()
    finish(client, idp, start(client), claims={"preferred_username": "v", "groups": "everyone other"})  # space separated string
    assert client.get("/api/auth/me").json()["role"] == "viewer"


def test_user_without_a_matching_group_is_refused(sso):
    client, idp = sso
    r = finish(client, idp, start(client), claims={"preferred_username": "eve", "groups": ["marketing"]})
    assert "sso_error=no_access" in r.text
    assert client.get("/api/auth/me").json()["authenticated"] is False
    assert client.get("/api/roles").status_code == 401


def test_default_role_for_unmapped_users(sso, monkeypatch):
    client, idp = sso
    monkeypatch.setenv("OIDC_DEFAULT_ROLE", "viewer")
    get_settings.cache_clear()
    client.app.state.oidc.s = get_settings()
    finish(client, idp, start(client), claims={"preferred_username": "eve", "groups": ["marketing"]})
    assert client.get("/api/auth/me").json()["role"] == "viewer"


@pytest.mark.parametrize(
    "tweak",
    [
        {"claims": {"aud": "someone-else"}},
        {"claims": {"iss": "https://evil.test"}},
        {"claims": {"exp": int(time.time()) - 3600}},
        {"claims": {"nonce": "not-the-nonce"}},
    ],
)
def test_bad_id_tokens_are_rejected(sso, tweak):
    client, idp = sso
    p = start(client)
    idp.claims = {"nonce": p["nonce"], "preferred_username": "mallory", "groups": ["pg-admins"], **tweak["claims"]}
    r = client.get("/api/auth/oidc/callback", params={"code": "abc", "state": p["state"]})
    assert "sso_error=failed" in r.text
    assert client.get("/api/auth/me").json()["authenticated"] is False


def test_token_signed_with_the_wrong_key_is_rejected(sso):
    client, idp = sso
    idp.sign_with = OTHER_KEY
    r = finish(client, idp, start(client), claims={"preferred_username": "mallory", "groups": ["pg-admins"]})
    assert "sso_error=failed" in r.text and client.get("/api/auth/me").json()["authenticated"] is False


def test_state_and_error_handling(sso):
    client, idp = sso
    p = start(client)
    assert "sso_error=failed" in finish(client, idp, p, state="forged").text  # state mismatch (CSRF)
    # a callback without our cookie (e.g. replayed elsewhere) fails
    fresh = start(client)
    client.cookies.clear()
    assert "sso_error=failed" in finish(client, idp, fresh).text
    # the user denied consent / the provider returned an error
    start(client)
    assert "sso_error=access_denied" in client.get("/api/auth/oidc/callback", params={"error": "access_denied"}).text
    # token endpoint failure
    idp.fail_token = True
    assert "sso_error=failed" in finish(client, idp, start(client)).text
    failed = client.get("/api/audit", params={"action": "auth.login_failed"})
    assert failed.status_code == 401  # nobody is signed in, and nothing leaks to anonymous callers


def test_state_cannot_be_reused(sso):
    client, idp = sso
    p = start(client)
    finish(client, idp, p, claims={"preferred_username": "dana", "groups": ["pg-ops"]})
    client.cookies.pop("pgac_session", None)
    r = client.get("/api/auth/oidc/callback", params={"code": "abc", "state": p["state"]})  # cookie was consumed
    assert "sso_error=failed" in r.text


def test_sso_not_configured_returns_404(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("ADMIN_PASSWORD", "correct horse battery")
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    for k in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    get_settings.cache_clear()
    from app.main import create_app

    with TestClient(create_app()) as c:
        assert c.get("/api/auth/oidc/login", follow_redirects=False).status_code == 404
        assert c.get("/api/auth/me").json()["oidc_enabled"] is False
    get_settings.cache_clear()
