"""App accounts with viewer / operator / admin roles, and the operator's privilege-escalation guards."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings

from .conftest import DB, admin

PW = "correct horse battery"
ACCT_PW = "a-long-password-1"


class Sess:
    """One signed-in browser. All sessions share a single TestClient (and so one event loop, which the
    database pools are bound to); the session cookie is sent explicitly per request."""

    def __init__(self, client: TestClient, token: str | None = None):
        self.client, self.token = client, token

    def _kw(self, kw):
        headers = dict(kw.pop("headers", {}))
        if self.token:
            headers["Cookie"] = f"pgac_session={self.token}"
        return {**kw, "headers": headers}

    def __getattr__(self, verb):  # get / post / put / patch / delete
        fn = getattr(self.client, verb)
        return lambda url, **kw: fn(url, **self._kw(kw))


def sign_in(client: TestClient, username: str, password: str) -> tuple[int, Sess]:
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    token = r.cookies.get("pgac_session")
    client.cookies.clear()
    return r.status_code, Sess(client, token)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("ADMIN_USERNAME", "root")
    monkeypatch.setenv("ADMIN_PASSWORD", PW)
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def S(env):
    """Sessions: root (built-in admin) plus an admin, operator and viewer account."""
    import app.security as sec
    from app.main import create_app

    sec._failures.clear()
    with TestClient(create_app()) as client:
        status, root = sign_in(client, "root", PW)
        assert status == 200
        for name, role in (("ann_admin", "admin"), ("olly_op", "operator"), ("vic_view", "viewer")):
            r = root.post("/api/app-users", json={"username": name, "password": ACCT_PW, "role": role})
            assert r.status_code == 201, r.text
        sessions = {"root": root}
        for name in ("ann_admin", "olly_op", "vic_view"):
            status, sessions[name] = sign_in(client, name, ACCT_PW)
            assert status == 200
        sessions["client"] = client
        yield sessions
    conn = sqlite3.connect(get_settings().data_db_path)
    conn.execute("DELETE FROM app_users")
    conn.commit()
    conn.close()


def mk(c, name, **kw):
    return c.post("/api/roles", json={"name": name, **kw})


def preview(c, role="postgres"):
    return c.post(f"/api/permissions/{role}/apply", json={"database": DB, "dry_run": True, "changes": [
        {"action": "grant", "object_type": "table", "schema": "app", "name": "orders", "privileges": ["SELECT"]}]})


def test_me_reports_role_and_source(S):
    assert S["root"].get("/api/auth/me").json()["role"] == "admin"
    me = S["olly_op"].get("/api/auth/me").json()
    assert (me["username"], me["role"], me["source"]) == ("olly_op", "operator", "local")


def test_viewer_is_read_only(S):
    v = S["vic_view"]
    assert v.get("/api/roles").status_code == 200
    assert v.get("/api/audit").status_code == 200
    assert v.get("/api/export", params={"database": DB, "format": "json"}).status_code == 200
    assert mk(v, "t_v1").status_code == 403
    assert v.patch("/api/roles/postgres", json={"comment": "x"}).status_code == 403
    assert v.put("/api/roles/postgres/member-of", json={"roles": []}).status_code == 403
    assert v.delete("/api/roles/t_nobody").status_code == 403
    assert preview(v).status_code == 403
    assert v.get("/api/app-users").status_code == 403


def test_operator_manages_access_but_cannot_escalate(S):
    o, a = S["olly_op"], S["ann_admin"]
    # everyday work is allowed
    assert mk(o, "t_op_grp").status_code == 201
    assert mk(o, "t_op_user", login=True, password="x" * 12, member_of=["t_op_grp"]).status_code == 201
    body = {"database": DB, "changes": [{"action": "grant", "object_type": "table", "schema": "app", "name": "orders", "privileges": ["SELECT"]}]}
    assert o.post("/api/permissions/t_op_grp/apply", json=body).status_code == 200
    assert o.patch("/api/roles/t_op_user", json={"comment": "ok", "createdb": True}).status_code == 200

    # privileged attributes are admin-only, on create and on update
    for attr in ("superuser", "createrole", "replication", "bypassrls"):
        assert mk(o, f"t_op_bad_{attr}", **{attr: True}).status_code == 403
        assert o.patch("/api/roles/t_op_user", json={attr: True}).status_code == 403
    # ...but an admin may
    assert mk(a, "t_adm_su", login=True, superuser=True).status_code == 201

    # cannot take over a privileged role (e.g. reset a superuser's password) or grant powerful roles
    assert o.patch("/api/roles/t_adm_su", json={"password": "new-password-123"}).status_code == 403
    assert o.put("/api/roles/t_op_user/member-of", json={"roles": ["t_op_grp", "t_adm_su"]}).status_code == 403
    assert o.put("/api/roles/t_op_user/member-of", json={"roles": ["pg_execute_server_program"]}).status_code == 403
    assert o.put("/api/roles/t_adm_su/members", json={"roles": ["t_op_user"]}).status_code == 403
    assert mk(o, "t_op_x", member_of=["t_adm_su"]).status_code == 403
    assert a.put("/api/roles/t_op_user/member-of", json={"roles": ["t_op_grp", "t_adm_su"]}).status_code == 200
    # an operator may still *remove* a powerful membership
    assert o.put("/api/roles/t_op_user/member-of", json={"roles": ["t_op_grp"]}).status_code == 200

    # deleting roles is admin-only
    assert o.delete("/api/roles/t_op_user").status_code == 403
    assert a.delete("/api/roles/t_op_user").status_code == 204
    # and the denied attempts were not applied
    with admin(DB) as c:
        assert c.execute("SELECT count(*) FROM pg_roles WHERE rolname LIKE 't_op_bad%'").fetchone()[0] == 0
    a.delete("/api/roles/t_adm_su")


def test_admin_manages_app_accounts(S):
    a, o, client = S["ann_admin"], S["olly_op"], S["client"]
    items = a.get("/api/app-users").json()["items"]
    assert {i["username"]: i["role"] for i in items} == {"ann_admin": "admin", "olly_op": "operator", "vic_view": "viewer"}
    assert "password_hash" not in str(items)

    new = {"username": "z", "password": ACCT_PW, "role": "viewer"}
    assert a.post("/api/app-users", json={**new, "password": "short"}).status_code == 422
    assert a.post("/api/app-users", json={**new, "username": "olly_op"}).status_code == 409
    assert a.post("/api/app-users", json={**new, "username": "OLLY_OP"}).status_code == 409  # case-insensitive
    assert a.post("/api/app-users", json={**new, "username": "root"}).status_code == 409  # reserved for the built-in admin
    assert a.post("/api/app-users", json={**new, "role": "god"}).status_code == 422

    # a role change takes effect immediately for the signed-in user
    assert preview(o).status_code == 200
    assert a.patch("/api/app-users/olly_op", json={"role": "viewer"}).status_code == 200
    assert o.get("/api/auth/me").json()["role"] == "viewer"
    assert preview(o).status_code == 403

    # disabling signs the account out at once, and it cannot sign in again
    assert a.patch("/api/app-users/olly_op", json={"disabled": True}).status_code == 200
    assert o.get("/api/roles").status_code == 401
    assert sign_in(client, "olly_op", ACCT_PW)[0] == 401

    # reset password
    assert a.patch("/api/app-users/vic_view", json={"password": "brand-new-password"}).status_code == 200
    assert sign_in(client, "vic_view", ACCT_PW)[0] == 401
    assert sign_in(client, "vic_view", "brand-new-password")[0] == 200

    # guard rails: not yourself
    assert a.patch("/api/app-users/ann_admin", json={"disabled": True}).status_code == 400
    assert a.patch("/api/app-users/ann_admin", json={"role": "viewer"}).status_code == 400
    assert a.delete("/api/app-users/ann_admin").status_code == 400
    assert a.delete("/api/app-users/olly_op").status_code == 204
    assert a.delete("/api/app-users/olly_op").status_code == 404

    # account changes are audited, never with passwords
    log = a.get("/api/audit", params={"action": "account."}).json()["items"]
    assert any(e["action"] == "account.update" and "password reset" in e["summary"] for e in log)
    assert "brand-new-password" not in str(log) and ACCT_PW not in str(log)


def test_change_own_password(S):
    v, client = S["vic_view"], S["client"]
    assert v.post("/api/auth/password", json={"current_password": "wrong", "new_password": "another-long-pw-2"}).status_code == 400
    assert v.post("/api/auth/password", json={"current_password": ACCT_PW, "new_password": "short"}).status_code == 422
    assert v.post("/api/auth/password", json={"current_password": ACCT_PW, "new_password": "another-long-pw-2"}).status_code == 200
    assert sign_in(client, "vic_view", "another-long-pw-2")[0] == 200
    assert sign_in(client, "vic_view", ACCT_PW)[0] == 401
    # the built-in admin has no stored password to change
    assert S["root"].post("/api/auth/password", json={"current_password": PW, "new_password": "another-long-pw-2"}).status_code == 400


def test_local_login_can_be_disabled_when_sso_is_configured(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("LOCAL_LOGIN_ENABLED", "false")
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    get_settings.cache_clear()
    with pytest.raises(Exception, match="needs SSO"):
        get_settings()
    for k, v in (("OIDC_ISSUER", "https://idp.test"), ("OIDC_CLIENT_ID", "x"), ("OIDC_CLIENT_SECRET", "y")):
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    from app.main import create_app

    with TestClient(create_app()) as c:
        assert c.post("/api/auth/login", json={"username": "a", "password": "b"}).status_code == 403
        me = c.get("/api/auth/me").json()
        assert me["oidc_enabled"] is True and me["local_login"] is False
    get_settings.cache_clear()
