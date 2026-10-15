"""Who may see and use which server: minimum roles, read-only servers, and what non-admins never learn."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings

from .conftest import PG2, admin2, pg2_available
from .test_rbac import ACCT_PW, PW, Sess, env, sign_in  # noqa: F401  (env is a fixture)

SERVER = {"environment": "staging", "host": PG2["host"], "port": PG2["port"], "user": PG2["user"], "password": PG2["password"],
          "database": "postgres", "sslmode": "disable"}


@pytest.fixture
def S(env):
    """root plus an admin, operator and viewer account, and three profiles with different restrictions."""
    if not pg2_available():
        pytest.skip("second test PostgreSQL server (TEST_PG2_*) is not running")
    import app.security as sec
    from app.main import create_app

    sec._failures.clear()
    with TestClient(create_app()) as client:
        status, root = sign_in(client, "root", PW)
        assert status == 200
        for name, role in (("ann_admin", "admin"), ("olly_op", "operator"), ("vic_view", "viewer")):
            assert root.post("/api/app-users", json={"username": name, "password": ACCT_PW, "role": role}).status_code == 201
        s = {"root": root, "client": client}
        for name in ("ann_admin", "olly_op", "vic_view"):
            s[name] = sign_in(client, name, ACCT_PW)[1]
        ids = {}
        for key, extra in (
            ("readonly", {"name": "Prod (read-only)", "environment": "production", "read_only": True}),
            ("ops", {"name": "Ops only", "min_role": "operator"}),
            ("secret", {"name": "Admins only", "min_role": "admin"}),
        ):
            r = root.post("/api/servers", json={**SERVER, **extra})
            assert r.status_code == 201, r.text
            ids[key] = r.json()["id"]
        s["ids"] = ids
        yield s
        with admin2() as c:
            for (name,) in c.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 't\\_%'").fetchall():
                c.execute(f'DROP OWNED BY "{name}"')
                c.execute(f'DROP ROLE "{name}"')
    conn = sqlite3.connect(get_settings().data_db_path)
    conn.execute("DELETE FROM app_users")
    conn.execute("DELETE FROM servers")
    conn.commit()
    conn.close()


def on(S, key, **params):
    return {"server": S["ids"][key], **params}


def names(session):
    return [i["name"] for i in session.get("/api/servers").json()["items"]]


def test_each_role_sees_only_the_servers_it_may_use(S):
    assert names(S["vic_view"]) == ["Default server", "Prod (read-only)"]
    assert names(S["olly_op"]) == ["Default server", "Ops only", "Prod (read-only)"]
    assert names(S["ann_admin"]) == ["Default server", "Admins only", "Ops only", "Prod (read-only)"]

    # connection details are for admins only; nobody ever gets a password
    viewer_item = S["vic_view"].get("/api/servers").json()["items"][1]
    assert not {"host", "port", "user", "database", "sslmode"} & set(viewer_item)
    admin_item = S["root"].get("/api/servers").json()["items"][1]
    assert admin_item["host"] == PG2["host"] and "password" not in admin_item
    assert PG2["password"] not in S["root"].get("/api/servers").text
    assert S["vic_view"].get("/api/meta", params=on(S, "readonly")).json()["host"] is None

    # a server you may not use looks exactly like one that does not exist
    hidden = S["vic_view"].get("/api/roles", params=on(S, "ops"))
    missing = S["vic_view"].get("/api/roles", params={"server": "no-such-server"})
    assert hidden.status_code == missing.status_code == 404 and hidden.json() == missing.json()
    assert S["olly_op"].get("/api/roles", params=on(S, "ops")).status_code == 200
    assert S["olly_op"].get("/api/roles", params=on(S, "secret")).status_code == 404
    assert S["ann_admin"].get("/api/roles", params=on(S, "secret")).status_code == 200
    # health of hidden servers is not revealed either
    assert set(S["olly_op"].get("/api/servers/status").json()["items"]) == {"default", S["ids"]["readonly"], S["ids"]["ops"]}


def test_read_only_servers_are_enforced_on_the_server(S):
    ro = on(S, "readonly")
    for who in ("olly_op", "ann_admin", "root"):  # even admins are capped on a read-only server
        r = S[who].post("/api/roles", params=ro, json={"name": "t_ro_try"})
        assert r.status_code == 403 and "read-only" in r.json()["detail"], (who, r.text)
    assert S["olly_op"].patch("/api/roles/postgres", params=ro, json={"comment": "x"}).status_code == 403
    assert S["olly_op"].delete("/api/roles/t_nobody", params=ro).status_code == 403
    assert S["olly_op"].put("/api/roles/postgres/member-of", params=ro, json={"roles": []}).status_code == 403
    body = {"database": "postgres", "dry_run": True, "changes": [
        {"action": "grant", "object_type": "table", "schema": "public", "name": "x", "privileges": ["SELECT"]}]}
    assert S["olly_op"].post("/api/permissions/postgres/apply", params=ro, json=body).status_code == 403
    assert S["olly_op"].put("/api/temporary/membership", params=ro, json={"role": "a", "member": "b", "expires_at": "2999-01-01T00:00:00Z"}).status_code == 403
    assert S["olly_op"].post("/api/snapshots", params=ro, json={"name": "s", "database": "postgres"}).status_code == 403
    # reading still works, the meta says so, and the same session may write on a writable server
    assert S["olly_op"].get("/api/roles", params=ro).status_code == 200
    assert S["olly_op"].get("/api/meta", params=ro).json()["read_only"] is True
    assert S["olly_op"].post("/api/roles", json={"name": "t_rw_ok"}).status_code == 201
    with admin2() as c:
        assert c.execute("SELECT count(*) FROM pg_roles WHERE rolname = 't_ro_try'").fetchone()[0] == 0

    # the cap does not lock admins out of administration: accounts and server profiles still work
    assert S["ann_admin"].get("/api/app-users", params=ro).status_code == 200
    r = S["ann_admin"].patch(f"/api/servers/{S['ids']['readonly']}", json={"read_only": False})
    assert r.status_code == 200 and r.json()["read_only"] is False
    assert S["olly_op"].post("/api/roles", params=ro, json={"name": "t_now_writable"}).status_code == 201


def test_only_admins_manage_servers(S):
    body = {**SERVER, "name": "sneaky"}
    for who in ("olly_op", "vic_view"):
        assert S[who].post("/api/servers", json=body).status_code == 403
        assert S[who].post("/api/servers/test", json=body).status_code == 403
        assert S[who].patch(f"/api/servers/{S['ids']['ops']}", json={"read_only": False}).status_code == 403
        assert S[who].delete(f"/api/servers/{S['ids']['ops']}").status_code == 403
        assert S[who].get(f"/api/servers/{S['ids']['ops']}/usage").status_code == 403
    assert S["olly_op"].get("/api/servers").json()["management_enabled"] is False
    assert S["ann_admin"].get("/api/servers").json()["management_enabled"] is True


def test_the_audit_trail_of_a_hidden_server_is_hidden_too(S):
    assert S["ann_admin"].post("/api/roles", params=on(S, "secret"), json={"name": "t_secret_role"}).status_code == 201
    assert S["olly_op"].post("/api/roles", json={"name": "t_visible_role"}).status_code == 201

    def targets(session, **params):
        return {e["target"] for e in session.get("/api/audit", params={"q": "t_", **params}).json()["items"]}

    assert targets(S["ann_admin"], server="*") >= {"t_secret_role", "t_visible_role"}
    seen = targets(S["olly_op"], server="*")
    assert "t_visible_role" in seen and "t_secret_role" not in seen
    assert targets(S["olly_op"], server=S["ids"]["secret"]) == set()
    facets = S["olly_op"].get("/api/audit/facets").json()["servers"]
    assert S["ids"]["secret"] not in {f["id"] for f in facets} and "default" in {f["id"] for f in facets}
    # and exports honour the same rule
    csv = S["olly_op"].get("/api/audit/export", params={"server": "*", "format": "csv"}).text
    assert "t_secret_role" not in csv


def test_disabled_servers_are_listed_for_admins_only(S):
    assert S["root"].patch(f"/api/servers/{S['ids']['ops']}", json={"disabled": True}).status_code == 200
    assert "Ops only" not in names(S["olly_op"])
    assert next(i for i in S["root"].get("/api/servers").json()["items"] if i["name"] == "Ops only")["disabled"] is True
    assert S["olly_op"].get("/api/roles", params=on(S, "ops")).status_code == 404
    assert S["root"].get("/api/roles", params=on(S, "ops")).status_code == 404  # disabled for everyone until re-enabled
    assert S["root"].get("/api/servers/status").json()["items"].get(S["ids"]["ops"]) is None


def test_server_changes_are_audited_without_secrets(S):
    S["root"].patch(f"/api/servers/{S['ids']['ops']}", json={"description": "d", "password": "brand-new-secret-pw", "environment": "production"})
    log = S["root"].get("/api/audit", params={"server": "*", "action": "server."}).json()["items"]
    upd = next(e for e in log if e["action"] == "server.update" and e["server"] == S["ids"]["ops"])
    assert upd["actor"] == "root" and "environment: staging → production" in upd["summary"] and "password changed" in upd["summary"]
    assert upd["details"]["password"] == "changed"
    assert "brand-new-secret-pw" not in str(log) and PG2["password"] not in str(log)
