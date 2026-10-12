from .conftest import DB, admin


def apply(client, role, changes, **extra):
    r = client.post(f"/api/permissions/{role}/apply", json={"database": DB, "changes": changes, **extra})
    assert r.status_code == 200, r.text


def mk(client, name, **kw):
    r = client.post("/api/roles", json={"name": name, **kw})
    assert r.status_code == 201, r.text


def holdings(client, role, **params):
    r = client.get(f"/api/roles/{role}/holdings", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_held_grants_summary_and_detail(client):
    mk(client, "t_hold", login=True)
    mk(client, "t_hold_other")
    with admin(DB) as c:
        c.execute('CREATE TABLE app.t_hold_tbl (id int)')
        c.execute('ALTER TABLE app.t_hold_tbl OWNER TO "t_hold"')  # owned object
        c.execute('GRANT CONNECT ON DATABASE pgac_test TO "t_hold"')  # cluster-wide (database) privilege
    tbl = {"object_type": "table", "schema": "app", "name": "orders"}
    apply(client, "t_hold", [
        {"action": "grant", **tbl, "privileges": ["SELECT", "UPDATE"]},
        {"action": "grant", **tbl, "privileges": ["DELETE"], "with_grant_option": True},
        {"action": "grant", "object_type": "schema", "name": "app", "privileges": ["USAGE"]},
        {"action": "grant", "object_type": "column", "schema": "app", "name": "customers", "columns": ["name"], "privileges": ["SELECT"]},
        {"action": "grant", "object_type": "default_tables", "schema": "app", "for_role": "postgres", "privileges": ["SELECT"]},
    ])
    # t_hold passes DELETE on to someone else, so it appears as a grantor
    apply(client, "t_hold_other", [{"action": "grant", **tbl, "privileges": ["DELETE"]}], grantor="t_hold")

    # --- summary: counts per database + cluster-wide items ---
    s = holdings(client, "t_hold")
    assert s["owns_objects"] is True and s["is_superuser"] is False
    mine = next(d for d in s["databases"] if d["database"] == DB)
    assert mine["owned_objects"] >= 1 and mine["privileges"] >= 3
    cluster = s["cluster"]
    assert any(p["kind"] == "database" and p["name"] == DB and p["privilege"] == "CONNECT" for p in cluster["privileges"])
    # the delete dialog's counts and this summary come from the same source
    deps = client.get("/api/roles/t_hold/dependencies").json()["dependencies"]
    assert {d["database"]: d["privileges"] for d in deps if d["database"]}[DB] == mine["privileges"]

    # --- detail for one database ---
    d = holdings(client, "t_hold", database=DB)
    assert d["database"] == DB
    assert {"kind": "table", "description": "table app.t_hold_tbl"} in d["owned"]
    privs = {(p["object_type"], p["name"], p["col"], p["privilege"], p["grantable"]) for p in d["privileges"]}
    assert ("table", "orders", "", "SELECT", False) in privs and ("table", "orders", "", "UPDATE", False) in privs
    assert ("table", "orders", "", "DELETE", True) in privs  # grant option is visible
    assert ("schema", "app", "", "USAGE", False) in privs
    assert ("column", "customers", "name", "SELECT", False) in privs
    assert all(p["grantee"] == "t_hold" for p in d["privileges"])
    assert not any(p["object_type"] == "database" for p in d["privileges"])  # that one is server-wide (see summary)
    assert [(x["for_role"], x["schema"], x["object_type"], x["privilege"]) for x in d["default_privileges"]] == [("postgres", "app", "tables", "SELECT")]
    assert [(g["grantee"], g["name"], g["privilege"]) for g in d["granted_to_others"]] == [("t_hold_other", "orders", "DELETE")]
    assert d["policies"] == []

    # a role holding nothing in a database
    mk(client, "t_hold_empty")
    empty = holdings(client, "t_hold_empty", database=DB)
    assert empty["owned"] == [] and empty["privileges"] == [] and empty["granted_to_others"] == []
    assert holdings(client, "t_hold_empty")["owns_objects"] is False


def test_holdings_errors(client):
    assert client.get("/api/roles/t_nobody/holdings").status_code == 404
    assert client.get("/api/roles/t_nobody/holdings", params={"database": DB}).status_code == 404
    mk(client, "t_hold_err")
    assert client.get("/api/roles/t_hold_err/holdings", params={"database": "no_such_db"}).status_code == 404
    # role names with a slash still work
    mk(client, "t_ho/ld")
    assert client.get("/api/roles/t_ho%2Fld/holdings").json()["role"] == "t_ho/ld"
