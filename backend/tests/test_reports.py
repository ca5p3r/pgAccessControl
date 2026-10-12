import csv
import io

from .conftest import DB, admin


def mk(client, name, **kw):
    r = client.post("/api/roles", json={"name": name, **kw})
    assert r.status_code == 201, r.text


def grant(client, role, **change):
    r = client.post(
        f"/api/permissions/{role}/apply",
        json={"database": DB, "changes": [{"action": "grant", "privileges": ["SELECT"], **change}]},
    )
    assert r.status_code == 200, r.text


def table_oid(name):
    with admin(DB) as c:
        return c.execute("SELECT %s::regclass::oid", (name,)).fetchone()[0]


def report(client, type, oid):
    r = client.get("/api/access-report", params={"database": DB, "type": type, "oid": oid})
    assert r.status_code == 200, r.text
    d = r.json()
    return d, {p["name"]: p for p in d["principals"]}


def test_access_report_attributes_every_source(client):
    mk(client, "t_rep_grp")
    mk(client, "t_rep_user", login=True, member_of=["t_rep_grp"])
    mk(client, "t_rep_direct", login=True)
    mk(client, "t_rep_none", login=True)
    mk(client, "t_rep_pre", login=True, member_of=["pg_read_all_data"])
    grant(client, "t_rep_grp", object_type="table", schema="app", name="orders")
    grant(client, "t_rep_direct", object_type="table", schema="app", name="orders")

    data, p = report(client, "table", table_oid("app.orders"))
    assert data["object"]["name"] == "orders" and data["object"]["owner"] == "postgres"
    assert p["t_rep_grp"]["privileges"]["SELECT"] == ["direct"]
    assert p["t_rep_user"]["privileges"]["SELECT"] == ["t_rep_grp"]  # inherited, with the source role
    assert p["t_rep_direct"]["privileges"]["SELECT"] == ["direct"]
    assert "t_rep_none" not in p
    assert "predefined" in p["t_rep_pre"]["privileges"]["SELECT"][0]
    assert p["postgres"]["superuser"] and p["postgres"]["is_owner"]
    # a superuser is not reported as "inheriting" from every role, only direct + superuser
    assert p["postgres"]["privileges"]["SELECT"] == ["direct", "superuser"]
    assert {g["grantee"] for g in data["grants"]} >= {"t_rep_grp", "t_rep_direct", "postgres"}
    # cross-check against PostgreSQL itself for every principal reported
    with admin(DB) as c:
        for name, pr in p.items():
            for priv in pr["privileges"]:
                assert c.execute("SELECT has_table_privilege(%s, 'app.orders', %s)", (name, priv)).fetchone()[0]


def test_access_report_public_and_other_object_types(client):
    mk(client, "t_rep_any", login=True)
    fn = client.get("/api/objects", params={"database": DB, "type": "function", "schema": "app"}).json()["items"][0]
    assert fn["name"] == "double" and fn["args"] == "i integer"
    _, p = report(client, "function", fn["oid"])
    assert p["t_rep_any"]["privileges"]["EXECUTE"] == ["PUBLIC"]  # functions are executable by PUBLIC by default

    schema = client.get("/api/objects", params={"database": DB, "type": "schema", "q": "app"}).json()["items"][0]
    grant(client, "t_rep_any", object_type="schema", name="app", privileges=["USAGE"])
    _, p = report(client, "schema", schema["oid"])
    assert p["t_rep_any"]["privileges"]["USAGE"] == ["direct"]

    db = client.get("/api/objects", params={"database": DB, "type": "database", "q": DB}).json()["items"][0]
    _, p = report(client, "database", db["oid"])
    assert p["t_rep_any"]["privileges"]["CONNECT"] == ["PUBLIC"]

    assert client.get("/api/access-report", params={"database": DB, "type": "table", "oid": 1}).status_code == 404


def test_object_search(client):
    data = client.get("/api/objects", params={"database": DB, "type": "table", "schema": "app", "q": "ORD"}).json()
    assert [i["name"] for i in data["items"]] == ["order_totals", "orders"] and data["total"] == 2
    assert {i["kind"] for i in data["items"]} == {"table", "view"}
    assert client.get("/api/objects", params={"database": DB, "type": "table", "q": "%"}).json()["total"] == 0


def test_sql_export_round_trips(client):
    mk(client, "t_rt_grp")
    mk(client, "t_rt", login=True, createdb=True, connection_limit=3, comment="it's a test", member_of=["t_rt_grp"])
    grant(client, "t_rt", object_type="table", schema="app", name="orders", privileges=["SELECT", "UPDATE"])
    grant(client, "t_rt", object_type="schema", name="app", privileges=["USAGE"])
    r = client.post(
        "/api/permissions/t_rt/apply",
        json={"database": DB, "changes": [
            {"action": "grant", "object_type": "default_tables", "schema": "app", "privileges": ["SELECT"], "for_role": "postgres"}]},
    )
    assert r.status_code == 200, r.text

    r = client.get("/api/export", params={"database": DB, "role": "t_rt", "format": "sql"})
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    script = r.text
    assert 'CREATE ROLE "t_rt" WITH LOGIN' in script and "CONNECTION LIMIT 3" in script
    assert "it''s a test" in script and 'GRANT "t_rt_grp" TO "t_rt";' in script
    assert 'GRANT SELECT, UPDATE ON TABLE "app"."orders" TO "t_rt";' in script
    assert 'ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "app" GRANT SELECT ON TABLES TO "t_rt";' in script
    assert "PASSWORD" not in script

    # Destroy the role completely, replay the script, and check everything came back.
    assert client.delete("/api/roles/t_rt").status_code == 204
    with admin(DB) as c:
        c.execute(script)
        row = c.execute(
            "SELECT rolcanlogin, rolcreatedb, rolconnlimit, shobj_description(oid, 'pg_authid') "
            "FROM pg_roles WHERE rolname = 't_rt'"
        ).fetchone()
        assert row == (True, True, 3, "it's a test")
        assert c.execute("SELECT pg_has_role('t_rt', 't_rt_grp', 'MEMBER')").fetchone()[0]
        assert c.execute("SELECT has_table_privilege('t_rt', 'app.orders', 'UPDATE')").fetchone()[0]
        assert c.execute("SELECT has_schema_privilege('t_rt', 'app', 'USAGE')").fetchone()[0]
    again = client.get("/api/export", params={"database": DB, "role": "t_rt", "format": "sql"}).text
    assert again.split("\n", 3)[3] == script.split("\n", 3)[3]  # identical apart from the timestamp header


def test_csv_and_json_exports(client):
    mk(client, "t_csv", login=True, comment="=1+1")
    grant(client, "t_csv", object_type="table", schema="app", name="customers")
    r = client.get("/api/export", params={"database": DB, "role": "t_csv", "format": "csv", "dataset": "privileges"})
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0] == ["object_type", "schema", "object", "arguments", "owner", "grantee", "privilege", "grantable", "grantor"]
    assert ["table", "app", "customers", "", "postgres", "t_csv", "SELECT", "False", "postgres"] in rows
    roles = list(csv.reader(io.StringIO(client.get("/api/export", params={"role": "t_csv", "format": "csv", "dataset": "roles"}).text)))
    assert roles[1][0] == "t_csv" and roles[1][-1] == "'=1+1"  # formula neutralised

    j = client.get("/api/export", params={"database": DB, "format": "json"}).json()
    assert j["database"] == DB and {"roles", "memberships", "privileges", "default_privileges"} <= set(j)
    assert any(x["grantee"] == "t_csv" for x in j["privileges"])
    pub = client.get("/api/export", params={"database": DB, "role": "PUBLIC", "format": "json"}).json()
    assert pub["roles"] == [] and any(x["grantee"] == "PUBLIC" for x in pub["privileges"])


def test_export_errors_and_audit(client):
    assert client.get("/api/export", params={"role": "t_nobody"}).status_code == 404
    assert client.get("/api/export", params={"database": "no_such_db"}).status_code == 404
    assert client.get("/api/export", params={"format": "xml"}).status_code == 422
    client.get("/api/export", params={"database": DB, "role": "postgres", "format": "csv"})
    items = client.get("/api/audit", params={"action": "export."}).json()["items"]
    assert items and items[0]["summary"].startswith("Exported CSV postgres")
