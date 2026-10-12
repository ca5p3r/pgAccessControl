from .conftest import DB, admin


def create(client, name, **kw):
    r = client.post("/api/roles", json={"name": name, **kw})
    assert r.status_code == 201, r.text


def objects(client, role, type="table", **params):
    r = client.get(f"/api/permissions/{role}/objects", params={"database": DB, "type": type, **params})
    assert r.status_code == 200, r.text
    return r.json()


def apply(client, role, changes, dry_run=False):
    return client.post(
        f"/api/permissions/{role}/apply", json={"database": DB, "changes": changes, "dry_run": dry_run}
    )


def by_name(data):
    return {i["name"]: i for i in data["items"]}


def test_grant_revoke_table_privileges(client):
    create(client, "t_reader")
    change = {"action": "grant", "object_type": "table", "schema": "app", "name": "orders",
              "privileges": ["select", "INSERT"]}
    r = apply(client, "t_reader", [change])
    assert r.status_code == 200, r.text
    assert r.json()["applied"] is True
    assert 'GRANT SELECT, INSERT ON TABLE "app"."orders" TO "t_reader"' in r.json()["statements"][0]

    items = by_name(objects(client, "t_reader", schema="app"))
    assert items["orders"]["direct"] == ["INSERT", "SELECT"]
    assert items["customers"]["direct"] == []
    assert items["order_totals"]["kind"] == "view"

    r = apply(client, "t_reader", [{**change, "action": "revoke", "privileges": ["INSERT"]}])
    assert r.status_code == 200
    assert by_name(objects(client, "t_reader", schema="app"))["orders"]["direct"] == ["SELECT"]


def test_dry_run_changes_nothing(client):
    create(client, "t_dry")
    r = apply(
        client, "t_dry",
        [{"action": "grant", "object_type": "all_tables", "schema": "app", "privileges": ["ALL"]}],
        dry_run=True,
    )
    assert r.status_code == 200 and r.json()["applied"] is False
    assert r.json()["statements"] == ['GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA "app" TO "t_dry";']
    assert objects(client, "t_dry", schema="app", granted_only=True)["total"] == 0


def test_inherited_privileges_show_their_source(client):
    create(client, "t_grp")
    create(client, "t_member", login=True, member_of=["t_grp"])
    apply(client, "t_grp", [{"action": "grant", "object_type": "table", "schema": "app",
                             "name": "customers", "privileges": ["SELECT"]}])
    item = by_name(objects(client, "t_member", schema="app"))["customers"]
    assert item["direct"] == []
    assert item["inherited"] == {"SELECT": ["t_grp"]}
    # the effective view agrees with PostgreSQL itself
    with admin(DB) as c:
        assert c.execute("SELECT has_table_privilege('t_member', 'app.customers', 'SELECT')").fetchone()[0]

    # A NOINHERIT member (set before it joins the group) does not inherit
    create(client, "t_noinherit", login=True, inherit=False, member_of=["t_grp"])
    item = by_name(objects(client, "t_noinherit", schema="app"))["customers"]
    assert item["inherited"] == {}


def test_granted_only_search_and_pagination(client):
    create(client, "t_page")
    apply(client, "t_page", [{"action": "grant", "object_type": "all_tables", "schema": "app", "privileges": ["SELECT"]}])
    data = objects(client, "t_page", schema="app", granted_only=True)
    assert data["total"] == 3
    page = objects(client, "t_page", schema="app", limit=2, offset=2)
    assert len(page["items"]) == 1 and page["total"] == 3
    past_end = objects(client, "t_page", schema="app", limit=2, offset=10)
    assert past_end["items"] == [] and past_end["total"] == 3
    assert [i["name"] for i in objects(client, "t_page", q="ORD")["items"]] == ["order_totals", "orders"]
    assert objects(client, "t_page", q="%")["total"] == 0  # wildcard is escaped


def test_sequences_functions_schemas_databases(client):
    create(client, "t_misc")
    changes = [
        {"action": "grant", "object_type": "sequence", "schema": "app", "name": "orders_id_seq", "privileges": ["USAGE", "SELECT"]},
        {"action": "grant", "object_type": "schema", "name": "app", "privileges": ["USAGE"]},
        {"action": "grant", "object_type": "database", "name": DB, "privileges": ["CONNECT"]},
    ]
    fn = by_name(objects(client, "t_misc", "function", schema="app"))["double"]
    assert fn["args"] == "i integer"
    changes.append({"action": "grant", "object_type": "function", "oid": fn["oid"], "privileges": ["EXECUTE"]})
    r = apply(client, "t_misc", changes)
    assert r.status_code == 200, r.text
    assert any("ROUTINE" in s for s in r.json()["statements"])

    assert by_name(objects(client, "t_misc", "sequence", schema="app"))["orders_id_seq"]["direct"] == ["SELECT", "USAGE"]
    assert by_name(objects(client, "t_misc", "schema"))["app"]["direct"] == ["USAGE"]
    assert by_name(objects(client, "t_misc", "database"))[DB]["direct"] == ["CONNECT"]
    # PUBLIC has EXECUTE on functions by default, which shows up as inherited
    assert by_name(objects(client, "t_misc", "function", schema="app"))["double"]["inherited"] == {"EXECUTE": ["PUBLIC"]}


def test_default_privileges_roundtrip(client):
    create(client, "t_defaults")
    change = {"action": "grant", "object_type": "default_tables", "schema": "app", "privileges": ["SELECT"],
              "for_role": "postgres"}
    assert apply(client, "t_defaults", [change]).status_code == 200
    rows = client.get("/api/permissions/t_defaults/default-privileges", params={"database": DB}).json()
    assert rows == [{"for_role": "postgres", "schema": "app", "object_type": "table", "privileges": ["SELECT"]}]
    assert apply(client, "t_defaults", [{**change, "action": "revoke"}]).status_code == 200
    assert client.get("/api/permissions/t_defaults/default-privileges", params={"database": DB}).json() == []


def test_public_pseudo_role(client):
    r = apply(client, "PUBLIC", [{"action": "revoke", "object_type": "database", "name": DB, "privileges": ["TEMPORARY"]}], dry_run=True)
    assert r.json()["statements"] == [f'REVOKE TEMPORARY ON DATABASE "{DB}" FROM PUBLIC;']
    db = by_name(objects(client, "PUBLIC", "database"))[DB]
    assert "CONNECT" in db["direct"]


def test_validation_and_errors(client):
    create(client, "t_val")
    bad = {"action": "grant", "object_type": "table", "schema": "app", "name": "orders"}
    assert apply(client, "t_val", [{**bad, "privileges": ["DROP"]}]).status_code == 400
    assert apply(client, "t_val", [{**bad, "privileges": ["SELECT; DROP TABLE app.orders"]}]).status_code == 400
    assert apply(client, "t_val", [{**bad, "privileges": ["SELECT"], "name": None}]).status_code == 400
    assert apply(client, "t_missing", [{**bad, "privileges": ["SELECT"]}]).status_code == 404
    assert apply(client, "t_val", [{**bad, "privileges": ["SELECT"], "name": "nope"}]).status_code == 404
    assert client.get("/api/permissions/t_val/objects", params={"database": "no_such_db"}).status_code == 404
    assert client.get("/api/permissions/t_missing/objects", params={"database": DB}).status_code == 404


def test_changes_are_atomic(client):
    create(client, "t_atomic")
    good = {"action": "grant", "object_type": "table", "schema": "app", "name": "orders", "privileges": ["SELECT"]}
    bad = {**good, "name": "does_not_exist"}
    assert apply(client, "t_atomic", [good, bad]).status_code == 404
    assert by_name(objects(client, "t_atomic", schema="app"))["orders"]["direct"] == []


def test_meta_and_lists(client):
    meta = client.get("/api/meta").json()
    assert meta["is_superuser"] and "SELECT" in meta["privileges"]["table"]
    assert DB in [d["name"] for d in client.get("/api/databases").json()]
    assert "app" in client.get("/api/schemas", params={"database": DB}).json()
    assert "pg_catalog" not in client.get("/api/schemas", params={"database": DB}).json()
    stats = client.get("/api/stats").json()
    assert stats["databases"] >= 2
    assert client.get("/api/health").json()["database"] == "up"


# ---------------------------------------------------------------------------
# Column-level privileges
# ---------------------------------------------------------------------------
def columns(client, role, table="orders"):
    r = client.get(f"/api/permissions/{role}/columns", params={"database": DB, "schema": "app", "table": table})
    assert r.status_code == 200, r.text
    return r.json()


def test_column_privileges_grant_read_revoke(client):
    create(client, "t_col")
    change = {"action": "grant", "object_type": "column", "schema": "app", "name": "customers",
              "columns": ["id", "name"], "privileges": ["SELECT", "update"]}
    r = apply(client, "t_col", [change])
    assert r.status_code == 200, r.text
    assert r.json()["statements"] == [
        'GRANT SELECT ("id", "name"), UPDATE ("id", "name") ON TABLE "app"."customers" TO "t_col";']

    data = columns(client, "t_col", "customers")
    by = {c["name"]: c for c in data["columns"]}
    assert by["name"]["direct"] == ["SELECT", "UPDATE"] and by["id"]["direct"] == ["SELECT", "UPDATE"]
    assert data["table_level"] == {}  # nothing table-wide
    with admin(DB) as c:
        assert c.execute("SELECT has_column_privilege('t_col', 'app.customers', 'name', 'SELECT')").fetchone()[0]
        assert not c.execute("SELECT has_table_privilege('t_col', 'app.customers', 'SELECT')").fetchone()[0]

    # a table-level grant shows up as covering every column, and inheritance is reported
    create(client, "t_col_g")
    create(client, "t_col_u", login=True, member_of=["t_col_g"])
    apply(client, "t_col_g", [{"action": "grant", "object_type": "column", "schema": "app", "name": "orders",
                               "columns": ["total"], "privileges": ["SELECT"]}])
    apply(client, "t_col_g", [{"action": "grant", "object_type": "table", "schema": "app", "name": "orders",
                               "privileges": ["INSERT"]}])
    d = columns(client, "t_col_u")
    assert {c["name"]: c["inherited"] for c in d["columns"]}["total"] == {"SELECT": ["t_col_g"]}
    assert d["table_level"] == {"INSERT": ["t_col_g"]}

    r = apply(client, "t_col", [{**change, "action": "revoke", "columns": ["name"], "privileges": ["UPDATE"]}])
    assert r.status_code == 200
    by = {c["name"]: c for c in columns(client, "t_col", "customers")["columns"]}
    assert by["name"]["direct"] == ["SELECT"] and by["id"]["direct"] == ["SELECT", "UPDATE"]


def test_column_validation_and_export(client):
    create(client, "t_colx")
    base = {"action": "grant", "object_type": "column", "schema": "app", "name": "customers"}
    assert apply(client, "t_colx", [{**base, "privileges": ["SELECT"]}]).status_code == 400  # columns required
    assert apply(client, "t_colx", [{**base, "columns": ["id"], "privileges": ["DELETE"]}]).status_code == 400
    assert apply(client, "t_colx", [{**base, "columns": ["nope"], "privileges": ["SELECT"]}]).status_code == 400
    assert apply(client, "t_colx", [{**base, "columns": ['id"); DROP TABLE app.orders; --'], "privileges": ["SELECT"]}]).status_code == 400
    with admin(DB) as c:
        assert c.execute("SELECT to_regclass('app.orders')").fetchone()[0] is not None
    assert client.get("/api/permissions/t_colx/columns", params={"database": DB, "schema": "app", "table": "zzz"}).status_code == 404

    assert apply(client, "t_colx", [{**base, "columns": ["id", "name"], "privileges": ["SELECT"]}]).status_code == 200
    script = client.get("/api/export", params={"database": DB, "role": "t_colx", "format": "sql"}).text
    assert 'GRANT SELECT ("id", "name") ON TABLE "app"."customers" TO "t_colx";' in script
    rows = client.get("/api/export", params={"database": DB, "role": "t_colx", "format": "json"}).json()["privileges"]
    assert {r["col"] for r in rows if r["object_type"] == "column"} == {"id", "name"}


# ---------------------------------------------------------------------------
# Grant option, cascade, grantor
# ---------------------------------------------------------------------------
def acl_grantors(table="orders"):
    with admin(DB) as c:
        return {
            (g, e)
            for g, e in c.execute(
                f"SELECT a.grantor::regrole::text, a.grantee::regrole::text FROM pg_class c, aclexplode(c.relacl) a "
                f"WHERE c.oid = 'app.{table}'::regclass"
            ).fetchall()
        }


def test_grant_option_toggle_and_cascade(client):
    create(client, "t_del")
    create(client, "t_sub")
    obj = {"object_type": "table", "schema": "app", "name": "orders", "privileges": ["SELECT"]}
    # add the grant option to an existing grant
    assert apply(client, "t_del", [{"action": "grant", **obj}]).status_code == 200
    assert by_name(objects(client, "t_del", schema="app"))["orders"]["grantable"] == []
    assert apply(client, "t_del", [{"action": "grant", "with_grant_option": True, **obj}]).status_code == 200
    assert by_name(objects(client, "t_del", schema="app"))["orders"]["grantable"] == ["SELECT"]

    # t_del delegates to t_sub, recorded with t_del as the grantor (it needs USAGE on the schema to name the table)
    assert apply(client, "t_del", [{"action": "grant", "object_type": "schema", "name": "app", "privileges": ["USAGE"]}]).status_code == 200
    r = apply_as(client, "t_sub", [{"action": "grant", **obj}], grantor="t_del")
    assert r.status_code == 200, r.text
    assert r.json()["statements"][0] == 'SET LOCAL ROLE "t_del";'
    assert ("t_del", "t_sub") in acl_grantors()

    # removing the option while dependents exist needs CASCADE, which removes the delegated grant
    rev = {"action": "revoke", "revoke_grant_option": True, **obj}
    r = apply(client, "t_del", [rev])
    assert r.status_code == 409 or r.status_code == 400
    assert "dependent privileges" in r.json()["detail"]
    r = apply(client, "t_del", [{**rev, "cascade": True}])
    assert r.status_code == 200, r.text
    assert r.json()["statements"] == ['REVOKE GRANT OPTION FOR SELECT ON TABLE "app"."orders" FROM "t_del" CASCADE;']
    item = by_name(objects(client, "t_del", schema="app"))["orders"]
    assert item["direct"] == ["SELECT"] and item["grantable"] == []  # still has SELECT, can no longer pass it on
    assert by_name(objects(client, "t_sub", schema="app"))["orders"]["direct"] == []
    assert ("t_del", "t_sub") not in acl_grantors()


def apply_as(client, role, changes, grantor):
    return client.post(
        f"/api/permissions/{role}/apply", json={"database": DB, "changes": changes, "grantor": grantor}
    )


def test_grantor_validation_and_atomicity(client):
    create(client, "t_gt")
    ch = [{"action": "grant", "object_type": "table", "schema": "app", "name": "orders", "privileges": ["SELECT"]}]
    assert apply_as(client, "t_gt", ch, grantor="t_nobody").status_code == 404
    assert apply_as(client, "t_gt", ch, grantor="PUBLIC").status_code == 400
    # a grantor without the right to grant: PostgreSQL refuses and nothing is changed
    create(client, "t_plain")
    r = apply_as(client, "t_gt", ch, grantor="t_plain")
    assert r.status_code in (400, 403)
    assert by_name(objects(client, "t_gt", schema="app"))["orders"]["direct"] == []
    # the grantor shows up in the audit entry
    apply_as(client, "t_gt", ch, grantor="postgres")
    e = client.get("/api/audit", params={"target": "t_gt", "action": "permission.", "status": "success"}).json()["items"][0]
    assert e["details"]["grantor"] == "postgres" and e["statements"][0] == 'SET LOCAL ROLE "postgres";'
