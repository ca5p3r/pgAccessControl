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
