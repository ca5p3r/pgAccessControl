"""Object ownership: browse owners, hand objects over, move everything one role owns."""

import pytest

from .conftest import DB, admin
from .test_rbac import ACCT_PW, S, env, sign_in  # noqa: F401  (fixtures)


def mk(client, name, **kw):
    r = client.post("/api/roles", json={"name": name, **kw})
    assert r.status_code == 201, r.text


def owners_of(*queries):
    with admin(DB) as c:
        return [c.execute(q).fetchone()[0] for q in queries]


def objs(client, **params):
    r = client.get("/api/ownership/objects", params={"database": DB, **params})
    assert r.status_code == 200, r.text
    return r.json()


def pick(client, type, name, schema="app"):
    items = objs(client, type=type, schema=schema, q=name)["items"]
    return next(i for i in items if i["name"] == name)


@pytest.fixture
def owned_tables():
    """Two tables, a view, a function, an enum and a domain, all in schema own_s and owned by postgres."""
    with admin(DB) as c:
        c.execute("DROP SCHEMA IF EXISTS own_s CASCADE")
        c.execute(
            """CREATE SCHEMA own_s;
               CREATE TABLE own_s.t1 (id serial PRIMARY KEY, v int);
               CREATE TABLE own_s.t2 (id int);
               CREATE VIEW own_s.v1 AS SELECT * FROM own_s.t1;
               CREATE MATERIALIZED VIEW own_s.mv1 AS SELECT * FROM own_s.t2;
               CREATE FUNCTION own_s.f1(i int) RETURNS int LANGUAGE sql AS 'SELECT i';
               CREATE PROCEDURE own_s.p1() LANGUAGE sql AS 'SELECT 1';
               CREATE TYPE own_s.en AS ENUM ('a', 'b');
               CREATE DOMAIN own_s.dm AS int;"""
        )
    yield
    with admin(DB) as c:
        c.execute("DROP SCHEMA IF EXISTS own_s CASCADE")


def test_list_filter_and_summary(client, owned_tables):
    mk(client, "t_own1")
    with admin(DB) as c:
        c.execute('ALTER TABLE own_s.t2 OWNER TO "t_own1"')

    everything = objs(client, type="table", schema="own_s")
    assert {i["name"] for i in everything["items"]} == {"t1", "t2", "v1", "mv1"}
    kinds = {i["name"]: i["kind"] for i in everything["items"]}
    assert kinds == {"t1": "table", "t2": "table", "v1": "view", "mv1": "matview"}

    mine = objs(client, type="table", schema="own_s", owner="t_own1")
    assert [i["name"] for i in mine["items"]] == ["t2"] and mine["total"] == 1
    assert objs(client, type="table", schema="own_s", owner="nobody_here")["items"] == []
    assert [i["name"] for i in objs(client, type="table", schema="own_s", q="T1")["items"]] == ["t1"]
    assert objs(client, type="table", schema="own_s", limit=2, offset=2)["total"] == 4
    # the search matches "schema.name", so no separate schema filter is needed
    assert sorted(i["name"] for i in objs(client, type="table", q="own_s.t")["items"]) == ["t1", "t2"]
    assert [i["name"] for i in objs(client, type="table", q="own_s.mv")["items"]] == ["mv1"]

    assert {i["name"]: i["kind"] for i in objs(client, type="function", schema="own_s")["items"]} == {"f1": "function", "p1": "procedure"}
    assert {i["name"]: i["kind"] for i in objs(client, type="type", schema="own_s")["items"]} == {"en": "enum", "dm": "domain"}
    assert objs(client, type="schema", q="own_s")["items"][0]["owner"] == "postgres"
    assert any(i["name"] == DB for i in objs(client, type="database")["items"])
    # system schemas stay out unless asked for
    assert not any(i["schema"] == "pg_catalog" for i in objs(client, type="function")["items"])

    seqs = objs(client, type="sequence", schema="own_s")["items"]
    assert seqs[0]["linked_to"] == "own_s.t1"  # serial column: the sequence follows its table

    s = client.get("/api/ownership/summary", params={"database": DB}).json()["owners"]
    me = next(o for o in s if o["owner"] == "t_own1")
    assert me["counts"] == {"table": 1} and me["total"] == 1 and me["kind"] == "role"
    assert next(o for o in s if o["owner"] == "postgres")["superuser"] is True


def test_change_owner_of_selected_objects(client, owned_tables):
    mk(client, "t_new", login=True)
    t1, v1, f1, en, dm = (pick(client, "table", "t1", "own_s"), pick(client, "table", "v1", "own_s"),
                          pick(client, "function", "f1", "own_s"), pick(client, "type", "en", "own_s"),
                          pick(client, "type", "dm", "own_s"))
    items = [{"object_type": "table", "oid": t1["oid"]}, {"object_type": "table", "oid": v1["oid"]},
             {"object_type": "function", "oid": f1["oid"]}, {"object_type": "type", "oid": en["oid"]},
             {"object_type": "type", "oid": dm["oid"]}]

    # preview: SQL is shown, nothing is changed
    r = client.post("/api/ownership/change", json={"database": DB, "new_owner": "t_new", "items": items, "dry_run": True})
    assert r.status_code == 200, r.text
    prev = r.json()
    assert prev["applied"] is False and prev["changed"] == 5
    assert 'ALTER TABLE "own_s"."t1" OWNER TO "t_new";' in prev["statements"]
    assert 'ALTER VIEW "own_s"."v1" OWNER TO "t_new";' in prev["statements"]
    assert 'ALTER ROUTINE "own_s"."f1"(i integer) OWNER TO "t_new";' in prev["statements"]
    assert 'ALTER TYPE "own_s"."dm" OWNER TO "t_new";' in prev["statements"]
    assert owners_of("select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t1'::regclass") == ["postgres"]

    r = client.post("/api/ownership/change", json={"database": DB, "new_owner": "t_new", "items": items})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] is True and r.json()["changed"] == 5
    assert owners_of(
        "select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t1'::regclass",
        "select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t1_id_seq'::regclass",  # followed its table
        "select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t2'::regclass",
        "select pg_get_userbyid(proowner) from pg_proc where oid = 'own_s.f1'::regproc",
        "select pg_get_userbyid(typowner) from pg_type where oid = 'own_s.dm'::regtype",
    ) == ["t_new", "t_new", "postgres", "t_new", "t_new"]

    # doing it again changes nothing and says so
    r = client.post("/api/ownership/change", json={"database": DB, "new_owner": "t_new", "items": items}).json()
    assert r["changed"] == 0 and len(r["skipped"]) == 5 and "already owned" in r["skipped"][0]["reason"]

    # it is recorded
    log = client.get("/api/audit", params={"action": "ownership.change", "target": "t_new"}).json()
    assert log["items"] and "owner of" in log["items"][0]["summary"] and "ALTER TABLE" in log["items"][0]["statements"][0]


def test_change_by_filter_procedures_and_matviews(client, owned_tables):
    mk(client, "t_flt")
    r = client.post("/api/ownership/change", json={
        "database": DB, "new_owner": "t_flt", "filter": {"object_type": "table", "schema": "own_s", "q": "1"}})
    assert r.status_code == 200, r.text
    assert r.json()["changed"] == 3  # t1, v1 and mv1 contain "1"
    assert {o["object"] for o in r.json()["objects"]} == {"table own_s.t1", "view own_s.v1", "matview own_s.mv1"}
    assert owners_of("select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.mv1'::regclass") == ["t_flt"]
    assert owners_of("select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t2'::regclass") == ["postgres"]

    p1 = pick(client, "function", "p1", "own_s")
    r = client.post("/api/ownership/change", json={"database": DB, "new_owner": "t_flt", "items": [{"object_type": "function", "oid": p1["oid"]}]})
    assert r.status_code == 200 and "ALTER ROUTINE" in r.json()["statements"][0]
    assert owners_of("select pg_get_userbyid(proowner) from pg_proc where oid = 'own_s.p1'::regproc") == ["t_flt"]


def test_linked_sequences_are_reported_not_altered(client, owned_tables):
    mk(client, "t_seq")
    seq = pick(client, "sequence", "t1_id_seq", "own_s")
    r = client.post("/api/ownership/change", json={"database": DB, "new_owner": "t_seq", "items": [{"object_type": "sequence", "oid": seq["oid"]}]})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["changed"] == 0 and "owned by own_s.t1" in j["skipped"][0]["reason"] and "change the table" in j["skipped"][0]["reason"]

    # selected together with its table, it is explained as following the table
    t1 = pick(client, "table", "t1", "own_s")
    r = client.post("/api/ownership/change", json={"database": DB, "new_owner": "t_seq", "items": [
        {"object_type": "sequence", "oid": seq["oid"]}, {"object_type": "table", "oid": t1["oid"]}]}).json()
    assert r["changed"] == 1 and "together with its table" in r["skipped"][0]["reason"]
    assert owners_of("select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t1_id_seq'::regclass") == ["t_seq"]


def test_schema_and_database_ownership(client, owned_tables):
    mk(client, "t_big", createdb=True)
    sch = pick(client, "schema", "own_s", "own_s")
    r = client.post("/api/ownership/change", json={"database": DB, "new_owner": "t_big", "items": [{"object_type": "schema", "oid": sch["oid"]}]})
    assert r.status_code == 200, r.text
    assert owners_of("select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'own_s'") == ["t_big"]

    with admin() as c:
        c.execute("DROP DATABASE IF EXISTS t_owned_db WITH (FORCE)")
        c.execute("CREATE DATABASE t_owned_db")
    try:
        db = next(i for i in objs(client, type="database")["items"] if i["name"] == "t_owned_db")
        r = client.post("/api/ownership/change", json={"database": DB, "new_owner": "t_big", "items": [{"object_type": "database", "oid": db["oid"]}]})
        assert r.status_code == 200, r.text
        assert r.json()["statements"] == ['ALTER DATABASE "t_owned_db" OWNER TO "t_big";']
        assert next(i for i in objs(client, type="database")["items"] if i["name"] == "t_owned_db")["owner"] == "t_big"
    finally:
        with admin() as c:
            c.execute("DROP DATABASE IF EXISTS t_owned_db WITH (FORCE)")


def test_validation_and_atomicity(client, owned_tables):
    mk(client, "t_ok")
    t1 = pick(client, "table", "t1", "own_s")
    one = [{"object_type": "table", "oid": t1["oid"]}]
    post = lambda **kw: client.post("/api/ownership/change", json={"database": DB, **kw})  # noqa: E731

    assert post(new_owner="no_such_role", items=one).status_code == 404
    assert post(new_owner="PUBLIC", items=one).status_code == 400
    assert post(new_owner="pg_read_all_data", items=one).status_code == 400
    assert post(new_owner="t_ok").status_code == 422  # neither items nor filter
    assert post(new_owner="t_ok", items=one, filter={"object_type": "table"}).status_code == 422  # both
    # an object that vanished is reported before anything changes
    gone = post(new_owner="t_ok", items=one + [{"object_type": "table", "oid": 1}])
    assert gone.status_code == 404 and "no longer exist" in gone.json()["detail"]
    assert owners_of("select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t1'::regclass") == ["postgres"]

    # PostgreSQL refusing the second statement rolls back the first: an event trigger vetoes changes to t3
    with admin(DB) as c:
        c.execute("CREATE TABLE own_s.t3 (id int)")
        c.execute(
            """CREATE FUNCTION own_s.veto() RETURNS event_trigger LANGUAGE plpgsql AS $$
               DECLARE r record;
               BEGIN
                 FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
                   IF r.object_identity = 'own_s.t3' THEN RAISE EXCEPTION 'vetoed %', r.object_identity; END IF;
                 END LOOP;
               END $$"""
        )
        c.execute("CREATE EVENT TRIGGER t_veto ON ddl_command_end WHEN TAG IN ('ALTER TABLE') EXECUTE FUNCTION own_s.veto()")
    try:
        t2, t3 = pick(client, "table", "t2", "own_s"), pick(client, "table", "t3", "own_s")
        r = post(new_owner="t_ok", items=[{"object_type": "table", "oid": t2["oid"]}, {"object_type": "table", "oid": t3["oid"]}])
        assert r.status_code == 400 and "vetoed" in r.json()["detail"]
        assert owners_of("select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t2'::regclass") == ["postgres"]
        failed = client.get("/api/audit", params={"action": "ownership.change", "status": "failed"}).json()["items"]
        assert failed and "ALTER TABLE" in failed[0]["statements"][0]  # the attempt is on record
    finally:
        with admin(DB) as c:
            c.execute("DROP EVENT TRIGGER IF EXISTS t_veto")


def test_reassign_everything(client, owned_tables):
    mk(client, "t_from")
    mk(client, "t_to")
    with admin(DB) as c:
        c.execute('ALTER TABLE own_s.t1 OWNER TO "t_from"')
        c.execute('ALTER TABLE own_s.t2 OWNER TO "t_from"')
        c.execute('ALTER SCHEMA own_s OWNER TO "t_from"')
    r = client.post("/api/ownership/reassign", json={"from_role": "t_from", "to_role": "t_to", "dry_run": True})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["applied"] is False and j["places"][DB] >= 3
    assert any('REASSIGN OWNED BY "t_from" TO "t_to";' in s and DB in s for s in j["statements"])
    assert owners_of("select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t1'::regclass") == ["t_from"]

    r = client.post("/api/ownership/reassign", json={"from_role": "t_from", "to_role": "t_to", "database": DB})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] is True
    assert owners_of("select count(*) from pg_class where relowner = 't_from'::regrole") == [0]
    assert owners_of("select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'own_s'") == ["t_to"]
    # the source role can now be dropped without reassigning anything
    assert client.delete("/api/roles/t_from").status_code == 204

    assert client.post("/api/ownership/reassign", json={"from_role": "t_to", "to_role": "t_to"}).status_code == 400
    assert client.post("/api/ownership/reassign", json={"from_role": "ghost", "to_role": "t_to"}).status_code == 404
    assert client.post("/api/ownership/reassign", json={"from_role": "pg_monitor", "to_role": "t_to"}).status_code == 400
    log = client.get("/api/audit", params={"action": "ownership.reassign"}).json()["items"]
    assert log and "Handed everything t_from owns" in log[0]["summary"]


def test_roles_with_nothing_to_reassign(client):
    mk(client, "t_empty")
    mk(client, "t_dest")
    r = client.post("/api/ownership/reassign", json={"from_role": "t_empty", "to_role": "t_dest"})
    assert r.status_code == 200 and r.json()["places"] == {} and r.json()["statements"] == []


# --------------------------------------------------------------------- who may do what
def test_operators_and_viewers(S, owned_tables):
    root, op, vic = S["root"], S["olly_op"], S["vic_view"]
    for name in ("t_plain1", "t_plain2"):
        assert root.post("/api/roles", json={"name": name}).status_code == 201
    assert root.post("/api/roles", json={"name": "t_priv", "createrole": True}).status_code == 201
    with admin(DB) as c:
        c.execute('CREATE TABLE own_s.t_mine (id int)')
        c.execute('ALTER TABLE own_s.t_mine OWNER TO "t_plain1"')
    obj = lambda t, n, s="own_s": next(i for i in vic.get("/api/ownership/objects", params={"database": DB, "type": t, "schema": s, "q": n}).json()["items"] if i["name"] == n)  # noqa: E731
    mine, t1, sch = obj("table", "t_mine"), obj("table", "t1"), obj("schema", "own_s", "")
    body = lambda owner, *items: {"database": DB, "new_owner": owner, "items": [{"object_type": t, "oid": o["oid"]} for t, o in items]}  # noqa: E731

    # viewers can look but not touch
    assert vic.get("/api/ownership/summary", params={"database": DB}).status_code == 200
    assert vic.post("/api/ownership/change", json=body("t_plain2", ("table", mine))).status_code == 403
    assert vic.post("/api/ownership/reassign", json={"from_role": "t_plain1", "to_role": "t_plain2"}).status_code == 403

    # operators: ordinary roles only
    assert op.post("/api/ownership/change", json=body("t_plain2", ("table", mine))).status_code == 200
    assert owners_of("select pg_get_userbyid(relowner) from pg_class where oid = 'own_s.t_mine'::regclass") == ["t_plain2"]
    r = op.post("/api/ownership/change", json=body("t_priv", ("table", mine)))
    assert r.status_code == 403 and "privileged" in r.json()["detail"]
    r = op.post("/api/ownership/change", json=body("t_plain1", ("table", t1)))  # t1 belongs to the superuser
    assert r.status_code == 403
    r = op.post("/api/ownership/change", json=body("t_plain1", ("schema", sch)))
    assert r.status_code == 403 and "databases and schemas" in r.json()["detail"]
    assert op.post("/api/ownership/reassign", json={"from_role": "t_plain1", "to_role": "t_plain2"}).status_code == 403

    # admins may do all of it
    ann = S["ann_admin"]
    assert ann.post("/api/ownership/change", json=body("t_plain1", ("table", t1))).status_code == 200
    assert ann.post("/api/ownership/reassign", json={"from_role": "t_plain1", "to_role": "t_plain2", "database": DB}).status_code == 200
