from app.services import drift

from .conftest import DB, admin


def mk(client, name, **kw):
    r = client.post("/api/roles", json={"name": name, **kw})
    assert r.status_code == 201, r.text


def snap(client, name, baseline=False, database=DB):
    r = client.post("/api/snapshots", json={"name": name, "database": database, "baseline": baseline})
    assert r.status_code == 201, r.text
    return r.json()


def report(client, sid, **params):
    r = client.get(f"/api/snapshots/{sid}/drift", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_drift_is_detected_and_remediation_restores_the_baseline(client):
    mk(client, "t_dr_a", login=True, comment="before")
    mk(client, "t_dr_g")
    mk(client, "t_dr_g2")
    mk(client, "t_dr_old")
    for role, ch in (
        ("t_dr_a", {"object_type": "table", "schema": "app", "name": "orders", "privileges": ["SELECT"]}),
        ("t_dr_a", {"object_type": "table", "schema": "app", "name": "customers", "privileges": ["SELECT"]}),
        ("t_dr_old", {"object_type": "table", "schema": "app", "name": "orders", "privileges": ["SELECT"]}),
    ):
        r = client.post(f"/api/permissions/{role}/apply", json={"database": DB, "changes": [{"action": "grant", **ch}]})
        assert r.status_code == 200, r.text
    client.put("/api/roles/t_dr_a/member-of", json={"roles": ["t_dr_g"]})

    meta = snap(client, "before changes", baseline=True)
    assert meta["baseline"] and meta["counts"]["roles"] >= 4 and meta["counts"]["privileges"] >= 3
    assert report(client, meta["id"])["total"] == 0  # nothing has changed yet

    # --- changes made behind the app's back (psql, pgAdmin, another tool) ---
    with admin(DB) as c:
        c.execute('GRANT UPDATE ON app.orders TO "t_dr_a"')  # added privilege
        c.execute('REVOKE SELECT ON app.customers FROM "t_dr_a"')  # removed privilege
        c.execute('GRANT SELECT ON app.orders TO "t_dr_a" WITH GRANT OPTION')  # changed: gained grant option
        c.execute('GRANT SELECT ("id") ON app.customers TO "t_dr_a"')  # added column privilege
        c.execute('ALTER ROLE "t_dr_a" CREATEDB')  # attribute change
        c.execute("COMMENT ON ROLE \"t_dr_a\" IS 'after'")
        c.execute('REVOKE "t_dr_g" FROM "t_dr_a"')  # membership removed
        c.execute('GRANT "t_dr_g2" TO "t_dr_a" WITH ADMIN OPTION')  # membership added
        c.execute('CREATE ROLE "t_dr_new" LOGIN')  # new role...
        c.execute('GRANT SELECT ON app.orders TO "t_dr_new"')  # ...with access
        c.execute('DROP OWNED BY "t_dr_old"')
        c.execute('DROP ROLE "t_dr_old"')  # role removed
        c.execute('ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA app GRANT SELECT ON TABLES TO "t_dr_a"')  # default added

    d = report(client, meta["id"])
    s = d["summary"]
    assert s["roles"] == {"added": 1, "removed": 1, "changed": 1}
    assert [r["name"] for r in d["roles"]["added"]] == ["t_dr_new"] and [r["name"] for r in d["roles"]["removed"]] == ["t_dr_old"]
    ch = d["roles"]["changed"][0]
    assert ch["item"]["name"] == "t_dr_a" and ch["changes"]["createdb"] == [False, True] and ch["changes"]["comment"] == ["before", "after"]
    assert s["memberships"]["added"] == 1 and s["memberships"]["removed"] == 1
    assert {(m["role"], m["member"]) for m in d["memberships"]["added"]} == {("t_dr_g2", "t_dr_a")}
    privs = {(p["grantee"], p["name"], p["col"], p["privilege"]) for p in d["privileges"]["added"]}
    assert ("t_dr_a", "orders", "", "UPDATE") in privs and ("t_dr_a", "customers", "id", "SELECT") in privs and ("t_dr_new", "orders", "", "SELECT") in privs
    assert [(p["grantee"], p["name"]) for p in d["privileges"]["removed"] if p["grantee"] in ("t_dr_a", "t_dr_old")] == [("t_dr_a", "customers"), ("t_dr_old", "orders")]
    assert [c["item"]["grantee"] for c in d["privileges"]["changed"]] == ["t_dr_a"]
    assert d["privileges"]["changed"][0]["changes"]["grantable"] == [False, True]
    assert s["defaults"]["added"] == 1 and d["total"] == sum(sum(v.values()) for v in s.values())

    # the UI list can be capped while the counts stay exact
    capped = report(client, meta["id"], limit=1)
    assert capped["truncated"] is True and capped["summary"] == s and len(capped["privileges"]["added"]) == 1

    # --- remediation: run the generated SQL and the drift disappears (except the new role, which is never dropped) ---
    r = client.get(f"/api/snapshots/{meta['id']}/remediation")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    script = r.text
    assert 'REVOKE UPDATE ON TABLE "app"."orders" FROM "t_dr_a";' in script
    assert 'GRANT SELECT ON TABLE "app"."customers" TO "t_dr_a";' in script
    assert 'REVOKE SELECT ("id") ON TABLE "app"."customers" FROM "t_dr_a";' in script
    assert '-- DROP ROLE "t_dr_new";' in script  # destructive step is only suggested, never emitted
    with admin(DB) as c:
        c.execute(script)
    left = report(client, meta["id"])
    assert left["total"] == 1 and [r["name"] for r in left["roles"]["added"]] == ["t_dr_new"], left["summary"]
    with admin(DB) as c:
        c.execute('REVOKE SELECT ON app.orders FROM "t_dr_new"')
    assert report(client, meta["id"])["total"] == 1  # still just the extra role (access to it is already gone)


def test_compare_two_snapshots_and_scheduled_check(client):
    mk(client, "t_dr2")
    base = snap(client, "base", baseline=True)
    with admin(DB) as c:
        c.execute('GRANT SELECT ON app.orders TO "t_dr2"')
    after = snap(client, "after")
    assert not after["baseline"]

    d = report(client, base["id"], against=after["id"])
    assert d["compared_with"]["kind"] == "snapshot" and d["compared_with"]["name"] == "after"
    assert d["summary"]["privileges"]["added"] == 1
    assert client.get(f"/api/snapshots/{base['id']}/remediation", params={"against": after["id"]}).status_code == 400
    assert report(client, after["id"], against=after["id"])["total"] == 0

    # the scheduled check reports a new drift once, stays quiet while it is unchanged, and reports it clearing
    run = lambda: client.portal.call(drift.check_baselines, client.app)  # noqa: E731
    assert run() == 1
    assert run() == 0
    found = client.get("/api/audit", params={"action": "drift.", "target": "base"}).json()["items"]
    assert [e["action"] for e in found] == ["drift.detected"] and found[0]["actor"] == "scheduler"
    assert "1 difference from baseline" in found[0]["summary"]
    with admin(DB) as c:
        c.execute('REVOKE SELECT ON app.orders FROM "t_dr2"')
    assert run() == 0
    actions = [e["action"] for e in client.get("/api/audit", params={"action": "drift.", "target": "base"}).json()["items"]]
    assert actions == ["drift.cleared", "drift.detected"]
    listed = {s["name"]: s for s in client.get("/api/snapshots").json()["items"]}
    assert listed["base"]["last_check"]["total"] == 0


def test_snapshot_management(client):
    a = snap(client, "mgmt-a", baseline=True)
    b = snap(client, "mgmt-b", baseline=True)  # only one baseline per database
    listed = {s["name"]: s for s in client.get("/api/snapshots").json()["items"]}
    assert listed["mgmt-a"]["baseline"] is False and listed["mgmt-b"]["baseline"] is True
    assert client.post(f"/api/snapshots/{a['id']}/baseline", json={"baseline": True}).json()["baseline"] is True
    assert {s["name"]: s["baseline"] for s in client.get("/api/snapshots").json()["items"]}["mgmt-b"] is False

    dup = client.post("/api/snapshots", json={"name": "mgmt-a", "database": DB})
    assert dup.status_code == 409
    assert client.post("/api/snapshots", json={"name": "x", "database": "no_such_db"}).status_code == 404
    assert client.post("/api/snapshots", json={"name": "", "database": DB}).status_code == 422

    dl = client.get(f"/api/snapshots/{a['id']}/download")
    assert dl.status_code == 200 and dl.json()["snapshot"]["name"] == "mgmt-a" and "roles" in dl.json()["data"]
    assert "password" not in dl.text.lower().replace("passwords", "")  # no credentials in snapshots

    assert client.delete(f"/api/snapshots/{a['id']}").status_code == 204
    assert client.delete(f"/api/snapshots/{b['id']}").status_code == 204
    assert client.get(f"/api/snapshots/{a['id']}/drift").status_code == 404
    assert client.delete(f"/api/snapshots/{a['id']}").status_code == 404
    log = client.get("/api/audit", params={"action": "snapshot."}).json()["items"]
    assert {"snapshot.create", "snapshot.delete", "snapshot.baseline"} <= {e["action"] for e in log}
