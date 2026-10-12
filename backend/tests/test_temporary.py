import sqlite3
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.services import expiring

from .conftest import DB, admin


def in_(**kw):
    return (datetime.now(timezone.utc) + timedelta(**kw)).isoformat()


def mk(client, name, **kw):
    r = client.post("/api/roles", json={"name": name, **kw})
    assert r.status_code == 201, r.text


def apply(client, role, changes, **extra):
    return client.post(f"/api/permissions/{role}/apply", json={"database": DB, "changes": changes, **extra})


def tbl(priv, table="orders", **kw):
    return {"action": "grant", "object_type": "table", "schema": "app", "name": table,
            "privileges": priv if isinstance(priv, list) else [priv], **kw}


def has(role, priv, table="app.orders"):
    with admin(DB) as c:
        return c.execute("SELECT has_table_privilege(%s, %s, %s)", (role, table, priv)).fetchone()[0]


def schedules(client, **params):
    r = client.get("/api/temporary", params={"status": "all", **params})
    assert r.status_code == 200, r.text
    return r.json()["items"]


def run_when_due(client, schedule_id):
    """Pretend the deadline has passed and run the background job once."""
    conn = sqlite3.connect(get_settings().data_db_path)
    conn.execute("UPDATE expiring_access SET expires_at = ? WHERE id = ?", (in_(minutes=-5), schedule_id))
    conn.commit()
    conn.close()
    return client.portal.call(expiring.run_due, client.app)


def test_temporary_grant_is_revoked_at_expiry(client):
    mk(client, "t_tmp1")
    r = apply(client, "t_tmp1", [tbl(["SELECT", "UPDATE"])], expires_at=in_(hours=2))
    assert r.status_code == 200, r.text
    t = r.json()["temporary"]
    assert t["expiring"] == ["SELECT/UPDATE on app.orders"] and t["skipped"] == [] and t["schedule_id"]
    assert has("t_tmp1", "SELECT") and has("t_tmp1", "UPDATE")

    [s] = schedules(client, involving="t_tmp1")
    assert s["status"] == "pending" and s["kind"] == "grant" and s["database"] == DB and s["created_by"] == "anonymous"
    assert client.get("/api/temporary", params={"involving": "t_tmp1"}).json()["items"][0]["id"] == s["id"]

    assert run_when_due(client, s["id"]) == 1
    assert not has("t_tmp1", "SELECT") and not has("t_tmp1", "UPDATE")
    [s] = schedules(client, involving="t_tmp1")
    assert s["status"] == "expired" and s["error"] is None
    # nothing left to run, and it was audited as the scheduler
    assert client.portal.call(expiring.run_due, client.app) == 0
    e = client.get("/api/audit", params={"target": "t_tmp1", "action": "access.expired"}).json()["items"][0]
    assert e["actor"] == "scheduler" and e["status"] == "success"
    assert 'REVOKE SELECT, UPDATE ON TABLE "app"."orders" FROM "t_tmp1";' in e["statements"]


def test_permanent_grants_are_never_removed_by_an_expiring_overlap(client):
    mk(client, "t_tmp2")
    assert apply(client, "t_tmp2", [tbl("SELECT")]).status_code == 200  # permanent
    r = apply(client, "t_tmp2", [tbl(["SELECT", "UPDATE"])], expires_at=in_(hours=1))
    t = r.json()["temporary"]
    assert t["expiring"] == ["UPDATE on app.orders"] and t["skipped"] == ["SELECT on app.orders"]
    run_when_due(client, t["schedule_id"])
    assert has("t_tmp2", "SELECT") and not has("t_tmp2", "UPDATE")

    # nothing new to expire -> no schedule at all
    r = apply(client, "t_tmp2", [tbl("SELECT")], expires_at=in_(hours=1)).json()["temporary"]
    assert r["schedule_id"] is None and r["skipped"] == ["SELECT on app.orders"]


def test_temporary_grant_option_and_columns(client):
    mk(client, "t_tmp3")
    assert apply(client, "t_tmp3", [tbl("SELECT")]).status_code == 200
    t = apply(client, "t_tmp3", [tbl("SELECT", with_grant_option=True)], expires_at=in_(hours=1)).json()["temporary"]
    assert t["expiring"] == ["grant option on SELECT on app.orders"]
    run_when_due(client, t["schedule_id"])
    item = client.get("/api/permissions/t_tmp3/objects", params={"database": DB, "schema": "app", "q": "orders"}).json()["items"][0]
    assert item["direct"] == ["SELECT"] and item["grantable"] == []  # still has SELECT, lost the option

    col = {"action": "grant", "object_type": "column", "schema": "app", "name": "customers", "columns": ["id", "name"], "privileges": ["SELECT"]}
    assert apply(client, "t_tmp3", [{**col, "columns": ["id"]}]).status_code == 200  # id is permanent
    t = apply(client, "t_tmp3", [col], expires_at=in_(hours=1)).json()["temporary"]
    assert t["expiring"] == ["SELECT on app.customers (name)"] and t["skipped"] == ["SELECT on app.customers (id)"]
    run_when_due(client, t["schedule_id"])
    with admin(DB) as c:
        assert c.execute("SELECT has_column_privilege('t_tmp3', 'app.customers', 'id', 'SELECT')").fetchone()[0]
        assert not c.execute("SELECT has_column_privilege('t_tmp3', 'app.customers', 'name', 'SELECT')").fetchone()[0]


def test_dry_run_previews_without_scheduling(client):
    mk(client, "t_tmp4")
    r = apply(client, "t_tmp4", [tbl("SELECT")], expires_at=in_(hours=1), dry_run=True).json()
    assert r["applied"] is False and r["temporary"]["expiring"] == ["SELECT on app.orders"]
    assert schedules(client, involving="t_tmp4") == [] and not has("t_tmp4", "SELECT")


def test_expiry_validation(client):
    mk(client, "t_tmp5")
    assert apply(client, "t_tmp5", [tbl("SELECT")], expires_at=in_(minutes=-1)).status_code == 422
    assert apply(client, "t_tmp5", [tbl("SELECT")], expires_at=in_(days=4000)).status_code == 422
    revoke = {**tbl("SELECT"), "action": "revoke"}
    assert apply(client, "t_tmp5", [revoke], expires_at=in_(hours=1)).status_code == 400
    bulk = {"action": "grant", "object_type": "all_tables", "schema": "app", "privileges": ["SELECT"]}
    r = apply(client, "t_tmp5", [bulk], expires_at=in_(hours=1))
    assert r.status_code == 400 and "individual objects" in r.json()["detail"]
    # rejected requests change nothing
    assert not has("t_tmp5", "SELECT") and schedules(client, involving="t_tmp5") == []


def test_cancel_extend_and_revoke_now(client):
    mk(client, "t_tmp6")
    sid = apply(client, "t_tmp6", [tbl("SELECT")], expires_at=in_(hours=1)).json()["temporary"]["schedule_id"]
    new = in_(days=2)
    r = client.post(f"/api/temporary/{sid}/extend", json={"expires_at": new})
    assert r.status_code == 200 and r.json()["expires_at"][:13] == new[:13]
    assert client.post(f"/api/temporary/{sid}/extend", json={"expires_at": in_(minutes=-3)}).status_code == 422

    r = client.post(f"/api/temporary/{sid}/cancel")
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    run_when_due(client, sid)  # a cancelled schedule never runs
    assert has("t_tmp6", "SELECT")
    assert client.post(f"/api/temporary/{sid}/cancel").status_code == 409
    assert client.post(f"/api/temporary/{sid}/revoke-now").status_code == 409

    sid = apply(client, "t_tmp6", [tbl("UPDATE")], expires_at=in_(hours=1)).json()["temporary"]["schedule_id"]
    r = client.post(f"/api/temporary/{sid}/revoke-now")
    assert r.status_code == 200 and r.json()["status"] == "expired"
    assert not has("t_tmp6", "UPDATE") and has("t_tmp6", "SELECT")
    e = client.get("/api/audit", params={"target": "t_tmp6", "action": "access."}).json()["items"]
    assert {x["action"] for x in e} >= {"access.extend", "access.cancel", "access.revoke_now"}
    assert client.post("/api/temporary/999999/cancel").status_code == 404


def test_temporary_membership(client):
    mk(client, "t_tmp_g")
    mk(client, "t_tmp_u", login=True, member_of=["t_tmp_g"])
    body = {"role": "t_tmp_g", "member": "t_tmp_u", "expires_at": in_(hours=3)}
    r = client.put("/api/temporary/membership", json=body)
    assert r.status_code == 200, r.text
    sid = r.json()["schedule"]["id"]
    # seen from either side, and re-saving updates rather than duplicates
    assert [s["id"] for s in schedules(client, involving="t_tmp_g")] == [sid]
    assert [s["id"] for s in schedules(client, involving="t_tmp_u")] == [sid]
    assert client.put("/api/temporary/membership", json={**body, "expires_at": in_(hours=5)}).json()["schedule"]["id"] == sid

    assert client.put("/api/temporary/membership", json={"role": "t_tmp_g", "member": "postgres", "expires_at": in_(hours=1)}).status_code == 404
    assert client.put("/api/temporary/membership", json={**body, "expires_at": in_(minutes=-1)}).status_code == 422

    run_when_due(client, sid)
    with admin(DB) as c:
        assert not c.execute("SELECT pg_has_role('t_tmp_u', 't_tmp_g', 'MEMBER')").fetchone()[0]
    assert schedules(client, involving="t_tmp_u")[0]["status"] == "expired"

    # clearing the expiry makes the membership permanent again
    client.put("/api/roles/t_tmp_u/member-of", json={"roles": ["t_tmp_g"]})
    assert client.put("/api/temporary/membership", json=body).status_code == 200
    r = client.put("/api/temporary/membership", json={**body, "expires_at": None})
    assert r.json() == {"schedule": None}
    assert [s["status"] for s in schedules(client, involving="t_tmp_u")][0] == "cancelled"


def test_expiry_of_something_already_gone_is_not_an_error(client):
    mk(client, "t_tmp7")
    sid = apply(client, "t_tmp7", [tbl("SELECT")], expires_at=in_(hours=1)).json()["temporary"]["schedule_id"]
    with admin(DB) as c:
        c.execute('DROP OWNED BY "t_tmp7"')
        c.execute('DROP ROLE "t_tmp7"')
    run_when_due(client, sid)
    [s] = schedules(client, involving="t_tmp7")
    assert s["status"] == "expired"
    e = client.get("/api/audit", params={"target": "t_tmp7", "action": "access.expired"}).json()["items"][0]
    assert "already removed" in e["details"]["note"]


def test_claiming_is_atomic(client):
    mk(client, "t_tmp8")
    sid = apply(client, "t_tmp8", [tbl("SELECT")], expires_at=in_(hours=1)).json()["temporary"]["schedule_id"]
    store = client.app.state.store
    conn = sqlite3.connect(get_settings().data_db_path)
    conn.execute("UPDATE expiring_access SET expires_at = ? WHERE id = ?", (in_(minutes=-5), sid))
    conn.commit()
    conn.close()
    first = client.portal.call(store.run, expiring.db_claim_due, expiring.iso(expiring.now()), 10)
    second = client.portal.call(store.run, expiring.db_claim_due, expiring.iso(expiring.now()), 10)
    assert [r["id"] for r in first] == [sid] and second == []  # two workers never get the same schedule
    client.portal.call(store.run, expiring.db_set_status, sid, "cancelled", None)
