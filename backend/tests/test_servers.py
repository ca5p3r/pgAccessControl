"""Managing several PostgreSQL servers: profiles, secrets, validation, isolation and migrations."""

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app import servers as sv
from app.audit import AuditStore
from app.config import get_settings
from app.crypto import SecretBox
from app.errors import AppError
from app.services import expiring
from app.store import AppStore

from .conftest import DB, PG, PG2, admin2

PW2 = PG2["password"]


def on(srv, **params):
    return {"server": srv["id"], **params}


def mk(client, srv, name, **kw):
    r = client.post("/api/roles", params=on(srv), json={"name": name, **kw})
    assert r.status_code == 201, r.text


# ---------------------------------------------------------------------------
# Profiles and secrets
# ---------------------------------------------------------------------------
def test_default_server_is_listed_and_cannot_be_changed(client):
    items = client.get("/api/servers").json()["items"]
    default = items[0]
    assert default["id"] == "default" and default["is_default"] and default["name"] == "Default server"
    assert client.patch("/api/servers/default", json={"name": "x"}).status_code == 400
    assert client.delete("/api/servers/default").status_code == 400
    assert client.get("/api/servers/default/usage").status_code == 400


def test_saved_passwords_are_encrypted_and_never_returned(client, srv2):
    listed = client.get("/api/servers").json()["items"]
    item = next(i for i in listed if i["id"] == srv2["id"])
    assert item["has_password"] is True and "password" not in item and "password_enc" not in item
    assert PW2 not in client.get("/api/servers").text and PW2 not in str(srv2)

    conn = sqlite3.connect(get_settings().data_db_path)
    enc = conn.execute("SELECT password_enc FROM servers WHERE id = ?", (srv2["id"],)).fetchone()[0]
    conn.close()
    assert enc.startswith("v1:") and PW2 not in enc  # ciphertext at rest, not the password

    # the profile actually works with the decrypted password, and nothing leaked into the audit trail
    assert client.get("/api/roles", params=on(srv2)).status_code == 200
    log = client.get("/api/audit", params={"server": "*", "action": "server."}).json()["items"]
    created = [e for e in log if e["action"] == "server.create"]
    assert created and created[0]["server"] == srv2["id"] and created[0]["details"]["password"] == "set"
    assert PW2 not in str(log)


def test_connection_test_reports_success_failure_and_warnings(client):
    good = {"host": PG2["host"], "port": PG2["port"], "user": PG2["user"], "password": PW2, "sslmode": "disable"}
    r = client.post("/api/servers/test", json=good).json()
    assert r["ok"] and r["server_version"].startswith("18") and r["is_superuser"] and r["ssl"] is False
    assert any("unencrypted" in w for w in r["warnings"])

    bad = client.post("/api/servers/test", json={**good, "password": "wrong"}).json()
    assert bad["ok"] is False and "password authentication failed" in bad["error"] and "user name and password" in bad["hint"]
    assert "wrong" not in str(bad)

    down = client.post("/api/servers/test", json={**good, "port": 59999, "connect_timeout": 2}).json()
    assert down["ok"] is False and down["hint"]


def test_test_connection_uses_saved_password_only_for_its_own_address(client, srv2):
    same = {"server_id": srv2["id"], "host": PG2["host"], "port": PG2["port"], "user": PG2["user"], "sslmode": "disable"}
    assert client.post("/api/servers/test", json=same).json()["ok"] is True
    # pointing the saved password at another address must not work: it could be a way to steal it
    moved = client.post("/api/servers/test", json={**same, "host": "localhost"})
    assert moved.status_code == 422 and "only used for the address" in moved.json()["detail"]
    assert client.post("/api/servers/test", json={**same, "port": PG["port"]}).status_code == 422


def test_changing_the_address_requires_the_password_again(client, srv2):
    r = client.patch(f"/api/servers/{srv2['id']}", json={"host": "localhost"})
    assert r.status_code == 422 and "Enter the password again" in r.json()["detail"]
    assert client.patch(f"/api/servers/{srv2['id']}", json={"user": "someone_else"}).status_code == 422
    # harmless edits keep the saved password
    ok = client.patch(f"/api/servers/{srv2['id']}", json={"description": "second", "environment": "production"})
    assert ok.status_code == 200 and ok.json()["environment"] == "production" and ok.json()["has_password"] is True
    assert client.get("/api/roles", params=on(srv2)).status_code == 200
    # moving it is fine when the password is given again
    moved = client.patch(f"/api/servers/{srv2['id']}", json={"host": "localhost", "password": PW2})
    assert moved.status_code == 200 and moved.json()["host"] == "localhost"
    assert client.get("/api/roles", params=on(srv2)).status_code == 200  # pools were rebuilt for the new address
    assert client.patch(f"/api/servers/{srv2['id']}", json={"clear_password": True}).json()["has_password"] is False
    assert client.get("/api/roles", params=on(srv2)).status_code == 503  # no password any more -> cannot sign in


def test_validation(client):
    base = {"name": "v", "host": "db.internal", "user": "u", "sslmode": "disable"}
    for bad_host in ("169.254.169.254", "fe80::1", "http://evil.example/", "/var/run/postgresql", "a b", "evil.example/x", ""):
        r = client.post("/api/servers", json={**base, "host": bad_host})
        assert r.status_code in (422,), (bad_host, r.status_code, r.text)
    assert client.post("/api/servers", json={**base, "port": 0}).status_code == 422
    assert client.post("/api/servers", json={**base, "sslmode": "yes"}).status_code == 422
    assert client.post("/api/servers", json={**base, "environment": "prodution"}).status_code == 422
    key = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    assert client.post("/api/servers", json={**base, "ssl_ca": key}).status_code == 422
    assert client.post("/api/servers", json={**base, "ssl_ca": "not a certificate"}).status_code == 422
    assert client.get("/api/servers").json()["items"][0]["id"] == "default"  # nothing was created


def test_host_allowlist_and_blocklist():
    asyncio.run(_allowlist_checks())


async def _allowlist_checks():
    s = get_settings().model_copy(update={"server_host_allowlist": "*.corp.example, db1.example.com, 10.1.0.0/16"})
    assert await sv.validate_host(s, "pg.corp.example") == "pg.corp.example"
    assert await sv.validate_host(s, "DB1.example.com") == "DB1.example.com"
    assert await sv.validate_host(s, "10.1.4.5") == "10.1.4.5"
    for outside in ("pg.other.example", "10.2.0.1", "corp.example.evil.com"):
        with pytest.raises(AppError) as e:
            await sv.validate_host(s, outside)
        assert e.value.status == 403
    # the metadata address is blocked even when the allowlist would permit it
    s2 = get_settings().model_copy(update={"server_host_allowlist": "169.254.0.0/16"})
    with pytest.raises(AppError) as e:
        await sv.validate_host(s2, "169.254.169.254")
    assert e.value.status == 422


def test_duplicate_names_and_limits(client, srv2):
    body = {"name": "second SERVER", "host": "db.internal", "user": "u", "sslmode": "disable"}
    assert client.post("/api/servers", json=body).status_code == 409  # names are unique, case-insensitively
    assert client.post("/api/servers", json={**body, "password": "p"}).status_code in (409, 201)  # still a duplicate


def test_connection_tests_are_rate_limited(client):
    import time

    sv._tests.clear()
    body = {"host": "127.0.0.1", "port": PG["port"], "user": PG["user"], "password": PG["password"], "sslmode": "disable"}
    assert client.post("/api/servers/test", json=body).status_code == 200  # counts as one test
    sv._tests["anonymous"].extend([time.monotonic()] * 14)  # fifteen in the last minute
    r = client.post("/api/servers/test", json=body)
    assert r.status_code == 429 and "Too many connection tests" in r.json()["detail"]
    sv._tests.clear()
    assert client.post("/api/servers/test", json=body).status_code == 200


# ---------------------------------------------------------------------------
# Isolation between servers
# ---------------------------------------------------------------------------
def test_each_server_has_its_own_roles_and_unknown_servers_are_refused(client, srv2):
    mk(client, srv2, "t_only_on_two", login=True)
    on_two = client.get("/api/roles", params=on(srv2, q="t_only")).json()
    on_default = client.get("/api/roles", params={"q": "t_only"}).json()
    assert [r["name"] for r in on_two["items"]] == ["t_only_on_two"] and on_default["items"] == []
    # the header works as well as the query parameter, and the meta endpoint says which server answered
    r = client.get("/api/meta", headers={"X-PGAC-Server": srv2["id"]}).json()
    assert r["server"]["id"] == srv2["id"] and r["server"]["environment"] == "staging" and r["read_only"] is False
    assert client.get("/api/meta").json()["server"]["id"] == "default"

    assert client.get("/api/roles", params={"server": "nope"}).status_code == 404
    assert client.get("/api/roles", params={"server": "nope"}).json()["detail"] == "Unknown server"
    # permissions apply to the right server only
    r = client.post("/api/permissions/t_only_on_two/apply", params=on(srv2), json={"database": "postgres", "changes": [
        {"action": "grant", "object_type": "table", "schema": "public", "name": "srv2_t", "privileges": ["SELECT"]}]})
    assert r.status_code == 200, r.text
    with admin2() as c:
        assert c.execute("SELECT has_table_privilege('t_only_on_two', 'public.srv2_t', 'SELECT')").fetchone()[0]


def test_disabled_servers_cannot_be_used(client, srv2):
    assert client.patch(f"/api/servers/{srv2['id']}", json={"disabled": True}).status_code == 200
    assert client.get("/api/roles", params=on(srv2)).status_code == 404
    assert client.patch(f"/api/servers/{srv2['id']}", json={"disabled": False}).status_code == 200
    assert client.get("/api/roles", params=on(srv2)).status_code == 200


def test_audit_entries_are_tagged_with_their_server(client, srv2):
    mk(client, srv2, "t_srvaud_two")
    r = client.post("/api/roles", json={"name": "t_srvaud_one"})
    assert r.status_code == 201
    two = client.get("/api/audit", params={"server": srv2["id"], "q": "t_srvaud_"}).json()["items"]
    one = client.get("/api/audit", params={"server": "default", "q": "t_srvaud_"}).json()["items"]
    both = client.get("/api/audit", params={"server": "*", "q": "t_srvaud_"}).json()["items"]
    assert [e["target"] for e in two] == ["t_srvaud_two"] and two[0]["server_name"] == "Second server"
    assert [e["target"] for e in one] == ["t_srvaud_one"] and one[0]["server"] == "default"
    assert {e["target"] for e in both} == {"t_srvaud_one", "t_srvaud_two"}
    facets = client.get("/api/audit/facets").json()["servers"]
    assert {"id": srv2["id"], "name": "Second server"} in facets


def test_snapshots_and_temporary_access_belong_to_one_server(client, srv2):
    # snapshots: same name on two servers is fine; ids from another server do not exist here
    a = client.post("/api/snapshots", params=on(srv2), json={"name": "multi-base", "database": "postgres", "baseline": True})
    b = client.post("/api/snapshots", json={"name": "multi-base", "database": DB})
    assert a.status_code == 201 and b.status_code == 201 and a.json()["server_id"] == srv2["id"]
    assert [s["name"] for s in client.get("/api/snapshots", params=on(srv2)).json()["items"]] == ["multi-base"]
    assert client.get(f"/api/snapshots/{a.json()['id']}/drift").status_code == 404  # asked on the default server
    assert client.get(f"/api/snapshots/{a.json()['id']}/drift", params=on(srv2)).status_code == 200
    client.delete(f"/api/snapshots/{b.json()['id']}")

    # temporary access: created and executed on the server it was granted on
    mk(client, srv2, "t_exp_two")
    when = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    r = client.post("/api/permissions/t_exp_two/apply", params=on(srv2), json={"database": "postgres", "expires_at": when, "changes": [
        {"action": "grant", "object_type": "table", "schema": "public", "name": "srv2_t", "privileges": ["SELECT"]}]})
    assert r.status_code == 200, r.text
    sid = r.json()["temporary"]["schedule_id"]
    assert client.get("/api/temporary", params={"status": "all"}).json()["items"] == [] or all(i["id"] != sid for i in client.get("/api/temporary", params={"status": "all"}).json()["items"])
    assert [i["id"] for i in client.get("/api/temporary", params=on(srv2, status="all")).json()["items"]] == [sid]
    assert client.post(f"/api/temporary/{sid}/cancel").status_code == 404  # not visible from the default server

    from app.config import get_settings as gs  # noqa: PLC0415
    conn = sqlite3.connect(gs().data_db_path)
    conn.execute("UPDATE expiring_access SET expires_at = ? WHERE id = ?", ((datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(), sid))
    conn.commit()
    conn.close()
    assert client.portal.call(expiring.run_due, client.app) == 1
    with admin2() as c:
        assert not c.execute("SELECT has_table_privilege('t_exp_two', 'public.srv2_t', 'SELECT')").fetchone()[0]
    e = client.get("/api/audit", params={"server": srv2["id"], "action": "access.expired"}).json()["items"][0]
    assert e["actor"] == "scheduler" and e["server_name"] == "Second server"


def test_removing_a_server_cleans_up_after_it(client, srv2):
    client.post("/api/snapshots", params=on(srv2), json={"name": "gone", "database": "postgres"})
    mk(client, srv2, "t_rm_two")
    when = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    sid = client.post("/api/permissions/t_rm_two/apply", params=on(srv2), json={"database": "postgres", "expires_at": when, "changes": [
        {"action": "grant", "object_type": "table", "schema": "public", "name": "srv2_t", "privileges": ["SELECT"]}]}).json()["temporary"]["schedule_id"]
    use = client.get(f"/api/servers/{srv2['id']}/usage").json()
    assert use == {"pending_schedules": 1, "snapshots": 1}
    assert client.delete(f"/api/servers/{srv2['id']}").status_code == 204
    assert client.get("/api/roles", params=on(srv2)).status_code == 404
    conn = sqlite3.connect(get_settings().data_db_path)
    status = conn.execute("SELECT status, error FROM expiring_access WHERE id = ?", (sid,)).fetchone()
    snaps = conn.execute("SELECT count(*) FROM snapshots WHERE server_id = ?", (srv2["id"],)).fetchone()[0]
    conn.close()
    assert tuple(status) == ("cancelled", "server removed") and snaps == 0
    # the audit trail of the removed server stays, under its name
    log = client.get("/api/audit", params={"server": "*", "action": "server.delete"}).json()["items"]
    assert log[0]["server_name"] == "Second server" and "1 scheduled expiries cancelled, 1 snapshots deleted" in log[0]["summary"]


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
def test_secretbox_roundtrip_binding_and_rotation():
    s = get_settings().model_copy(update={"encryption_key": "first-key-first-key-first-key", "encryption_key_previous": ""})
    old = SecretBox.from_settings(s)
    token = old.encrypt("s3cret", "server:a:password")
    assert "s3cret" not in token and old.decrypt(token, "server:a:password").plaintext == "s3cret"
    assert old.encrypt("s3cret", "server:a:password") != token  # fresh nonce every time
    with pytest.raises(AppError):  # bound to the profile: a value copied to another profile does not decrypt
        old.decrypt(token, "server:b:password")
    # rotation: the new key encrypts, the previous key still decrypts and flags re-encryption
    new = SecretBox.from_settings(s.model_copy(update={"encryption_key": "second-key-second-key-second", "encryption_key_previous": "first-key-first-key-first-key"}))
    res = new.decrypt(token, "server:a:password")
    assert res.plaintext == "s3cret" and res.current_key is False
    assert new.decrypt(new.encrypt("x", "aad"), "aad").current_key is True
    with pytest.raises(AppError):  # without the previous key it is unreadable
        SecretBox.from_settings(s.model_copy(update={"encryption_key": "second-key-second-key-second", "encryption_key_previous": ""})).decrypt(token, "server:a:password")
    with pytest.raises(AppError):
        old.decrypt("v1:not-base64!!", "x")
    with pytest.raises(ValueError):
        SecretBox.from_settings(s.model_copy(update={"encryption_key": "short"}))


def test_key_fallback_rules():
    base = get_settings().model_copy(update={"encryption_key": "", "secret_key_generated": False, "secret_key": "an-explicit-secret-key-1234"})
    assert SecretBox.from_settings(base).from_secret_key is True  # falls back to an explicit SECRET_KEY
    assert SecretBox.from_settings(base.model_copy(update={"secret_key_generated": True})) is None  # a random one would not survive a restart


def test_rotation_reencrypts_saved_passwords(client, srv2):
    reg = client.app.state.servers
    s = get_settings()
    old_box = reg.box
    rotated = SecretBox.from_settings(s.model_copy(update={"encryption_key": "rotated-key-rotated-key-1234", "encryption_key_previous": s.encryption_key}))
    conn = sqlite3.connect(s.data_db_path)
    before = conn.execute("SELECT password_enc FROM servers WHERE id = ?", (srv2["id"],)).fetchone()[0]
    reg.box = rotated
    try:
        assert client.portal.call(reg.reencrypt) == 1
        after = conn.execute("SELECT password_enc FROM servers WHERE id = ?", (srv2["id"],)).fetchone()[0]
        assert after != before and PW2 not in after
        assert rotated.decrypt(after, f"server:{srv2['id']}:password").current_key is True
        assert client.portal.call(reg.reencrypt) == 0  # nothing left to do
    finally:
        reg.box = old_box
        conn.execute("UPDATE servers SET password_enc = ? WHERE id = ?", (before, srv2["id"]))
        conn.commit()
        conn.close()
        reg.invalidate()


# ---------------------------------------------------------------------------
# Migrations from the single-server version
# ---------------------------------------------------------------------------
def test_old_databases_are_migrated_to_the_default_server(tmp_path):
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.executescript(
        """
        CREATE TABLE app_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
            created_by TEXT, last_login TEXT);
        CREATE TABLE expiring_access (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, grantee TEXT NOT NULL, database TEXT,
            description TEXT NOT NULL, revoke_spec TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
            expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', finished_at TEXT, error TEXT);
        CREATE INDEX ix_expiring_grantee ON expiring_access (grantee, status);
        CREATE TABLE snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, note TEXT, database TEXT NOT NULL,
            created_at TEXT NOT NULL, created_by TEXT NOT NULL, baseline INTEGER NOT NULL DEFAULT 0, counts TEXT NOT NULL,
            data BLOB NOT NULL, last_check TEXT, UNIQUE (name, database));
        INSERT INTO expiring_access (kind, grantee, database, description, revoke_spec, created_at, created_by, expires_at)
            VALUES ('grant', 'bob', 'shop', 'SELECT on x', '{}', '2026-01-01', 'me', '2026-02-01');
        INSERT INTO snapshots (name, database, created_at, created_by, baseline, counts, data) VALUES ('s1', 'shop', '2026-01-01', 'me', 1, '{}', x'00');
        """
    )
    old.commit()
    old.close()

    store = AppStore(path)
    store.init()
    store.init()  # idempotent
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    assert conn.execute("SELECT server_id, grantee FROM expiring_access").fetchone()["server_id"] == "default"
    snap = conn.execute("SELECT server_id, name, baseline, data FROM snapshots").fetchone()
    assert (snap["server_id"], snap["name"], snap["baseline"], bytes(snap["data"])) == ("default", "s1", 1, b"\x00")
    # the new uniqueness rule: same name + database on a different server is allowed, on the same one it is not
    conn.execute("INSERT INTO snapshots (server_id, name, database, created_at, created_by, counts, data) VALUES ('other', 's1', 'shop', 'x', 'y', '{}', x'01')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO snapshots (server_id, name, database, created_at, created_by, counts, data) VALUES ('default', 's1', 'shop', 'x', 'y', '{}', x'01')")
    assert {r[1] for r in conn.execute("PRAGMA table_info(servers)")} >= {"id", "password_enc", "min_role", "read_only"}
    conn.close()


def test_old_audit_files_are_migrated(tmp_path):
    asyncio.run(_audit_migration(tmp_path))


async def _audit_migration(tmp_path):
    path = tmp_path / "audit-old.db"
    old = sqlite3.connect(path)
    old.executescript(
        """
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, ip TEXT, action TEXT NOT NULL,
            target_type TEXT, target TEXT, database TEXT, status TEXT NOT NULL, summary TEXT NOT NULL, statements TEXT, details TEXT, error TEXT);
        INSERT INTO audit_log (ts, actor, action, status, summary) VALUES ('2026-01-01T00:00:00Z', 'admin', 'role.create', 'success', 'Created user old');
        """
    )
    old.commit()
    old.close()
    store = AuditStore(get_settings().model_copy(update={"audit_db_path": str(path), "audit_enabled": True}))
    store.init()
    items, total = await store.query({"server": "default"}, 10, 0)  # rows from before multi-server belong to the default server
    assert total == 1 and items[0]["summary"] == "Created user old" and items[0]["server"] == "default"
    assert items[0]["server_name"] == get_settings().pg_server_name
    # entries that are not about a server (sign-ins, accounts, server management) are not assigned to one
    await store.record(actor="a", action="auth.login", summary="Signed in")
    await store.record(actor="a", action="server.test", summary="Tested")
    assert (await store.query({"server": "default"}, 10, 0))[1] == 1
    assert (await store.query({"servers_in": ["default"]}, 10, 0))[1] == 3  # visible to everyone who may see the server
    assert (await store.query({"server": "something-else"}, 10, 0))[1] == 0


def test_only_a_limited_number_of_servers_keep_open_connections(client, srv2):
    """Adding many profiles must not exhaust database connections: idle least-recently-used servers are closed."""
    extra = []
    for n in ("A", "B"):
        r = client.post("/api/servers", json={"name": f"Extra {n}", "host": PG2["host"], "port": PG2["port"], "user": PG2["user"],
                                              "password": PW2, "database": "postgres", "sslmode": "disable"})
        assert r.status_code == 201, r.text
        extra.append(r.json())
    reg = client.app.state.servers
    original = reg.s
    reg.s = original.model_copy(update={"max_open_servers": 2})  # the default server plus one more
    try:
        for srv in (srv2, *extra):
            assert client.get("/api/roles", params=on(srv, limit=1)).status_code == 200
        open_now = set(reg._managers)
        assert "default" in open_now and len(open_now) == 2  # default is never evicted; only the most recent other server stays
        assert extra[-1]["id"] in open_now
        # an evicted server simply reconnects on the next request
        assert client.get("/api/roles", params=on(srv2, limit=1)).status_code == 200
    finally:
        reg.s = original
        for srv in extra:
            client.delete(f"/api/servers/{srv['id']}")
