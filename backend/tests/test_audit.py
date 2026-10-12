import csv
import io

from .conftest import DB


def mk(client, name, **kw):
    r = client.post("/api/roles", json={"name": name, **kw})
    assert r.status_code == 201, r.text


def entries(client, **params):
    r = client.get("/api/audit", params=params)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_create_is_recorded_with_redacted_sql(client):
    mk(client, "t_aud1", login=True, password="Sup3r-secret-pw", comment="audited")
    [e] = entries(client, target="t_aud1")
    assert e["action"] == "role.create" and e["status"] == "success" and e["actor"] == "anonymous"
    assert e["summary"] == "Created user t_aud1"
    sql = "\n".join(e["statements"])
    assert 'CREATE ROLE "t_aud1"' in sql and "PASSWORD '********'" in sql
    assert "Sup3r-secret-pw" not in sql and "SCRAM-SHA-256" not in sql  # neither plaintext nor verifier
    assert "COMMENT ON ROLE" in sql
    assert "Sup3r-secret-pw" not in str(e["details"])


def test_update_records_before_and_after(client):
    mk(client, "t_aud2", login=True)
    client.patch("/api/roles/t_aud2", json={"createdb": True, "connection_limit": 7, "password": "another-Secret-1"})
    e = entries(client, target="t_aud2", action="role.update")[0]
    assert e["details"]["changes"]["createdb"] == [False, True]
    assert e["details"]["changes"]["connection_limit"] == [-1, 7]
    assert "createdb: no → yes" in e["summary"] and "password changed" in e["summary"]
    assert "another-Secret-1" not in str(e)
    client.patch("/api/roles/t_aud2", json={"rename_to": "t_aud2b"})
    e = entries(client, target="t_aud2", action="role.update")[0]
    assert e["details"]["changes"]["name"] == ["t_aud2", "t_aud2b"]


def test_membership_and_delete_are_recorded(client):
    mk(client, "t_aud_g")
    mk(client, "t_aud3", login=True)
    client.put("/api/roles/t_aud3/member-of", json={"roles": ["t_aud_g"]})
    e = entries(client, target="t_aud3", action="role.membership")[0]
    assert e["summary"] == "Changed roles of t_aud3: +t_aud_g" and e["details"]["added"] == ["t_aud_g"]
    assert 'GRANT "t_aud_g" TO "t_aud3";' in e["statements"]

    client.delete("/api/roles/t_aud3")
    e = entries(client, target="t_aud3", action="role.delete")[0]
    assert e["summary"] == "Deleted user t_aud3" and e["details"]["before"]["member_of"] == ["t_aud_g"]
    assert any(s.startswith("DROP ROLE") for s in e["statements"])


def test_permission_apply_recorded_dry_run_not_and_failures_kept(client):
    mk(client, "t_aud4")
    change = {"action": "grant", "object_type": "table", "schema": "app", "name": "orders", "privileges": ["SELECT"]}
    body = {"database": DB, "changes": [change]}
    client.post("/api/permissions/t_aud4/apply", json={**body, "dry_run": True})
    assert entries(client, target="t_aud4", action="permission.") == []  # previews are not audited

    assert client.post("/api/permissions/t_aud4/apply", json=body).status_code == 200
    [e] = entries(client, target="t_aud4", action="permission.")
    assert e["database"] == DB and e["summary"] == f"1 grant for t_aud4 in {DB}"
    assert e["statements"] == ['GRANT SELECT ON TABLE "app"."orders" TO "t_aud4";']

    bad = {**body, "changes": [{**change, "name": "missing_table"}]}
    assert client.post("/api/permissions/t_aud4/apply", json=bad).status_code == 404
    failed = entries(client, target="t_aud4", status="failed")[0]
    assert failed["summary"].startswith("Failed:") and "missing_table" in failed["error"]
    assert "missing_table" in failed["statements"][0]  # the attempted SQL is kept


def test_failed_create_is_recorded(client):
    mk(client, "t_aud5")
    assert client.post("/api/roles", json={"name": "t_aud5"}).status_code == 409
    e = entries(client, target="t_aud5", status="failed")[0]
    assert e["action"] == "role.create" and "already exists" in e["error"]


def test_filters_pagination_and_search(client):
    mk(client, "t_aud6a")
    mk(client, "t_aud6b")
    client.delete("/api/roles/t_aud6a")
    everything = client.get("/api/audit", params={"q": "t_aud6"}).json()
    assert everything["total"] == 3
    assert len(client.get("/api/audit", params={"q": "t_aud6", "limit": 2}).json()["items"]) == 2
    assert client.get("/api/audit", params={"q": "t_aud6", "limit": 2, "offset": 2}).json()["total"] == 3
    assert client.get("/api/audit", params={"q": "t_aud6", "action": "role.delete"}).json()["total"] == 1
    assert client.get("/api/audit", params={"q": "t_aud6", "actor": "nobody"}).json()["total"] == 0
    assert client.get("/api/audit", params={"q": "t_aud6", "date_from": "2999-01-01"}).json()["total"] == 0
    assert client.get("/api/audit", params={"q": "t_aud6", "date_to": "2999-01-01"}).json()["total"] == 3
    assert client.get("/api/audit", params={"q": "%"}).json()["total"] == 0  # wildcard is literal
    assert client.get("/api/audit", params={"date_from": "yesterday"}).status_code == 422
    newest_first = [e["ts"] for e in everything["items"]]
    assert newest_first == sorted(newest_first, reverse=True)
    assert "anonymous" in client.get("/api/audit/facets").json()["actors"]


def test_csv_export_neutralises_formulas(client):
    mk(client, "=HYPERLINK(evil)")
    r = client.get("/api/audit/export", params={"q": "HYPERLINK", "format": "csv"})
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:4] == ["time_utc", "actor", "ip", "action"]
    assert rows[1][4] == "'=HYPERLINK(evil)"  # formula prefix neutralised
    j = client.get("/api/audit/export", params={"q": "HYPERLINK", "format": "json"}).json()
    assert j["total"] == 1 and j["entries"][0]["target"] == "=HYPERLINK(evil)"  # raw in JSON
    client.delete("/api/roles/=HYPERLINK(evil)")
