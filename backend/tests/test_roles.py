import psycopg
import pytest

from .conftest import DB, PG, admin


def create(client, name, **kw):
    r = client.post("/api/roles", json={"name": name, **kw})
    assert r.status_code == 201, r.text
    return r.json()


def test_create_user_with_password_can_log_in(client):
    user = create(client, "t_alice", login=True, password="s3cret-Pw!", createdb=True, comment="Alice")
    assert user["kind"] == "user" and user["createdb"] and user["comment"] == "Alice"
    # The password is sent as a pre-computed SCRAM verifier; the server must still accept it.
    with psycopg.connect(**{**PG, "user": "t_alice", "password": "s3cret-Pw!"}, dbname="postgres") as c:
        assert c.execute("SELECT current_user").fetchone()[0] == "t_alice"
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(**{**PG, "user": "t_alice", "password": "wrong"}, dbname="postgres")


def test_non_ascii_password_falls_back_to_server_side_hash(client):
    create(client, "t_unicode", login=True, password="pässwörd-ß")
    with psycopg.connect(**{**PG, "user": "t_unicode", "password": "pässwörd-ß"}, dbname="postgres"):
        pass


def test_list_filter_and_search(client):
    create(client, "t_reader", login=False)
    create(client, "t_bob", login=True)
    users = client.get("/api/roles", params={"kind": "user", "q": "t_"}).json()
    roles = client.get("/api/roles", params={"kind": "role", "q": "t_"}).json()
    assert [u["name"] for u in users["items"]] == ["t_bob"]
    assert [r["name"] for r in roles["items"]] == ["t_reader"]
    assert users["total"] == 1
    # LIKE wildcards in the search term are literal
    assert client.get("/api/roles", params={"q": "t_%"}).json()["total"] == 0
    # predefined roles are hidden unless requested
    names = {r["name"] for r in client.get("/api/roles", params={"limit": 500}).json()["items"]}
    assert "pg_read_all_data" not in names
    names = {r["name"] for r in client.get("/api/roles", params={"limit": 500, "include_system": True}).json()["items"]}
    assert "pg_read_all_data" in names


def names(client, **params):
    r = client.get("/api/roles", params={"q": "t_", "limit": 100, **params})
    assert r.status_code == 200, r.text
    return [i["name"] for i in r.json()["items"]]


def test_sorting(client):
    create(client, "t_grp_a")
    create(client, "t_grp_b")
    create(client, "t_u1", login=True, member_of=["t_grp_a", "t_grp_b"], valid_until="2031-01-01T00:00:00Z")
    create(client, "t_u2", login=True, member_of=["t_grp_a"], valid_until="2030-01-01T00:00:00Z", createdb=True)
    create(client, "t_u3", login=True, superuser=True)  # never expires

    assert names(client) == ["t_grp_a", "t_grp_b", "t_u1", "t_u2", "t_u3"]
    assert names(client, order="desc") == ["t_u3", "t_u2", "t_u1", "t_grp_b", "t_grp_a"]
    # by number of roles the account belongs to; ties broken by name
    assert names(client, kind="user", sort="member_of", order="desc") == ["t_u1", "t_u2", "t_u3"]
    assert names(client, kind="role", sort="members", order="desc") == ["t_grp_a", "t_grp_b"]
    # soonest expiry first, NULL ("never") always last — in both directions
    assert names(client, kind="user", sort="expires") == ["t_u2", "t_u1", "t_u3"]
    assert names(client, kind="user", sort="expires", order="desc") == ["t_u1", "t_u2", "t_u3"]
    assert names(client, kind="user", sort="privilege", order="desc")[0] == "t_u3"
    # pagination stays consistent with the chosen order
    page = client.get("/api/roles", params={"q": "t_", "sort": "name", "order": "desc", "limit": 2, "offset": 2}).json()
    assert [i["name"] for i in page["items"]] == ["t_u1", "t_grp_b"] and page["total"] == 5
    assert client.get("/api/roles", params={"sort": "rolpassword"}).status_code == 422


def test_attribute_filters(client):
    create(client, "t_super", login=True, superuser=True)
    create(client, "t_plain", login=True)
    create(client, "t_exp", login=True, valid_until="2000-01-01T00:00:00Z")
    create(client, "t_member", login=True, member_of=["t_plain"])
    assert names(client, attr="superuser") == ["t_super"]
    assert names(client, attr="expired") == ["t_exp"]
    assert "t_member" not in names(client, attr="no_memberships")
    assert "t_plain" in names(client, attr="no_memberships")
    assert client.get("/api/roles", params={"attr": "bogus"}).status_code == 422


def test_duplicate_and_reserved_names(client):
    create(client, "t_dup")
    assert client.post("/api/roles", json={"name": "t_dup"}).status_code == 409
    assert client.post("/api/roles", json={"name": "pg_custom"}).status_code == 422
    assert client.post("/api/roles", json={"name": "  "}).status_code == 422


def test_odd_names_are_quoted_safely(client):
    name = 't_x"; DROP TABLE app.orders; --'
    create(client, name)
    assert client.get(f"/api/roles/{name}").status_code == 200
    with admin(DB) as c:
        assert c.execute("SELECT to_regclass('app.orders')").fetchone()[0] is not None
    create(client, "t_a/b")
    assert client.get("/api/roles/t_a%2Fb").json()["name"] == "t_a/b"


def test_update_attributes_comment_rename_and_expiry(client):
    create(client, "t_carol", login=True, valid_until="2030-01-01T00:00:00Z")
    r = client.patch(
        "/api/roles/t_carol",
        json={"createrole": True, "connection_limit": 5, "comment": "hi", "rename_to": "t_carol2", "valid_until": None},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "t_carol2" and body["createrole"] and body["connection_limit"] == 5
    assert body["comment"] == "hi" and body["valid_until"] is None
    assert client.get("/api/roles/t_carol").status_code == 404
    # fields not in the payload are untouched
    assert body["login"] is True


def test_membership_both_directions(client):
    create(client, "t_grp1")
    create(client, "t_grp2")
    create(client, "t_user", login=True, member_of=["t_grp1"])
    detail = client.get("/api/roles/t_user").json()
    assert [m["role"] for m in detail["memberships"]] == ["t_grp1"]

    detail = client.put("/api/roles/t_user/member-of", json={"roles": ["t_grp2"]}).json()
    assert [m["role"] for m in detail["memberships"]] == ["t_grp2"]
    assert client.get("/api/roles/t_grp1").json()["member_count"] == 0

    detail = client.put("/api/roles/t_grp1/members", json={"roles": ["t_user", "t_grp2"]}).json()
    assert sorted(m["role"] for m in detail["members"]) == ["t_grp2", "t_user"]

    # circular membership is rejected by PostgreSQL
    assert client.put("/api/roles/t_grp1/member-of", json={"roles": ["t_grp2"]}).status_code == 400
    assert client.put("/api/roles/t_grp1/member-of", json={"roles": ["t_grp1"]}).status_code == 400


def test_membership_options(client):
    create(client, "t_opt_g")
    create(client, "t_opt_u", login=True)

    def put(specs, direction="member-of", name="t_opt_u"):
        r = client.put(f"/api/roles/{name}/{direction}", json={"memberships": specs})
        assert r.status_code == 200, r.text
        return {m["role"]: m for m in (r.json()["memberships"] if direction == "member-of" else r.json()["members"])}

    m = put([{"role": "t_opt_g"}])["t_opt_g"]
    assert (m["admin_option"], m["inherit_option"], m["set_option"]) == (False, True, True)  # server defaults

    # each call changes only the options it names
    m = put([{"role": "t_opt_g", "admin_option": True}])["t_opt_g"]
    assert (m["admin_option"], m["inherit_option"], m["set_option"]) == (True, True, True)
    m = put([{"role": "t_opt_g", "inherit_option": False, "set_option": False}])["t_opt_g"]
    assert (m["admin_option"], m["inherit_option"], m["set_option"]) == (True, False, False)
    m = put([{"role": "t_opt_g", "admin_option": False}])["t_opt_g"]
    assert (m["admin_option"], m["inherit_option"], m["set_option"]) == (False, False, False)

    # the effective view honours INHERIT FALSE
    with admin(DB) as c:
        assert not c.execute("SELECT pg_has_role('t_opt_u', 't_opt_g', 'USAGE')").fetchone()[0]
    put([{"role": "t_opt_g", "inherit_option": True}])
    with admin(DB) as c:
        assert c.execute("SELECT pg_has_role('t_opt_u', 't_opt_g', 'USAGE')").fetchone()[0]

    # the audit entry names the option change
    from .conftest import DB as _db  # noqa: F401
    e = client.get("/api/audit", params={"target": "t_opt_u", "action": "role.membership"}).json()["items"][0]
    assert "~t_opt_g (options)" in e["summary"]

    # same thing from the group's side, and the plain role list still works
    m = put([{"role": "t_opt_u", "admin_option": True}], "members", "t_opt_g")["t_opt_u"]
    assert m["admin_option"] is True
    assert client.put("/api/roles/t_opt_u/member-of", json={"roles": []}).status_code == 200
    assert client.get("/api/roles/t_opt_u").json()["memberships"] == []


def test_delete_requires_reassign_when_owning_objects(client):
    create(client, "t_owner", login=True)
    create(client, "t_heir")
    with admin(DB) as c:
        c.execute("CREATE TABLE app.owned_by_t (id int)")
        c.execute("ALTER TABLE app.owned_by_t OWNER TO t_owner")
        c.execute("GRANT SELECT ON app.customers TO t_owner")

    deps = client.get("/api/roles/t_owner/dependencies").json()
    assert deps["owns_objects"] is True
    assert any(d["database"] == DB and d["owned_objects"] >= 1 for d in deps["dependencies"])

    r = client.delete("/api/roles/t_owner")
    assert r.status_code == 409 and "owns objects" in r.json()["detail"]

    assert client.delete("/api/roles/t_owner", params={"reassign_to": "t_heir"}).status_code == 204
    assert client.get("/api/roles/t_owner").status_code == 404
    with admin(DB) as c:
        owner = c.execute("SELECT tableowner FROM pg_tables WHERE tablename = 'owned_by_t'").fetchone()[0]
        assert owner == "t_heir"
        c.execute("DROP TABLE app.owned_by_t")


def test_delete_role_with_only_privileges(client):
    create(client, "t_priv")
    with admin(DB) as c:
        c.execute("GRANT SELECT ON app.customers TO t_priv")
    assert client.delete("/api/roles/t_priv").status_code == 204


def test_cannot_delete_self_or_system_roles(client):
    assert client.delete("/api/roles/postgres").status_code == 400
    assert client.delete("/api/roles/pg_read_all_data").status_code == 400
    assert client.delete("/api/roles/t_missing").status_code == 404
