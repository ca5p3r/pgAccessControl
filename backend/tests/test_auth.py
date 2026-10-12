import pytest
from fastapi.testclient import TestClient

from app.config import get_settings


@pytest.fixture
def secured(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("ADMIN_USERNAME", "root")
    monkeypatch.setenv("ADMIN_PASSWORD", "correct horse")
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    get_settings.cache_clear()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
    monkeypatch.undo()
    get_settings.cache_clear()


def test_api_requires_login(secured):
    assert secured.get("/api/roles").status_code == 401
    assert secured.get("/api/meta").status_code == 401
    assert secured.get("/api/auth/me").json()["authenticated"] is False
    assert secured.get("/api/health").status_code == 200  # health stays public


def test_login_logout_cycle(secured):
    assert secured.post("/api/auth/login", json={"username": "root", "password": "nope"}).status_code == 401
    r = secured.post("/api/auth/login", json={"username": "root", "password": "correct horse"})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert secured.get("/api/roles").status_code == 200
    assert secured.get("/api/auth/me").json()["username"] == "root"
    secured.post("/api/auth/logout")
    assert secured.get("/api/roles").status_code == 401


def test_tampered_cookie_rejected(secured):
    secured.cookies.set("pgac_session", "not-a-jwt")
    assert secured.get("/api/roles").status_code == 401


def test_login_is_throttled(secured):
    for _ in range(5):
        secured.post("/api/auth/login", json={"username": "root", "password": "bad"})
    assert secured.post("/api/auth/login", json={"username": "root", "password": "correct horse"}).status_code == 429
