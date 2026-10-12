import pytest
from fastapi.testclient import TestClient

from vigilien import web


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(web, "limiter", web.RateLimiter(3, 60))
    return TestClient(web.app)


def test_page_et_en_tetes_de_securite(client):
    r = client.get("/")
    assert r.status_code == 200 and "Ce lien est-il" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/static/app.js").status_code == 200


def test_analyse_hors_ligne(client):
    r = client.post("/api/analyse", json={"url": "http://mtn.bj.verification-compte.xyz/momo/login", "hors_ligne": True})
    assert r.status_code == 200
    assert r.json()["verdict"] == "élevé"
    assert r.headers["cache-control"] == "no-store"


def test_lien_illisible_et_trop_long(client):
    assert client.post("/api/analyse", json={"url": "http://", "hors_ligne": True}).status_code == 422
    assert client.post("/api/analyse", json={"url": "a" * 3000, "hors_ligne": True}).status_code == 422


def test_limite_par_visiteur(client):
    body = {"url": "https://exemple.com", "hors_ligne": True}
    headers = {"X-Forwarded-For": "203.0.113.9"}
    codes = [client.post("/api/analyse", json=body, headers=headers).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    # un autre visiteur n'est pas bloqué
    assert client.post("/api/analyse", json=body, headers={"X-Forwarded-For": "198.51.100.4"}).status_code == 200


def test_fenetre_glissante():
    limiter = web.RateLimiter(2, 60)
    assert limiter.allow("a", 0) and limiter.allow("a", 1)
    assert not limiter.allow("a", 2)
    assert limiter.allow("a", 61.5)
