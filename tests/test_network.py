"""Tests sans réseau : les connexions sont remplacées par de fausses réponses."""

import ssl
from datetime import datetime, timedelta, timezone

import pytest
import requests

from vigilien import network
from vigilien.analyse import analyse
from vigilien.signals import verdict_for

NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731


class FakeResponse:
    def __init__(self, status=200, headers=None, payload=None):
        self.status_code = status
        self.headers = headers or {}
        self._payload = payload

    def json(self):
        return self._payload

    def close(self):
        pass


class FakeSession:
    """Répond selon une table url -> réponse ; garde la liste des adresses demandées."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        for prefix, resp in self.routes.items():
            if url.startswith(prefix):
                return resp
        raise requests.ConnectionError(url)


def rdap(created: datetime) -> FakeResponse:
    return FakeResponse(payload={"events": [{"eventAction": "registration", "eventDate": created.isoformat()}]})


def test_age_du_domaine():
    assert network.age_signals(NOW - timedelta(days=5), NOW)[0].code == "domaine_tres_recent"
    assert network.age_signals(NOW - timedelta(days=90), NOW)[0].code == "domaine_recent"
    assert network.age_signals(NOW - timedelta(days=4000), NOW)[0].points == 0
    assert network.age_signals(None, NOW)[0].code == "age_inconnu"


def test_lecture_rdap():
    payload = {"events": [{"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
                          {"eventAction": "registration", "eventDate": "2007-10-09T18:20:50Z"}]}
    assert network.parse_registration_date(payload).date().isoformat() == "2007-10-09"


def test_redirections_vers_un_autre_site():
    session = FakeSession({
        "https://bit.ly/x": FakeResponse(301, {"Location": "http://relais.example/a"}),
        "http://relais.example/a": FakeResponse(302, {"Location": "/b"}),
        "http://relais.example/b": FakeResponse(302, {"Location": "http://faux-compte.xyz/login"}),
        "http://faux-compte.xyz/login": FakeResponse(200),
    })
    chain = network.follow_redirects("https://bit.ly/x", session, 1, PUBLIC)
    assert chain[-1] == "http://faux-compte.xyz/login"
    found = {s.code for s in network.redirect_signals(chain)}
    assert found == {"redirections_multiples", "change_de_site", "perte_https"}


def test_refuse_les_adresses_internes():
    assert not network.is_public_host("127.0.0.1")
    assert not network.is_public_host("intranet.local", lambda h: ["10.0.0.5"])
    assert network.is_public_host("exemple.com", PUBLIC)
    with pytest.raises(PermissionError):
        network.follow_redirects("http://intranet.local/", FakeSession({}), 1, lambda h: ["192.168.0.1"])


def test_redirection_vers_le_reseau_interne_bloquee():
    session = FakeSession({"https://piege.example/": FakeResponse(302, {"Location": "http://routeur.local/"})})
    resolve = lambda host: ["192.168.1.1"] if host == "routeur.local" else ["93.184.216.34"]  # noqa: E731
    with pytest.raises(PermissionError):
        network.follow_redirects("https://piege.example/", session, 1, resolve)
    assert session.calls == ["https://piege.example/"]  # l'adresse interne n'a jamais été contactée


def test_certificat_neuf_et_emetteur():
    cert = {"issuer": ((("organizationName", "Let's Encrypt"),),),
            "notBefore": (NOW - timedelta(days=2)).strftime("%b %d %H:%M:%S %Y GMT")}
    signals, issuer = network.certificate_signals(cert, NOW)
    assert issuer == "Let's Encrypt"
    assert [s.code for s in signals] == ["certificat_neuf"]


def test_analyse_complete_sans_reseau(monkeypatch):
    monkeypatch.setattr(network, "fetch_certificate", lambda *a: (_ for _ in ()).throw(
        ssl.SSLCertVerificationError("certificate has expired")))
    session = FakeSession({
        "https://mtn-bonus.xyz/momo": FakeResponse(200),
        "https://rdap.org/domain/mtn-bonus.xyz": rdap(NOW - timedelta(days=3)),
    })
    report = analyse("https://mtn-bonus.xyz/momo", session=session, resolve=PUBLIC, now=NOW)
    found = {s.code for s in report.signals}
    assert {"usurpation_marque", "domaine_tres_recent", "certificat_invalide", "extension_suspecte"} <= found
    assert report.score == 100 and report.verdict == "élevé"
    assert report.domain_created == (NOW - timedelta(days=3)).date().isoformat()


def test_mode_hors_ligne_ne_se_connecte_pas():
    session = FakeSession({})
    report = analyse("https://exemple.com", offline=True, session=session)
    assert session.calls == []
    assert report.score == 0


def test_seuils_du_verdict():
    assert [verdict_for(s) for s in (0, 24, 25, 59, 60, 100)] == ["faible", "faible", "modéré", "modéré", "élevé", "élevé"]


def test_chaine_incomplete_moins_grave_qu_un_certificat_invalide():
    incomplete = ssl.SSLCertVerificationError("unable to get local issuer certificate")
    incomplete.verify_code = 20
    expired = ssl.SSLCertVerificationError("certificate has expired")
    expired.verify_code = 10
    assert network.certificate_error_signal(incomplete).code == "chaine_incomplete"
    assert network.certificate_error_signal(incomplete).points == 5
    assert network.certificate_error_signal(expired).code == "certificat_invalide"
