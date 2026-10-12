import pytest

from vigilien.url_checks import check, parse, skeleton


def codes(url: str) -> set[str]:
    return {s.code for s in check(parse(url))}


def test_site_officiel_sans_signal():
    assert codes("https://www.mtn.bj") == set()
    assert codes("https://www.service-public.gouv.bj/demarches") == set()


def test_usurpation_de_marque_en_sous_domaine():
    found = codes("http://mtn.bj.verification-compte.xyz/momo/login")
    assert {"usurpation_marque", "extension_suspecte", "sans_https", "mots_cles"} <= found


def test_faux_site_public():
    assert "faux_site_officiel" in codes("https://service-public.gouv.bj.paiement-amende.top/payer")


def test_homographe_imite_une_marque():
    # « pаypal » avec un « а » cyrillique
    found = codes("https://xn--pypal-4ve.com")
    assert {"homographe", "usurpation_marque"} <= found
    assert "tirets" not in found  # le préfixe xn-- ne compte pas
    assert skeleton("xn--pypal-4ve.com") == "paypal.com"


def test_adresse_ip_arobase_et_port():
    found = codes("http://user@192.168.1.10:8080/login")
    assert {"adresse_ip", "arobase", "port_inhabituel"} <= found


def test_lien_sans_schema_traite_comme_http():
    p = parse("exemple.com/page")
    assert p.scheme == "http"
    assert p.registered_domain == "exemple.com"


def test_raccourcisseur():
    assert "raccourcisseur" in codes("https://bit.ly/3abcDEF")


def test_mots_cles_plafonnes():
    signal = next(s for s in check(parse("https://a.com/login/verify/password/account/update")) if s.code == "mots_cles")
    assert signal.points == 15


def test_lien_illisible():
    with pytest.raises(ValueError):
        parse("http://")


def test_faux_nom_de_site_avant_arobase():
    signals = {s.code: s for s in check(parse("https://mtn.bj@site-pirate.com/"))}
    assert signals["arobase"].points == 35
    assert "usurpation_marque" in signals  # « mtn » sert d'appât
    assert sum(s.points for s in signals.values()) >= 60
