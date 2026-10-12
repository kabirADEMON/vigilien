"""Analyse hors ligne : tout ce qu'on peut déduire du texte du lien, sans le visiter."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

import tldextract

from .data import BRANDS, GOV_SUFFIX, KEYWORDS, SHORTENERS, SUSPICIOUS_TLDS
from .signals import Signal

# Liste des suffixes embarquée : pas de téléchargement au premier lancement.
_extract = tldextract.TLDExtract(suffix_list_urls=())


@dataclass(frozen=True)
class ParsedUrl:
    url: str
    scheme: str
    host: str
    port: int | None
    path_and_query: str
    subdomain: str
    registered_domain: str  # ex. « mtn.bj » pour « www.mtn.bj »
    suffix: str
    userinfo: str  # ce qui précède « @ » : ignoré par le navigateur, souvent un faux nom de site
    is_ip: bool


def normalize(raw: str) -> str:
    url = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url  # un lien collé sans schéma s'ouvre en http dans la plupart des cas
    return url


def parse(raw: str) -> ParsedUrl:
    url = normalize(raw)
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError(f"Lien illisible : {raw!r}")
    is_ip = _is_ip(host)
    ext = _extract(host)
    registered = host if is_ip else (ext.top_domain_under_public_suffix or host)
    return ParsedUrl(
        url=url,
        scheme=parts.scheme.lower(),
        host=host,
        port=parts.port,
        path_and_query=parts.path + ("?" + parts.query if parts.query else ""),
        subdomain="" if is_ip else ext.subdomain,
        registered_domain=registered,
        suffix="" if is_ip else ext.suffix,
        userinfo=parts.netloc.rpartition("@")[0],
        is_ip=is_ip,
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _decode_idna(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


# Lettres d'autres alphabets qui ressemblent aux lettres latines (« а » cyrillique pour « a »...).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ӏ": "l", "ɡ": "g", "ո": "n", "ս": "u", "ⅼ": "l", "ο": "o", "α": "a",
    "ν": "v", "τ": "t", "κ": "k", "ı": "i",
})


def skeleton(host: str) -> str:
    """Nom tel qu'un œil le lit : « pаypal.com » (avec un « а » cyrillique) devient « paypal.com »."""
    return _decode_idna(host).translate(_CONFUSABLES)


def check(p: ParsedUrl) -> list[Signal]:
    signals: list[Signal] = []
    add = signals.append

    if p.is_ip:
        add(Signal("adresse_ip", "Le lien pointe vers une adresse IP, pas vers un nom de site", 25, p.host))
    if p.scheme == "http":
        add(Signal("sans_https", "Connexion non chiffrée (http)", 10))
    if p.userinfo:
        # « https://mtn.bj@site-pirate.com » : le lecteur voit mtn.bj, le navigateur ouvre site-pirate.com.
        fake_host = "." in p.userinfo
        add(Signal(
            "arobase",
            "Le lien contient « @ » : tout ce qui précède est ignoré par le navigateur",
            35 if fake_host else 20,
            f"« {unquote(p.userinfo)} » est un leurre, le site ouvert est {p.host}" if fake_host else "",
        ))
    if p.port and p.port not in (80, 443):
        add(Signal("port_inhabituel", "Port inhabituel", 10, str(p.port)))

    decoded = _decode_idna(p.host)
    if decoded != p.host or any(ord(c) > 127 for c in decoded):
        add(Signal(
            "homographe",
            "Nom de domaine en caractères internationaux : il peut imiter un site connu",
            20,
            f"{p.host} s'affiche « {decoded} »",
        ))

    tld = p.suffix.rsplit(".", 1)[-1] if p.suffix else ""
    if tld in SUSPICIOUS_TLDS:
        add(Signal("extension_suspecte", "Extension de domaine très utilisée par l'hameçonnage", 10, "." + tld))

    if p.registered_domain in SHORTENERS:
        add(Signal("raccourcisseur", "Lien raccourci : la vraie destination est cachée", 10, p.registered_domain))

    if p.subdomain.count(".") >= 3:
        add(Signal("sous_domaines", "Beaucoup de sous-domaines, souvent pour cacher le vrai domaine", 10, p.subdomain))
    if len(p.host) > 50:
        add(Signal("domaine_long", "Nom de domaine anormalement long", 5, f"{len(p.host)} caractères"))
    if len(p.url) > 120:
        add(Signal("lien_long", "Lien anormalement long", 5, f"{len(p.url)} caractères"))
    name = _decode_idna(p.registered_domain).split(".", 1)[0]
    if name.count("-") >= 2:
        add(Signal("tirets", "Nom de domaine avec plusieurs tirets", 5, p.registered_domain))

    signals.extend(_keywords(p))
    signals.extend(_impersonation(p))
    return signals


def _words(text: str) -> set[str]:
    return set(re.split(r"[^a-z0-9]+", unquote(text).lower())) - {""}


def _keywords(p: ParsedUrl) -> list[Signal]:
    found = sorted(_words(p.host + " " + p.path_and_query) & KEYWORDS)
    if not found:
        return []
    points = min(15, 5 * len(found))
    return [Signal("mots_cles", "Mots typiques des demandes d'identifiants ou de paiement", points, ", ".join(found))]


def _impersonation(p: ParsedUrl) -> list[Signal]:
    if p.is_ip:
        host_words = set()
    else:
        host_words = _words(p.host.replace(".", " ")) | _words(skeleton(p.host).replace(".", " "))
    host_words |= _words(p.userinfo.replace(".", " "))  # la marque affichée en leurre avant « @ »
    out = []
    for brand, official in BRANDS.items():
        if brand in host_words and p.registered_domain not in official:
            out.append(Signal(
                "usurpation_marque",
                f"Le nom « {brand} » apparaît, mais le site n'appartient pas à cette marque",
                25,
                f"domaine réel : {p.registered_domain}",
            ))
    if "gouv" in host_words and not (p.host == GOV_SUFFIX or p.host.endswith("." + GOV_SUFFIX)):
        out.append(Signal(
            "faux_site_officiel",
            f"Se présente comme un site public, mais n'est pas sous .{GOV_SUFFIX}",
            25,
            f"domaine réel : {p.registered_domain}",
        ))
    return out
