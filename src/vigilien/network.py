"""Vérifications en ligne : âge du domaine (RDAP), redirections et certificat.

Rien n'est attaqué : on lit les en-têtes des réponses sans télécharger les pages,
sans exécuter de JavaScript et sans envoyer de formulaire.
"""

import ipaddress
import socket
import ssl
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests

from .signals import Signal
from .url_checks import parse

USER_AGENT = "vigilien/0.1 (analyse anti-hameconnage ; https://github.com/kabirADEMON/vigilien)"
MAX_REDIRECTS = 8

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})


def is_public_host(host: str, resolve: Resolver = system_resolver) -> bool:
    """Refuse les adresses internes : un lien piégé ne doit pas nous faire sonder le réseau local."""
    try:
        addresses = [host.strip("[]")] if _looks_like_ip(host) else resolve(host)
    except OSError:
        return False
    if not addresses:
        return False
    return all(ipaddress.ip_address(a).is_global for a in addresses)


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# ---------- Âge du domaine (RDAP, successeur normalisé de WHOIS) ----------

def domain_created(domain: str, session: requests.Session, timeout: float) -> datetime | None:
    resp = session.get(
        f"https://rdap.org/domain/{domain}",
        headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
        timeout=timeout,
    )
    if resp.status_code != 200:
        return None
    return parse_registration_date(resp.json())


def parse_registration_date(rdap: dict) -> datetime | None:
    for event in rdap.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
    return None


def age_signals(created: datetime | None, now: datetime) -> list[Signal]:
    if created is None:
        return [Signal("age_inconnu", "Âge du domaine inconnu (le registre ne le publie pas)", 0)]
    days = (now - created).days
    detail = f"créé le {created.date().isoformat()}, il y a {days} jours"
    if days < 30:
        return [Signal("domaine_tres_recent", "Domaine créé il y a moins d'un mois", 30, detail)]
    if days < 180:
        return [Signal("domaine_recent", "Domaine créé il y a moins de six mois", 15, detail)]
    return [Signal("domaine_ancien", "Domaine ancien", 0, detail)]


# ---------- Redirections ----------

def follow_redirects(url: str, session: requests.Session, timeout: float,
                     resolve: Resolver = system_resolver) -> list[str]:
    """Suit les redirections HTTP une à une et renvoie la chaîne d'adresses visitées."""
    chain = [url]
    current = url
    for _ in range(MAX_REDIRECTS):
        host = urlsplit(current).hostname or ""
        if not is_public_host(host, resolve):
            raise PermissionError(f"adresse interne ou introuvable : {host}")
        resp = session.get(current, allow_redirects=False, stream=True, timeout=timeout,
                           headers={"User-Agent": USER_AGENT})
        resp.close()  # seuls le code et les en-têtes nous intéressent
        location = resp.headers.get("Location")
        if resp.status_code not in (301, 302, 303, 307, 308) or not location:
            return chain
        current = urljoin(current, location)
        chain.append(current)
    return chain


def redirect_signals(chain: list[str]) -> list[Signal]:
    out = []
    hops = len(chain) - 1
    if hops >= 3:
        out.append(Signal("redirections_multiples", "Nombreuses redirections successives", 10, f"{hops} redirections"))
    if hops:
        start, end = parse(chain[0]), parse(chain[-1])
        if start.registered_domain != end.registered_domain:
            out.append(Signal(
                "change_de_site",
                "Le lien mène en réalité vers un autre site",
                15,
                f"{start.registered_domain} → {end.registered_domain}",
            ))
        if any(a.startswith("https://") and b.startswith("http://") for a, b in zip(chain, chain[1:])):
            out.append(Signal("perte_https", "Une redirection abandonne le chiffrement (https → http)", 10))
    return out


# ---------- Certificat ----------

def fetch_certificate(host: str, port: int, timeout: float) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()


def certificate_signals(cert: dict, now: datetime) -> tuple[list[Signal], str | None]:
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    issuer_name = issuer.get("organizationName") or issuer.get("commonName")
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    age = (now - not_before).days
    if age < 7:
        return [Signal("certificat_neuf", "Certificat émis il y a moins d'une semaine", 5,
                       f"émis le {not_before.date().isoformat()}")], issuer_name
    return [], issuer_name


# Code OpenSSL « unable to get local issuer certificate » : le serveur n'envoie pas toute
# la chaîne. Les navigateurs la complètent souvent seuls ; c'est une mauvaise configuration
# fréquente sur des sites légitimes, pas un signe fort d'hameçonnage.
INCOMPLETE_CHAIN = 20


def certificate_error_signal(error: Exception) -> Signal:
    reason = getattr(error, "verify_message", None) or str(error)
    if getattr(error, "verify_code", None) == INCOMPLETE_CHAIN:
        return Signal("chaine_incomplete", "Chaîne de certificats incomplète (souvent une erreur de configuration)", 5, reason)
    return Signal("certificat_invalide", "Certificat invalide : le navigateur afficherait une alerte", 25, reason)
