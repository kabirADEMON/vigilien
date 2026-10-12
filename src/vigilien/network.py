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
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

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


class BlockedAddress(Exception):
    """Connexion refusée : le nom pointe vers une adresse interne.

    Volontairement pas une sous-classe d'OSError, que urllib3 transformerait en simple
    « erreur de connexion » : on veut pouvoir dire pourquoi le lien n'a pas été visité.
    """


def public_addresses(host: str, resolve: Resolver = system_resolver) -> list[str]:
    try:
        addresses = [host.strip("[]")] if _looks_like_ip(host) else resolve(host)
    except OSError as e:
        raise BlockedAddress(f"nom introuvable : {host}") from e
    if not addresses or not all(ipaddress.ip_address(a).is_global for a in addresses):
        raise BlockedAddress(f"adresse interne : {host}")
    return addresses


def connect_public(host: str, port: int, timeout: float | None, resolve: Resolver = system_resolver,
                   source_address=None) -> socket.socket:
    """Ouvre une socket vers une adresse publique déjà vérifiée : IPv4 d'abord, puis les suivantes."""
    addresses = sorted(public_addresses(host, resolve), key=lambda a: ":" in a)
    error: OSError | None = None
    for ip in addresses:
        try:
            return socket.create_connection((ip, port), timeout, source_address=source_address)
        except OSError as e:
            error = e
    raise error


def pinned_session(resolve: Resolver = system_resolver) -> requests.Session:
    """Session HTTP qui vérifie l'adresse au moment même de la connexion.

    Vérifier un nom puis laisser la bibliothèque le résoudre à nouveau laisse une fenêtre :
    entre les deux, le nom peut pointer ailleurs (DNS rebinding). Ici la socket s'ouvre sur
    l'adresse qui vient d'être contrôlée ; le certificat reste vérifié avec le vrai nom.
    """

    class Pinned:
        def _new_conn(self):
            timeout = self.timeout if isinstance(self.timeout, (int, float)) else None
            return connect_public(self._dns_host, self.port, timeout, resolve, self.source_address)

    class PinnedHTTP(Pinned, HTTPConnection):
        pass

    class PinnedHTTPS(Pinned, HTTPSConnection):
        pass

    class HTTPPool(HTTPConnectionPool):
        ConnectionCls = PinnedHTTP

    class HTTPSPool(HTTPSConnectionPool):
        ConnectionCls = PinnedHTTPS

    class Adapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            super().init_poolmanager(*args, **kwargs)
            self.poolmanager.pool_classes_by_scheme = {"http": HTTPPool, "https": HTTPSPool}

    session = requests.Session()
    session.trust_env = False  # pas de proxy implicite qui contournerait le contrôle
    session.mount("http://", Adapter())
    session.mount("https://", Adapter())
    return session


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
                     resolve: Resolver = system_resolver, max_redirects: int = MAX_REDIRECTS) -> list[str]:
    """Suit les redirections HTTP une à une et renvoie la chaîne d'adresses visitées."""
    chain = [url]
    current = url
    for _ in range(max_redirects):
        public_addresses(urlsplit(current).hostname or "", resolve)  # lève BlockedAddress, avec la raison
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

def fetch_certificate(host: str, port: int, timeout: float, resolve: Resolver = system_resolver) -> dict:
    context = ssl.create_default_context()
    with connect_public(host, port, timeout, resolve) as sock:
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
