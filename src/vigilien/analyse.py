"""Point d'entrée : analyse un lien et rassemble les signaux en un rapport."""

import ssl
from datetime import datetime, timezone

import requests

from . import network
from .signals import Report, Signal
from .url_checks import check, parse


def analyse(raw_url: str, *, offline: bool = False, timeout: float = 8.0,
            session: requests.Session | None = None,
            resolve: network.Resolver = network.system_resolver,
            now: datetime | None = None, max_redirects: int = network.MAX_REDIRECTS) -> Report:
    now = now or datetime.now(timezone.utc)
    parsed = parse(raw_url)
    report = Report(url=parsed.url, domain=parsed.registered_domain)
    report.signals.extend(check(parsed))
    if offline:
        return report

    session = session or network.pinned_session(resolve)

    # 1. Où mène vraiment le lien ? Les contrôles suivants portent sur la destination finale.
    target = parsed
    try:
        chain = network.follow_redirects(parsed.url, session, timeout, resolve, max_redirects)
        report.redirects = chain[1:]
        report.final_url = chain[-1]
        report.signals.extend(network.redirect_signals(chain))
        target = parse(chain[-1])
        if target.registered_domain != parsed.registered_domain:
            report.signals.extend(s for s in check(target) if s.code not in _codes(report))
    except (PermissionError, network.BlockedAddress) as e:
        report.signals.append(Signal("non_visite", "Lien non visité", 0, str(e)))
        return report
    except requests.exceptions.SSLError:
        pass  # le contrôle du certificat (étape 3) l'explique mieux
    except requests.RequestException as e:
        report.signals.append(Signal("injoignable", "Site injoignable", 0, type(e).__name__))

    # 2. Âge du domaine de destination.
    if not target.is_ip:
        try:
            created = network.domain_created(target.registered_domain, session, timeout)
            report.domain_created = created.date().isoformat() if created else None
            report.signals.extend(network.age_signals(created, now))
        except (requests.RequestException, ValueError):
            report.signals.extend(network.age_signals(None, now))

    # 3. Certificat, si la destination est en https.
    if target.scheme == "https":
        try:
            cert = network.fetch_certificate(target.host, target.port or 443, timeout, resolve)
            signals, report.certificate_issuer = network.certificate_signals(cert, now)
            report.signals.extend(signals)
        except ssl.SSLCertVerificationError as e:
            report.signals.append(network.certificate_error_signal(e))
        except (OSError, network.BlockedAddress) as e:
            report.signals.append(Signal("certificat_illisible", "Certificat non vérifiable", 0, type(e).__name__))

    return report


def _codes(report: Report) -> set[str]:
    return {s.code for s in report.signals}
