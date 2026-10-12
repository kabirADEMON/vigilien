"""Ligne de commande : vigilien <lien> [<lien> ...] [--json] [--hors-ligne]."""

import argparse
import json
import sys

from .analyse import analyse
from .signals import HIGH, MODERATE, Report

ICONS = {"faible": "🟢", "modéré": "🟠", "élevé": "🔴"}


def format_report(r: Report) -> str:
    lines = [f"{ICONS[r.verdict]} Risque {r.verdict} : {r.score}/100", f"   Lien     : {r.url}"]
    if r.final_url and r.final_url != r.url:
        lines.append(f"   Mène à   : {r.final_url}")
    lines.append(f"   Domaine  : {r.domain}" + (f" (créé le {r.domain_created})" if r.domain_created else ""))
    if r.certificate_issuer:
        lines.append(f"   Certificat émis par : {r.certificate_issuer}")
    risky = sorted((s for s in r.signals if s.points), key=lambda s: -s.points)
    info = [s for s in r.signals if not s.points]
    if risky:
        lines.append("   Signaux :")
        for s in risky:
            lines.append(f"     +{s.points:<3} {s.label}" + (f" ({s.detail})" if s.detail else ""))
    for s in info:
        lines.append(f"     ·    {s.label}" + (f" ({s.detail})" if s.detail else ""))
    if not risky:
        lines.append("   Aucun signal de risque détecté. Restez prudent : un score faible n'est pas une garantie.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vigilien",
        description="Évalue le risque d'hameçonnage d'un lien. Outil défensif : il analyse, il n'attaque rien.",
    )
    parser.add_argument("liens", nargs="+", help="lien(s) à analyser")
    parser.add_argument("--json", action="store_true", help="sortie JSON")
    parser.add_argument("--hors-ligne", action="store_true",
                        help="n'analyse que le texte du lien, sans aucune connexion")
    parser.add_argument("--delai", type=float, default=8.0, help="délai réseau en secondes (défaut : 8)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    reports = []
    for link in args.liens:
        try:
            reports.append(analyse(link, offline=args.hors_ligne, timeout=args.delai))
        except ValueError as e:
            print(f"Erreur : {e}", file=sys.stderr)
            return 3

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2))
    else:
        print("\n\n".join(format_report(r) for r in reports))

    # Code de sortie exploitable dans un script : 0 faible, 1 modéré, 2 élevé.
    worst = max(r.score for r in reports)
    return 2 if worst >= HIGH else 1 if worst >= MODERATE else 0


if __name__ == "__main__":
    sys.exit(main())
