"""Structure commune : un signal de risque et le calcul du score."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signal:
    code: str  # identifiant stable, utile pour les tests et la sortie JSON
    label: str  # phrase courte, lisible par un non-spécialiste
    points: int  # contribution au score (0 = information seule)
    detail: str = ""


@dataclass
class Report:
    url: str
    signals: list[Signal] = field(default_factory=list)
    final_url: str | None = None
    redirects: list[str] = field(default_factory=list)
    domain: str | None = None
    domain_created: str | None = None
    certificate_issuer: str | None = None

    @property
    def score(self) -> int:
        return min(100, sum(s.points for s in self.signals))

    @property
    def verdict(self) -> str:
        return verdict_for(self.score)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "score": self.score,
            "verdict": self.verdict,
            "domaine": self.domain,
            "domaine_cree_le": self.domain_created,
            "url_finale": self.final_url,
            "redirections": self.redirects,
            "emetteur_certificat": self.certificate_issuer,
            "signaux": [
                {"code": s.code, "points": s.points, "label": s.label, "detail": s.detail}
                for s in self.signals
            ],
        }


# Seuils volontairement prudents : un lien « modéré » mérite déjà une vérification.
MODERATE = 25
HIGH = 60


def verdict_for(score: int) -> str:
    if score >= HIGH:
        return "élevé"
    if score >= MODERATE:
        return "modéré"
    return "faible"
