"""Interface web : une page pour coller un lien, et l'API qui l'analyse.

Lancer en local : uvicorn vigilien.web:app --reload
"""

import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..analyse import analyse

STATIC = Path(__file__).parent / "static"

# Un service public qui visite des liens pour ses visiteurs doit rester sobre :
# délais courts, peu de redirections, et un nombre d'analyses limité par visiteur.
TIMEOUT = 3.0
MAX_REDIRECTS = 5
RATE_LIMIT = 10  # analyses
RATE_WINDOW = 60.0  # secondes

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

app = FastAPI(title="vigilien", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class RateLimiter:
    """Fenêtre glissante en mémoire. Sur un hébergement à plusieurs instances, chaque
    instance compte de son côté : c'est un garde-fou, pas une protection absolue."""

    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            hits = self.hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


limiter = RateLimiter(RATE_LIMIT, RATE_WINDOW)


class Demande(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    hors_ligne: bool = False


def client_ip(request: Request) -> str:
    # Derrière l'hébergeur, l'adresse réelle du visiteur est dans X-Forwarded-For.
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (request.client.host if request.client else "inconnu")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", include_in_schema=False)
def page():
    return FileResponse(STATIC / "index.html")


@app.post("/api/analyse")
def api_analyse(demande: Demande, request: Request):
    if not limiter.allow(client_ip(request)):
        return JSONResponse(
            {"erreur": f"Trop d'analyses : {RATE_LIMIT} par minute au plus. Réessayez dans un instant."},
            status_code=429,
        )
    try:
        report = analyse(demande.url, offline=demande.hors_ligne, timeout=TIMEOUT, max_redirects=MAX_REDIRECTS)
    except ValueError as e:
        return JSONResponse({"erreur": str(e)}, status_code=422)
    return report.to_dict()
