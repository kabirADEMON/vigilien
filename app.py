"""Point d'entrée pour l'hébergement (Vercel) : expose l'application FastAPI."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from vigilien.web import app  # noqa: E402

__all__ = ["app"]
