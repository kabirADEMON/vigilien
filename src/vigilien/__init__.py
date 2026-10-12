"""vigilien : évalue le risque d'hameçonnage d'un lien."""

from .analyse import analyse
from .signals import Report, Signal

__all__ = ["analyse", "Report", "Signal"]
__version__ = "0.1.0"
