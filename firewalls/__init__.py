"""Firewalls management package."""

import gettext
from pathlib import Path

__version__ = "0.1.0"

LOCALE_DIR = Path(__file__).resolve().parent / "locale"
try:
    _translation = gettext.translation("firewalls", localedir=LOCALE_DIR, fallback=True)
    _ = _translation.gettext
except Exception:
    _ = lambda s: s

__all__ = ["__version__", "_", "LOCALE_DIR"]
