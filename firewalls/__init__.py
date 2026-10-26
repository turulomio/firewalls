"""Firewalls management package."""

import datetime
import gettext
from pathlib import Path
from zoneinfo import ZoneInfo

__version__ = "0.1.0"
__version_datetime__ = datetime.datetime(2026, 10, 26, 13, 2, tzinfo=ZoneInfo("Europe/Madrid"))
__version_date__ = __version_datetime__.date()

LOCALE_DIR = Path(__file__).resolve().parent / "locale"
try:
    _translation = gettext.translation("firewalls", localedir=LOCALE_DIR, fallback=True)
    _ = _translation.gettext
except Exception:
    _ = lambda s: s

__all__ = [
    "__version__",
    "__version_datetime__",
    "__version_date__",
    "_",
    "LOCALE_DIR",
]
