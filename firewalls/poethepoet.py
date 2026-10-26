"""Poe the Poet task scripts for firewalls."""

from pathlib import Path
import subprocess


def translate() -> None:
    """Extract translatable strings, update PO catalogs, and compile MO binary files."""
    locale_dir = Path("firewalls/locale")
    locale_dir.mkdir(parents=True, exist_ok=True)
    pot_file = locale_dir / "firewalls.pot"

    # Locate all Python files in the package (excluding build/task scripts)
    python_files = sorted(
        str(p) for p in Path("firewalls").glob("*.py") if p.name != "poethepoet.py"
    )

    subprocess.run(
        [
            "xgettext",
            "-L",
            "Python",
            "--no-wrap",
            "--no-location",
            "--from-code=UTF-8",
            "-o",
            str(pot_file),
            *python_files,
        ],
        check=True,
    )

    for lang in ["es", "fr", "ro", "ru", "zh", "hi"]:
        lc_dir = locale_dir / lang / "LC_MESSAGES"
        lc_dir.mkdir(parents=True, exist_ok=True)
        po_file = locale_dir / f"{lang}.po"

        if not po_file.exists():
            subprocess.run(
                [
                    "msginit",
                    "--no-translator",
                    "-i",
                    str(pot_file),
                    "-o",
                    str(po_file),
                    "-l",
                    lang,
                ],
                check=True,
            )
        else:
            subprocess.run(
                [
                    "msgmerge",
                    "-N",
                    "--no-wrap",
                    "-U",
                    str(po_file),
                    str(pot_file),
                ],
                check=True,
            )

        mo_file = lc_dir / "firewalls.mo"
        subprocess.run(
            [
                "msgfmt",
                "-cv",
                "-o",
                str(mo_file),
                str(po_file),
            ],
            check=True,
        )
