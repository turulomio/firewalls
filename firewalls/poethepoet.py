"""Poe the Poet task scripts for firewalls."""

from pathlib import Path
import subprocess

from colorama import Fore, Style, init

from firewalls import __version__, _

init(autoreset=True)


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
                    "--backup=none",
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


def release() -> None:
    """Print the step-by-step checklist for publishing a new release."""
    print(f"\n{Style.BRIGHT}{Fore.CYAN}{_('=== Release checklist for firewalls (Current version: {version}) ===')}{Style.RESET_ALL}".format(version=__version__))

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}1. {_('Update Version & Changelog:')}{Style.RESET_ALL}")
    print(f"   * {_('Change version and date in')} firewalls/__init__.py")
    print(f"   * {_('Change version in')} pyproject.toml")

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}2. {_('Update Translations (i18n):')}{Style.RESET_ALL}")
    print(f"   * {Fore.GREEN}poetry run poe translate{Style.RESET_ALL}")
    print(f"   * {Fore.GREEN}mcedit firewalls/locale/es.po{Style.RESET_ALL}  {Fore.LIGHTBLACK_EX}# {_('and other languages as needed')}{Style.RESET_ALL}")
    print(f"   * {Fore.GREEN}poetry run poe translate{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}3. {_('Git Commit & Tagging:')}{Style.RESET_ALL}")
    print(f"   * {Fore.GREEN}git commit -a -m 'firewalls-{__version__}'{Style.RESET_ALL}")
    print(f"   * {Fore.GREEN}git push{Style.RESET_ALL}")
    print(f"   * {Fore.GREEN}Create a new release in GitHub{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}4. {_('Build & Publish Python Package:')}{Style.RESET_ALL}")
    print(f"   * {Fore.GREEN}poetry build{Style.RESET_ALL}")
    print(f"   * {Fore.GREEN}poetry publish{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}5. {_('Gentoo Portage Package:')}{Style.RESET_ALL}")
    print(f"   * {_('Create a new gentoo ebuild with the new version (firewalls-{version}.ebuild)').format(version=__version__)}")
    print(f"   * {Fore.GREEN}ebuild firewalls-{__version__}.ebuild digest{Style.RESET_ALL}")
    print(f"   * {_('Commit and upload to Portage repository / overlay')}\n")

