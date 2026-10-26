import os

def translate():
    """Extract translatable strings, update PO catalogs, and compile MO binary files."""
    os.system("xgettext -L Python --no-wrap --no-location --from-code='UTF-8' -o firewalls/locale/firewalls.pot firewalls/*.py")
    for lang in ["es", "fr", "ro", "ru", "zh", "hi"]:
        os.makedirs(f"firewalls/locale/{lang}/LC_MESSAGES", exist_ok=True)
        os.system(f"msgmerge -N --no-wrap -U firewalls/locale/{lang}.po firewalls/locale/firewalls.pot")
        os.system(f"msgfmt -cv -o firewalls/locale/{lang}/LC_MESSAGES/firewalls.mo firewalls/locale/{lang}.po")
