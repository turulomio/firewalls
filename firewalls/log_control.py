#!/usr/bin/env python3
"""Module to manage firewalld runtime LogDenied settings dynamically."""

import os
import signal
import sys
from contextlib import contextmanager
from shutil import which
from subprocess import run

from colorama import Fore, Style


def ensure_root():
    """Ensure script is running as root."""
    if os.geteuid() != 0:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Este script debe ser ejecutado con permisos de root.")
        sys.exit(1)


def get_firewalld_log_denied() -> str:
    """Query the current LogDenied setting in firewalld."""
    if not which("firewall-cmd"):
        return "off"
    res = run(["firewall-cmd", "--get-log-denied"], capture_output=True, text=True)
    if res.returncode == 0:
        return res.stdout.strip()
    return "off"


def set_firewalld_log_denied(mode: str) -> bool:
    """Set the firewalld runtime LogDenied setting (e.g., 'all', 'unicast', 'off')."""
    if not which("firewall-cmd"):
        return False
    res = run(["firewall-cmd", "--set-log-denied", mode], capture_output=True, text=True)
    return res.returncode == 0


@contextmanager
def managed_firewall_log(mode: str = "all"):
    """
    Context manager to dynamically enable firewalld LogDenied during runtime,
    and guarantee it is deactivated (off) upon exit or interruption (Ctrl+C).
    """
    ensure_root()

    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Activando registro de denegaciones en firewalld (LogDenied={mode})...")
    if set_firewalld_log_denied(mode):
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Registro temporal de descartes activado.")
    else:
        print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} No se pudo configurar LogDenied={mode} en firewalld.")

    def _sigterm_handler(signum, frame):
        sys.exit(0)

    prev_sigterm = signal.signal(signal.SIGTERM, _sigterm_handler)

    try:
        yield
    finally:
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Desactivando registro de denegaciones en firewalld (LogDenied=off)...")
        if set_firewalld_log_denied("off"):
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Registro de descartes desactivado (dmesg protegido).")
        else:
            print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} No se pudo desactivar LogDenied en firewalld.")
        signal.signal(signal.SIGTERM, prev_sigterm)
