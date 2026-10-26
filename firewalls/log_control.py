#!/usr/bin/env python3
"""Module to manage firewalld runtime LogDenied settings dynamically."""

import os
import signal
import sys
from collections.abc import Generator
from contextlib import contextmanager
from shutil import which
from subprocess import run

from colorama import Fore, Style


def ensure_root() -> None:
    """Ensure the script is being executed with root privileges.

    Raises:
        SystemExit: If the current effective user ID is not 0 (root).
    """
    if os.geteuid() != 0:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} This script must be executed with root privileges.")
        sys.exit(1)


def get_firewalld_log_denied() -> str:
    """Query the current LogDenied runtime setting in firewalld.

    Returns:
        str: The active LogDenied mode ('all', 'unicast', 'broadcast',
        'multicast', or 'off'). Defaults to 'off' if firewall-cmd is unavailable
        or fails.
    """
    if not which("firewall-cmd"):
        return "off"
    res = run(["firewall-cmd", "--get-log-denied"], capture_output=True, text=True)
    if res.returncode == 0:
        return res.stdout.strip()
    return "off"


def set_firewalld_log_denied(mode: str) -> bool:
    """Set the firewalld runtime LogDenied setting.

    Args:
        mode: LogDenied mode to apply ('all', 'unicast', 'broadcast',
            'multicast', or 'off').

    Returns:
        bool: True if the command succeeded, False otherwise.
    """
    if not which("firewall-cmd"):
        return False
    res = run(["firewall-cmd", "--set-log-denied", mode], capture_output=True, text=True)
    return res.returncode == 0


@contextmanager
def managed_firewall_log(mode: str = "all") -> Generator[None, None, None]:
    """Context manager to dynamically enable firewalld LogDenied during runtime.

    Ensures root permissions, enables the specified LogDenied mode, and
    guarantees that LogDenied is deactivated ('off') upon exit or interruption
    (e.g., Ctrl+C or SIGTERM), preventing kernel ring buffer (dmesg) pollution.

    Args:
        mode: LogDenied mode to activate during the context block.
            Defaults to "all".

    Yields:
        None: Control is returned to the context block.
    """
    ensure_root()

    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Enabling firewalld packet drop logging (LogDenied={mode})...")
    if set_firewalld_log_denied(mode):
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Temporary drop logging activated.")
    else:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Could not set LogDenied={mode} in firewalld.")

    def _sigterm_handler(signum, frame):
        sys.exit(0)

    prev_sigterm = signal.signal(signal.SIGTERM, _sigterm_handler)

    try:
        yield
    finally:
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Disabling firewalld packet drop logging (LogDenied=off)...")
        if set_firewalld_log_denied("off"):
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Drop logging deactivated (dmesg protected).")
        else:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Could not reset LogDenied in firewalld.")
        signal.signal(signal.SIGTERM, prev_sigterm)
