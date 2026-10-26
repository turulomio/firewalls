#!/usr/bin/env python3
"""CLI tool to probe connectivity for incoming and outgoing connections across specified hosts, ports, and protocols."""

import argparse
import socket
import sys
import time

from colorama import Fore, Style, init

init(autoreset=True)


def probe_tcp_out(host: str, ip: str, port: int, timeout: float) -> tuple[bool, str, float]:
    """Perform an outgoing (egress) TCP connection probe to a target host and port.

    Args:
        host: Target hostname string.
        ip: Target IP address string.
        port: Target TCP port number.
        timeout: Socket timeout in seconds.

    Returns:
        tuple[bool, str, float]: Tuple containing success status, descriptive
        status message, and elapsed time in milliseconds.
    """
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        sock.close()
        return True, "Outgoing connection established successfully", elapsed_ms
    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Connection timed out (Timeout > {timeout}s) - Probable egress firewall drop", elapsed_ms
    except ConnectionRefusedError:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, "Connection refused - Port closed on remote destination", elapsed_ms
    except OSError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Network error ({e.strerror or e})", elapsed_ms
    finally:
        sock.close()


def probe_udp_out(host: str, ip: str, port: int, timeout: float) -> tuple[bool, str, float]:
    """Perform an outgoing (egress) UDP probe packet to target host and port.

    Args:
        host: Target hostname string.
        ip: Target IP address string.
        port: Target UDP port number.
        timeout: Socket timeout in seconds.

    Returns:
        tuple[bool, str, float]: Tuple containing success status, descriptive
        status message, and elapsed time in milliseconds.
    """
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"FIREWALL_PROBE", (ip, port))
        sock.recvfrom(1024)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return True, "UDP response received from destination", elapsed_ms
    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"No UDP response (Timeout > {timeout}s) - Port filtered or dropped", elapsed_ms
    except OSError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"UDP network error ({e.strerror or e})", elapsed_ms
    finally:
        sock.close()


def probe_tcp_listen(bind_ip: str, port: int, timeout: float) -> tuple[bool, str, float]:
    """Listen on a local port for an incoming (ingress) TCP connection.

    Args:
        bind_ip: Local network interface IP to bind.
        port: Local TCP port number to open.
        timeout: Maximum wait time in seconds.

    Returns:
        tuple[bool, str, float]: Tuple containing success status, descriptive
        status message, and elapsed time in milliseconds.
    """
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.bind((bind_ip, port))
        sock.listen(1)
        conn, addr = sock.accept()
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        conn.close()
        return True, f"Incoming connection received successfully from {addr[0]}:{addr[1]}", elapsed_ms
    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"No incoming connections within {timeout}s - Probable ingress firewall block", elapsed_ms
    except PermissionError:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Permission denied binding port {port} (root privileges required for ports < 1024)", elapsed_ms
    except OSError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Local socket error ({e.strerror or e})", elapsed_ms
    finally:
        sock.close()


def probe_udp_listen(bind_ip: str, port: int, timeout: float) -> tuple[bool, str, float]:
    """Listen on a local port for an incoming (ingress) UDP packet.

    Args:
        bind_ip: Local network interface IP to bind.
        port: Local UDP port number to open.
        timeout: Maximum wait time in seconds.

    Returns:
        tuple[bool, str, float]: Tuple containing success status, descriptive
        status message, and elapsed time in milliseconds.
    """
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.bind((bind_ip, port))
        data, addr = sock.recvfrom(1024)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return True, f"Incoming UDP packet received successfully from {addr[0]}:{addr[1]}", elapsed_ms
    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"No incoming UDP packets within {timeout}s - Probable ingress firewall block", elapsed_ms
    except PermissionError:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Permission denied binding port {port} (root privileges required for ports < 1024)", elapsed_ms
    except OSError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Local socket error ({e.strerror or e})", elapsed_ms
    finally:
        sock.close()


def resolve_target(host: str) -> str | None:
    """Resolve destination hostname to IPv4 address.

    Args:
        host: Hostname or IP string.

    Returns:
        str | None: Resolved IPv4 address string, or None if resolution failed.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def run_probes(
    host: str,
    port: int,
    protocol: str,
    timeout: float,
    count: int,
    listen: bool = False,
    bind_ip: str = "0.0.0.0",
) -> int:
    """Execute connectivity probes and print formatted results.

    Args:
        host: Destination hostname or IP for outgoing probes.
        port: Target port number.
        protocol: Protocol string ('tcp' or 'udp').
        timeout: Timeout per probe in seconds.
        count: Number of probe iterations.
        listen: If True, operates in listen mode for incoming probes.
        bind_ip: Local interface IP address to bind in listen mode.

    Returns:
        int: 0 if all probes succeeded, 1 if any probe failed.
    """
    protocol = protocol.lower()

    if listen:
        print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Firewall Ingress Probe (Listen Mode)                {Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Listening: {bind_ip}:{port} ({protocol.upper()}) | Timeout: {timeout}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")

        successes = 0
        for i in range(1, count + 1):
            if count > 1:
                print(f"Waiting for incoming connection [{i}/{count}]...")
            else:
                print(f"Waiting for incoming connection on port {port}...")

            if protocol == "tcp":
                ok, msg, ms = probe_tcp_listen(bind_ip, port, timeout)
            else:
                ok, msg, ms = probe_udp_listen(bind_ip, port, timeout)

            status_color = Fore.GREEN if ok else Fore.RED
            status_text = "PASSED" if ok else "FAILED"

            print(f"  Result: [{status_color}{status_text}{Style.RESET_ALL}] {msg} ({ms:.1f} ms)")
            if ok:
                successes += 1

        print(f"\n{Fore.YELLOW}Summary: {successes}/{count} incoming connections received successfully.{Style.RESET_ALL}")
        return 0 if successes == count else 1

    else:
        ip = resolve_target(host)
        if not ip:
            print(f"{Fore.RED}[ERROR] Could not resolve host: {host}{Style.RESET_ALL}")
            return 1

        print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Firewall Egress Probe (Outgoing Mode)               {Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Target: {host} ({ip}):{port} ({protocol.upper()}) | Timeout: {timeout}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")

        successes = 0
        for i in range(1, count + 1):
            prefix = f"[{i}/{count}] " if count > 1 else ""

            if protocol == "tcp":
                ok, msg, ms = probe_tcp_out(host, ip, port, timeout)
            else:
                ok, msg, ms = probe_udp_out(host, ip, port, timeout)

            status_color = Fore.GREEN if ok else Fore.RED
            status_text = "PASSED" if ok else "FAILED"

            print(f"  {prefix}[{status_color}{status_text}{Style.RESET_ALL}] {msg} ({ms:.1f} ms)")
            if ok:
                successes += 1

        print(f"\n{Fore.YELLOW}Summary: {successes}/{count} probe attempts succeeded.{Style.RESET_ALL}")
        return 0 if successes == count else 1


def main() -> int:
    """Main CLI entrypoint for firewalls_probes.

    Returns:
        int: Exit status code (0 for success, non-zero for error).
    """
    parser = argparse.ArgumentParser(
        prog="firewalls_probes",
        description="Probe firewall connectivity for ingress and egress connections across hosts and ports.",
    )
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default="kde.org",
        help="Target hostname or IP address for outgoing probes (default: kde.org)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=1555,
        help="Port to probe (default: 1555)",
    )
    parser.add_argument(
        "-proto",
        "--protocol",
        choices=["tcp", "udp"],
        default="tcp",
        help="Transport protocol (tcp or udp, default: tcp)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Maximum socket timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=1,
        help="Number of probe attempts to perform (default: 1)",
    )
    parser.add_argument(
        "-l",
        "--listen",
        action="store_true",
        help="Run in incoming listen mode (Ingress test) binding local port",
    )
    parser.add_argument(
        "-b",
        "--bind",
        type=str,
        default="0.0.0.0",
        help="Local IP address to bind in listen mode (default: 0.0.0.0)",
    )

    args = parser.parse_args()

    return run_probes(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        timeout=args.timeout,
        count=args.count,
        listen=args.listen,
        bind_ip=args.bind,
    )


if __name__ == "__main__":
    sys.exit(main())
