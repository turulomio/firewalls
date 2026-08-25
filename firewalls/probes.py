#!/usr/bin/env python3
"""CLI tool to probe connectivity for specified hosts, ports, and protocols."""

import argparse
import socket
import sys
import time
from colorama import Fore, Style, init

init(autoreset=True)


def probe_tcp(host: str, ip: str, port: int, timeout: float) -> tuple[bool, str, float]:
    """Perform a TCP connection test to the target host and port."""
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        sock.close()
        return True, "Conexión establecida con éxito", elapsed_ms
    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Tiempo de espera agotado (Timeout > {timeout}s) - Posible bloqueo de firewall", elapsed_ms
    except ConnectionRefusedError:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, "Conexión rechazada (Connection Refused) - Puerto cerrado en destino", elapsed_ms
    except OSError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Error de red ({e.strerror or e})", elapsed_ms
    finally:
        sock.close()


def probe_udp(host: str, ip: str, port: int, timeout: float) -> tuple[bool, str, float]:
    """Perform a UDP packet test to the target host and port."""
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"FIREWALL_PROBE", (ip, port))
        sock.recvfrom(1024)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return True, "Respuesta UDP recibida del destino", elapsed_ms
    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Sin respuesta UDP (Timeout > {timeout}s) - Posible puerto filtrado/bloqueado", elapsed_ms
    except OSError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Error UDP ({e.strerror or e})", elapsed_ms
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Prueba de conectividad y sondeo de puertos de salida/entrada para la red."
    )
    parser.add_argument(
        "-H",
        "--host",
        default="kde.org",
        help="Host o dirección IP de destino a probar (por defecto: kde.org)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=1555,
        help="Puerto de destino a probar (por defecto: 1555)",
    )
    parser.add_argument(
        "-proto",
        "--protocol",
        choices=["tcp", "udp"],
        default="tcp",
        help="Protocolo de transporte a utilizar: tcp o udp (por defecto: tcp)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Tiempo máximo de espera en segundos (por defecto: 5.0)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=1,
        help="Número de intentos de prueba a realizar (por defecto: 1)",
    )

    args = parser.parse_args()

    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}        Prueba de Conectividad (Firewall Probes)       {Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f" Destino:   {Fore.WHITE}{Style.BRIGHT}{args.host}{Style.RESET_ALL}")
    print(f" Puerto:    {Fore.WHITE}{Style.BRIGHT}{args.port}{Style.RESET_ALL}")
    print(f" Protocolo: {Fore.WHITE}{Style.BRIGHT}{args.protocol.upper()}{Style.RESET_ALL}")
    print(f" Timeout:   {Fore.WHITE}{args.timeout}s{Style.RESET_ALL}")
    print(f"{Fore.CYAN}------------------------------------------------------{Style.RESET_ALL}")

    try:
        ip = socket.gethostbyname(args.host)
        print(f" Dirección IP resuelta: {Fore.YELLOW}{ip}{Style.RESET_ALL}\n")
    except socket.gaierror as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se pudo resolver el nombre de host '{args.host}': {e}")
        sys.exit(1)

    successful = 0
    total_latency = 0.0

    for i in range(1, args.count + 1):
        prefix = f"[{i}/{args.count}]" if args.count > 1 else "Prueba:"

        if args.protocol == "tcp":
            success, msg, latency = probe_tcp(args.host, ip, args.port, args.timeout)
        else:
            success, msg, latency = probe_udp(args.host, ip, args.port, args.timeout)

        if success:
            successful += 1
            total_latency += latency
            print(
                f"{Fore.GREEN}[ÉXITO]{Style.RESET_ALL} {prefix} {args.protocol.upper()} {ip}:{args.port} -> "
                f"{msg} ({latency:.2f} ms)"
            )
        else:
            print(
                f"{Fore.RED}[DENEGADO/FALLO]{Style.RESET_ALL} {prefix} {args.protocol.upper()} {ip}:{args.port} -> "
                f"{msg} ({latency:.2f} ms)"
            )

        if i < args.count:
            time.sleep(0.5)

    if args.count > 1:
        print(f"\n{Fore.CYAN}------------------------------------------------------{Style.RESET_ALL}")
        print(
            f" Resultados: {successful}/{args.count} exitosos. "
            f"Latencia media: {(total_latency / successful):.2f} ms" if successful > 0 else f" Resultados: 0/{args.count} exitosos."
        )

    sys.exit(0 if successful > 0 else 1)


if __name__ == "__main__":
    main()
