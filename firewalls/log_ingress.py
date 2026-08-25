#!/usr/bin/env python3
"""CLI tool to monitor and summarize denied ingress (incoming) firewall logs."""

import argparse
import re
import sys
import time
from collections import Counter
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_LOG = Path("/var/log/firewalld/denied.log")


def parse_line(line: str) -> dict | None:
    # Match kernel log line for denied packet
    # Ingress lines have OUT= (empty interface) or OUT= followed by space
    out_match = re.search(r"\bOUT=(\s|$)", line)
    if not out_match:
        return None

    # Check date/time at start of line
    timestamp_match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
    timestamp = timestamp_match.group(1) if timestamp_match else "N/A"

    proto_m = re.search(r"\bPROTO=([^\s]+)", line)
    src_m = re.search(r"\bSRC=([^\s]+)", line)
    dpt_m = re.search(r"\bDPT=([^\s]+)", line)
    spt_m = re.search(r"\bSPT=([^\s]+)", line)
    in_m = re.search(r"\bIN=([^\s]+)", line)

    return {
        "timestamp": timestamp,
        "proto": proto_m.group(1) if proto_m else "N/A",
        "src": src_m.group(1) if src_m else "N/A",
        "dpt": dpt_m.group(1) if dpt_m else "N/A",
        "spt": spt_m.group(1) if spt_m else "N/A",
        "in": in_m.group(1) if in_m else "N/A",
    }


def show_summary(log_file: Path):
    if not log_file.exists():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No existe el archivo de log: {log_file}")
        sys.exit(1)

    counter = Counter()
    with log_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            data = parse_line(line)
            if data:
                key = (data["proto"], data["src"], data["dpt"])
                counter[key] += 1

    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Resumen de Conexiones Entrantes Bloqueadas (Ingress){Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    if not counter:
        print(f"{Fore.YELLOW}No se encontraron eventos de entrada denegados.{Style.RESET_ALL}")
        return

    print(f"{Fore.YELLOW}{'CONTEO':<8} {'PROTO':<8} {'ORIGEN':<18} {'PUERTO DEST':<12}{Style.RESET_ALL}")
    print("-" * 50)
    for (proto, src, dpt), count in counter.most_common():
        print(f"{Fore.GREEN}{count:<8}{Style.RESET_ALL} {Fore.CYAN}{proto:<8}{Style.RESET_ALL} {Fore.WHITE}{src:<18}{Style.RESET_ALL} {Fore.MAGENTA}{dpt:<12}{Style.RESET_ALL}")


def follow_logs(log_file: Path):
    if not log_file.exists():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No existe el archivo de log: {log_file}")
        sys.exit(1)

    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Monitor de Tráfico ENTRANTE Denegado (Ingress)      {Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Archivo: {log_file}                                  {Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Mostrando eventos en tiempo real (Ctrl+C para salir)...\n{Style.RESET_ALL}")

    with log_file.open("r", encoding="utf-8", errors="ignore") as f:
        # Seek near end for follow mode
        f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                data = parse_line(line)
                if data:
                    print(
                        f"{Fore.YELLOW}[{data['timestamp']}]{Style.RESET_ALL} "
                        f"{Fore.RED}[BLOQUEADO ENTRADA]{Style.RESET_ALL} "
                        f"Proto: {Fore.CYAN}{data['proto']:<5}{Style.RESET_ALL} "
                        f"Origen: {Fore.GREEN}{data['src']:<15}{Style.RESET_ALL} "
                        f"Puerto Destino: {Fore.MAGENTA}{data['dpt']:<5}{Style.RESET_ALL} "
                        f"(Puerto Origen: {data['spt']} -> Interfaz: {data['in']})"
                    )
                    sys.stdout.flush()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Monitor finalizado.{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        prog="firewalls_log_ingress",
        description="Monitoriza y resume los logs de conexiones entrantes bloqueadas por el firewall.",
    )
    parser.add_argument(
        "-s", "--summary", action="store_true", help="Muestra un resumen ordenado de conexiones entrantes bloqueadas."
    )
    parser.add_argument(
        "-f", "--file", type=Path, default=DEFAULT_LOG, help="Ruta al archivo de log (por defecto /var/log/firewalld/denied.log)."
    )
    args = parser.parse_args()

    if args.summary:
        show_summary(args.file)
    else:
        follow_logs(args.file)


if __name__ == "__main__":
    main()
