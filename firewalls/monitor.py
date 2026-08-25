#!/usr/bin/env python3
"""CLI tool to continuously monitor and tally denied ingress and egress firewall connections."""

import argparse
import datetime
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_LOG = Path("/var/log/firewalld/denied.log")


def parse_denied_line(line: str):
    """Parse log line into ingress or egress event with IP, port, and protocol."""
    # Egress if OUT= has a non-empty interface
    out_m = re.search(r"\bOUT=([^\s]+)", line)
    is_egress = bool(out_m and out_m.group(1) != "")

    proto_m = re.search(r"\bPROTO=([^\s]+)", line)
    dpt_m = re.search(r"\bDPT=([^\s]+)", line)

    proto = proto_m.group(1) if proto_m else "N/A"
    dpt = dpt_m.group(1) if dpt_m else "N/A"

    if is_egress:
        dst_m = re.search(r"\bDST=([^\s]+)", line)
        dst = dst_m.group(1) if dst_m else "N/A"
        return "egress", (proto, dst, dpt)
    else:
        src_m = re.search(r"\bSRC=([^\s]+)", line)
        src = src_m.group(1) if src_m else "N/A"
        return "ingress", (proto, src, dpt)


def read_and_count_events(log_file: Path):
    ingress_counts = Counter()
    egress_counts = Counter()

    if not log_file.exists():
        return ingress_counts, egress_counts, False

    try:
        with log_file.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "_DROP" in line or "_REJECT" in line or "FINAL_DROP" in line or "FINAL_REJECT" in line or "_DENIED" in line:
                    event_type, key = parse_denied_line(line)
                    if event_type == "egress":
                        egress_counts[key] += 1
                    else:
                        ingress_counts[key] += 1
        return ingress_counts, egress_counts, True
    except Exception:
        return ingress_counts, egress_counts, False


def render_dashboard(log_file: Path, interval: float, top_limit: int, count_historical: bool = False):
    ingress_counts = Counter()
    egress_counts = Counter()
    start_time_str = datetime.datetime.now().strftime("%H:%M:%S")

    f = None
    if log_file.exists():
        try:
            f = log_file.open("r", encoding="utf-8", errors="ignore")
            if not count_historical:
                # Start from end of file (count from zero for new events)
                f.seek(0, os.SEEK_END)
        except Exception:
            f = None

    while True:
        now_str = datetime.datetime.now().strftime("%H:%M:%S")

        # Read any new lines appended since last check
        if f is None and log_file.exists():
            try:
                f = log_file.open("r", encoding="utf-8", errors="ignore")
                if not count_historical:
                    f.seek(0, os.SEEK_END)
            except Exception:
                f = None

        if f is not None:
            try:
                # Check for file truncation/rotation
                current_pos = f.tell()
                file_size = log_file.stat().st_size
                if current_pos > file_size:
                    f.seek(0, 0)

                for line in f:
                    if "_DROP" in line or "_REJECT" in line or "FINAL_DROP" in line or "FINAL_REJECT" in line or "_DENIED" in line:
                        event_type, key = parse_denied_line(line)
                        if event_type == "egress":
                            egress_counts[key] += 1
                        else:
                            ingress_counts[key] += 1
            except Exception:
                pass

        # Clear screen (ANSI escape)
        sys.stdout.write("\033[H\033[2J")

        print(f"{Fore.CYAN}================================================================================{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  MONITOR DE DENEGACIONES FIREWALL | Inicio: {start_time_str} | Refresco: {interval}s {Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Archivo: {log_file} | Última actualización: {Fore.YELLOW}{now_str}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}================================================================================{Style.RESET_ALL}")

        if not log_file.exists():
            print(f"\n{Fore.RED}[ERROR] No se encuentra el archivo de log: {log_file}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Esperando a que se cree el archivo...{Style.RESET_ALL}")
        else:
            total_ingress = sum(ingress_counts.values())
            total_egress = sum(egress_counts.values())

            # Panel 1: INGRESS
            print(f"\n{Fore.RED}📥 ENTRADAS DENEGADAS (INGRESS){Style.RESET_ALL} - Eventos capturados: {Fore.YELLOW}{total_ingress}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'POS':<5} {'CONTEO':<10} {'PROTO':<8} {'IP ORIGEN':<22} {'PUERTO DESTINO':<12}{Style.RESET_ALL}")
            print("-" * 60)
            if not ingress_counts:
                print(f"{Fore.WHITE}Esperando eventos de entrada denegados...{Style.RESET_ALL}")
            else:
                for rank, ((proto, src, dpt), count) in enumerate(ingress_counts.most_common(top_limit), start=1):
                    print(
                        f"{Fore.WHITE}#{rank:<4}{Style.RESET_ALL} "
                        f"{Fore.GREEN}{count:<10}{Style.RESET_ALL} "
                        f"{Fore.CYAN}{proto:<8}{Style.RESET_ALL} "
                        f"{Fore.WHITE}{src:<22}{Style.RESET_ALL} "
                        f"{Fore.MAGENTA}{dpt:<12}{Style.RESET_ALL}"
                    )

            # Panel 2: EGRESS
            print(f"\n{Fore.RED}📤 SALIDAS DENEGADAS (EGRESS){Style.RESET_ALL} - Eventos capturados: {Fore.YELLOW}{total_egress}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'POS':<5} {'CONTEO':<10} {'PROTO':<8} {'IP DESTINO':<22} {'PUERTO':<12}{Style.RESET_ALL}")
            print("-" * 60)
            if not egress_counts:
                print(f"{Fore.WHITE}Esperando eventos de salida denegados...{Style.RESET_ALL}")
            else:
                for rank, ((proto, dst, dpt), count) in enumerate(egress_counts.most_common(top_limit), start=1):
                    print(
                        f"{Fore.WHITE}#{rank:<4}{Style.RESET_ALL} "
                        f"{Fore.GREEN}{count:<10}{Style.RESET_ALL} "
                        f"{Fore.CYAN}{proto:<8}{Style.RESET_ALL} "
                        f"{Fore.WHITE}{dst:<22}{Style.RESET_ALL} "
                        f"{Fore.MAGENTA}{dpt:<12}{Style.RESET_ALL}"
                    )

        sys.stdout.flush()
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(
        prog="firewalls_monitor",
        description="Monitor en tiempo real de conteo acumulado de denegaciones de entrada y salida (IP + puerto).",
    )
    parser.add_argument(
        "-n",
        "-i",
        "--interval",
        type=float,
        default=3.0,
        help="Intervalo de refresco en segundos (por defecto 3.0).",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        default=DEFAULT_LOG,
        help="Ruta al archivo de log (por defecto /var/log/firewalld/denied.log).",
    )
    parser.add_argument(
        "-p",
        "-l",
        "-t",
        "--positions",
        "--limit",
        "--top",
        dest="top",
        type=int,
        default=20,
        help="Número de posiciones / entradas a mostrar en el ranking por panel (por defecto 20).",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Incluir el historial completo desde el inicio del archivo de log en lugar de empezar desde cero.",
    )
    args = parser.parse_args()

    try:
        render_dashboard(args.file, args.interval, args.top, count_historical=args.all)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Monitor finalizado.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
