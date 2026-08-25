#!/usr/bin/env python3
"""CLI tool to deploy firewalld configuration and reload the service."""

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from os import chmod, execvp, geteuid, walk
from pathlib import Path
from shutil import chown, copy2, which
from subprocess import run
from sys import argv, executable, exit

from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def get_project_root() -> Path:
    """Find the root directory of the project."""
    current = Path(__file__).resolve().parent
    # If in firewalls/cli.py, parent is project root
    if (current.parent / "pyproject.toml").exists() or (current.parent / ".git").exists():
        return current.parent
    return current


def get_available_machines(project_root: Path) -> list[str]:
    """Find all configured machine directories (containing an etc/ folder)."""
    machines = []
    for item in project_root.iterdir():
        if item.is_dir() and (item / "etc").is_dir() and not item.name.startswith("."):
            machines.append(item.name)
    return sorted(machines)


def ensure_root():
    """Ensure script is running as root; re-exec with sudo if needed."""
    if geteuid() != 0:
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Se requieren privilegios de root para aplicar la configuración en /etc.")
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Reejecutando con sudo...")
        try:
            # Re-exec preserving current python and arguments
            args = ["sudo", executable] + argv
            execvp("sudo", args)
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se pudo elevar privilegios con sudo: {e}")
            exit(1)


def copy_configuration(source_etc: Path, target_etc: Path = Path("/etc")):
    """Copy configuration files from machine etc directory to /etc."""
    if which("rsync"):
        # Use rsync if available
        cmd = ["rsync", "-avh", "--keep-dirlinks", f"{source_etc}/", f"{target_etc}/"]
        res = run(cmd)
        if res.returncode != 0:
            raise RuntimeError(f"Fallo al sincronizar con rsync (código {res.returncode})")
    else:
        # Fallback: copy tree
        for root, dirs, files in walk(source_etc):
            rel_path = Path(root).relative_to(source_etc)
            dest_dir = target_etc / rel_path
            dest_dir.mkdir(parents=True, exist_ok=True)
            for file in files:
                src_file = Path(root) / file
                dest_file = dest_dir / file
                copy2(src_file, dest_file)


def fix_firewalld_permissions(firewalld_path: Path = Path("/etc/firewalld")):
    """Set standard permissions and ownership for firewalld directory."""
    if not firewalld_path.exists():
        return

    # Set root:root ownership
    try:
        chown(firewalld_path, user="root", group="root")
        chmod(firewalld_path, 0o750)
        for root, dirs, files in walk(firewalld_path):
            for d in dirs:
                dir_full = Path(root) / d
                chown(dir_full, user="root", group="root")
                chmod(dir_full, 0o750)
            for f in files:
                file_full = Path(root) / f
                chown(file_full, user="root", group="root")
                chmod(file_full, 0o644)
    except Exception as e:
        print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} No se pudieron ajustar todos los permisos en {firewalld_path}: {e}")


def reload_firewalld():
    """Check firewalld status and reload or start the service."""
    if not which("firewall-cmd"):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} 'firewall-cmd' no está instalado o no se encuentra en el PATH.")
        print(f"        En Gentoo puedes instalarlo con: {Fore.YELLOW}emerge --ask net-firewall/firewalld{Style.RESET_ALL}")
        exit(1)

    # Check if firewalld is currently running
    state_res = run(["firewall-cmd", "--state"], capture_output=True, text=True)
    is_running = (state_res.returncode == 0)

    if is_running:
        print(f"{Fore.CYAN}[3/3]{Style.RESET_ALL} Recargando reglas de firewalld...")
        reload_res = run(["firewall-cmd", "--reload"])
        if reload_res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Configuración recargada con éxito en firewalld.")
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Falló la recarga de firewalld. Comprueba los archivos XML de configuración.")
            exit(1)
    else:
        print(f"{Fore.YELLOW}[ADVERTENCIA]{Style.RESET_ALL} firewalld no está en ejecución.")
        # Detect service manager
        if which("rc-service"):
            print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Detectado OpenRC. Intentando iniciar servicio firewalld...")
            start_res = run(["rc-service", "firewalld", "start"])
            if start_res.returncode == 0:
                print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Servicio firewalld iniciado correctamente.")
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se pudo iniciar el servicio firewalld con OpenRC.")
                exit(1)
        elif which("systemctl"):
            print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Detectado systemd. Intentando iniciar servicio firewalld...")
            start_res = run(["systemctl", "start", "firewalld"])
            if start_res.returncode == 0:
                print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Servicio firewalld iniciado correctamente.")
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se pudo iniciar el servicio firewalld con systemd.")
                exit(1)
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se pudo determinar el gestor de servicios para iniciar firewalld.")
            print("        Por favor, inicia el servicio manualmente.")
            exit(1)


def main() -> int:
    project_root = get_project_root()
    available_machines = get_available_machines(project_root)

    parser = ArgumentParser(
        prog="deploy",
        description="Despliega la configuración de firewalld para una máquina en Gentoo Linux y recarga el servicio.",
        formatter_class=RawDescriptionHelpFormatter,
        epilog=f"Máquinas disponibles:\n  {', '.join(available_machines) if available_machines else 'Ninguna encontrada'}",
    )
    parser.add_argument(
        "machine",
        nargs="?",
        help="Nombre de la máquina cuya configuración se desea desplegar (ej. worky)",
    )

    args = parser.parse_args()

    if not args.machine:
        parser.print_help()
        return 1

    machine = args.machine
    machine_dir = project_root / machine
    source_etc = machine_dir / "etc"

    if not machine_dir.is_dir():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se encuentra el directorio de la máquina '{machine}': {machine_dir}")
        if available_machines:
            print(f"{Fore.YELLOW}Máquinas disponibles:{Style.RESET_ALL} {', '.join(available_machines)}")
        return 1

    if not source_etc.is_dir():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No existe la subcarpeta etc en '{machine}': {source_etc}")
        return 1

    # Require root / re-elevate
    ensure_root()

    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Despliegue de Firewalld (Gentoo) - Máquina: {Fore.GREEN}{machine}{Fore.CYAN}  {Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")

    print(f"{Fore.CYAN}[1/3]{Style.RESET_ALL} Desplegando archivos...")
    print(f"      Origen:  {source_etc}/")
    print(f"      Destino: /etc/")

    try:
        copy_configuration(source_etc, Path("/etc"))
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error al copiar archivos: {e}")
        return 1

    print(f"{Fore.CYAN}[2/3]{Style.RESET_ALL} Ajustando permisos en /etc/firewalld...")
    fix_firewalld_permissions(Path("/etc/firewalld"))

    reload_firewalld()

    print(f"{Fore.GREEN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  Despliegue finalizado con éxito para '{machine}'  {Style.RESET_ALL}")
    print(f"{Fore.GREEN}======================================================{Style.RESET_ALL}")
    return 0


if __name__ == "__main__":
    exit(main())
