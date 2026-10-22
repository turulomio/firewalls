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
    """Ensure script is running as root."""
    if geteuid() != 0:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Este script debe ser ejecutado con permisos de root.")
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
    """Set root ownership and standard permissions only for files under /etc/firewalld."""
    if not firewalld_path.exists():
        return

    try:
        # Set permissions for /etc/firewalld directory itself and all items inside it
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
        print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} No se pudieron ajustar los permisos en {firewalld_path}: {e}")


def ensure_log_directory(log_dir: Path = Path("/var/log/firewalld")):
    """Ensure /var/log/firewalld exists with secure permissions."""
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        chown(log_dir, user="root", group="root")
        chmod(log_dir, 0o750)
    except Exception as e:
        print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} No se pudo verificar/crear el directorio de logs {log_dir}: {e}")


def ensure_syslog_ng_include(syslog_conf: Path = Path("/etc/syslog-ng/syslog-ng.conf")):
    """Ensure /etc/syslog-ng/syslog-ng.conf includes conf.d/*.conf BEFORE destination/log messages."""
    if not syslog_conf.is_file():
        return
    try:
        content = syslog_conf.read_text(encoding="utf-8")
        include_line = '@include "/etc/syslog-ng/conf.d/*.conf"'
        
        # Remove any misplaced includes at the end or elsewhere to ensure correct order
        lines = [line for line in content.splitlines() if 'conf.d/*.conf' not in line]
        clean_content = "\n".join(lines).rstrip() + "\n"

        # Find where destinations or logs start to place include BEFORE them
        # so flags(final) in conf.d takes precedence over catch-all log destinations
        target_marker = "destination messages"
        if target_marker in clean_content:
            parts = clean_content.split(target_marker, 1)
            new_content = parts[0] + f"# Include modular configuration files (before default destinations/logs)\n{include_line}\n\n" + target_marker + parts[1]
        else:
            log_marker = "log {"
            if log_marker in clean_content:
                parts = clean_content.split(log_marker, 1)
                new_content = parts[0] + f"# Include modular configuration files\n{include_line}\n\n" + log_marker + parts[1]
            else:
                new_content = clean_content + f"\n{include_line}\n"

        if new_content != content:
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Configurando inclusión prioritaria de conf.d en {syslog_conf}...")
            syslog_conf.write_text(new_content, encoding="utf-8")
    except Exception as e:
        print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} No se pudo actualizar {syslog_conf}: {e}")



def reload_syslog_service():
    """Ensure syslog-ng daemon is running or restarted/reloaded with OpenRC/systemd."""
    ensure_syslog_ng_include()
    if which("rc-service"):
        print(f"{Fore.CYAN}[3/5]{Style.RESET_ALL} Gestionando servicio syslog-ng con OpenRC...")
        res = run(["rc-service", "syslog-ng", "status"], capture_output=True, text=True)
        if res.returncode == 0:
            print(f"        Recargando/Reiniciando syslog-ng con OpenRC...")
            run(["rc-service", "syslog-ng", "restart"])
        else:
            print(f"        Iniciando servicio syslog-ng con OpenRC...")
            run(["rc-service", "syslog-ng", "start"])
    elif which("systemctl"):
        print(f"{Fore.CYAN}[3/5]{Style.RESET_ALL} Gestionando servicio syslog-ng con systemd...")
        res = run(["systemctl", "is-active", "--quiet", "syslog-ng"])
        if res.returncode == 0:
            run(["systemctl", "reload-or-restart", "syslog-ng"])
        else:
            run(["systemctl", "start", "syslog-ng"])



def reload_sysctl_settings(source_etc: Path):
    """Reload sysctl settings if sysctl.d configuration exists in the deployed machine."""
    sysctl_dir = source_etc / "sysctl.d"
    if not sysctl_dir.is_dir():
        return

    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Detectada configuración sysctl.d. Recargando parámetros de kernel con sysctl...")
    if which("sysctl"):
        res = run(["sysctl", "--system"])
        if res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Parámetros de sysctl aplicados correctamente.")
        else:
            print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} sysctl --system finalizó con código {res.returncode}.")
    else:
        print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} No se encontró el ejecutable 'sysctl' en el PATH.")


def reload_firewalld():
    """Check firewalld status and reload or start the service with OpenRC/systemd."""
    if not which("firewall-cmd"):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} 'firewall-cmd' no está instalado o no se encuentra en el PATH.")
        print(f"        En Gentoo puedes instalarlo con: {Fore.YELLOW}emerge --ask net-firewall/firewalld{Style.RESET_ALL}")
        exit(1)

    # Check if firewalld is currently running
    state_res = run(["firewall-cmd", "--state"], capture_output=True, text=True)
    is_running = (state_res.returncode == 0)

    if is_running:
        print(f"{Fore.CYAN}[4/5]{Style.RESET_ALL} Recargando reglas de firewalld...")
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


def run_post_deploy_script(machine_dir: Path):
    """Execute optional post_deploy.sh script for the machine if present."""
    script_names = ["post_deploy.sh", "post_deploy"]
    target_script = None
    for sname in script_names:
        candidate = machine_dir / sname
        if candidate.is_file():
            target_script = candidate
            break

    if not target_script:
        return

    print(f"{Fore.CYAN}[5/5]{Style.RESET_ALL} Ejecutando script de post-despliegue ({target_script.name})...")
    try:
        chmod(target_script, 0o755)
        res = run([str(target_script)])
        if res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Script post-despliegue ejecutado con éxito.")
        else:
            print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} El script post-despliegue finalizó con código {res.returncode}.")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error al ejecutar script post-despliegue: {e}")


def stop_firewalld() -> int:
    """Stop firewalld service using OpenRC or systemd."""
    ensure_root()
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Deteniendo servicio firewalld                       {Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")

    if which("rc-service"):
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Ejecutando OpenRC: rc-service firewalld stop...")
        res = run(["rc-service", "firewalld", "stop"])
        if res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Servicio firewalld detenido correctamente.")
            return 0
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se pudo detener el servicio firewalld con OpenRC.")
            return 1
    elif which("systemctl"):
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Ejecutando systemd: systemctl stop firewalld...")
        res = run(["systemctl", "stop", "firewalld"])
        if res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Servicio firewalld detenido correctamente.")
            return 0
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se pudo detener el servicio firewalld con systemd.")
            return 1
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No se pudo determinar el gestor de servicios para detener firewalld.")
        return 1


def main() -> int:
    project_root = get_project_root()
    available_machines = get_available_machines(project_root)

    parser = ArgumentParser(
        prog="deploy",
        description="Despliega la configuración de firewalld para una máquina en Gentoo Linux y recarga el servicio, o detiene el servicio.",
        formatter_class=RawDescriptionHelpFormatter,
        epilog=f"Máquinas disponibles:\n  {', '.join(available_machines) if available_machines else 'Ninguna encontrada'}\n\nOpciones especiales:\n  stop                  Detiene el servicio firewalld del sistema.",
    )
    parser.add_argument(
        "machine",
        nargs="?",
        help="Nombre de la máquina cuya configuración se desea desplegar (ej. worky) o 'stop' para detener firewalld",
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Detiene el servicio firewalld del sistema",
    )

    args = parser.parse_args()

    if args.stop or args.machine == "stop":
        return stop_firewalld()

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

    print(f"{Fore.CYAN}[1/5]{Style.RESET_ALL} Desplegando archivos...")
    print(f"      Origen:  {source_etc}/")
    print(f"      Destino: /etc/")

    try:
        copy_configuration(source_etc, Path("/etc"))
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error al copiar archivos: {e}")
        return 1

    print(f"{Fore.CYAN}[2/5]{Style.RESET_ALL} Ajustando permisos y directorios...")
    fix_firewalld_permissions(Path("/etc/firewalld"))
    ensure_log_directory(Path("/var/log/firewalld"))

    reload_sysctl_settings(source_etc)
    reload_syslog_service()
    reload_firewalld()

    run_post_deploy_script(machine_dir)

    print(f"{Fore.GREEN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  Despliegue finalizado con éxito para '{machine}'  {Style.RESET_ALL}")
    print(f"{Fore.GREEN}======================================================{Style.RESET_ALL}")
    return 0


if __name__ == "__main__":
    exit(main())
