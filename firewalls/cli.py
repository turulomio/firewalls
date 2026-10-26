#!/usr/bin/env python3
"""CLI tool to deploy firewalld configuration and manage the service."""

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from os import chmod, environ, geteuid, walk
from pathlib import Path
from shutil import chown, copy2, which
from subprocess import run
from sys import exit

from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def get_project_root() -> Path:
    """Find the root directory of the project.

    Returns:
        Path: The root directory containing pyproject.toml or .git,
        or the parent directory of this module.
    """
    current = Path(__file__).resolve().parent
    if (current.parent / "pyproject.toml").exists() or (current.parent / ".git").exists():
        return current.parent
    return current


def get_search_directories(project_root: Path, configs_dir: Path | None = None) -> list[Path]:
    """Get list of directories where machine configurations might be located.

    Checks, in priority order:
    1. Explicit configs_dir CLI argument (--configs-dir / -d)
    2. FIREWALLS_DIR environment variable
    3. User configuration directory (~/.config/firewalls/machines)
    4. Project root directory

    Args:
        project_root: Project root directory Path.
        configs_dir: Optional explicit directory passed by CLI argument.

    Returns:
        list[Path]: Ordered list of existing search directory paths.
    """
    search_dirs: list[Path] = []
    if configs_dir:
        resolved_configs = configs_dir.expanduser().resolve()
        if resolved_configs.is_dir() and resolved_configs not in search_dirs:
            search_dirs.append(resolved_configs)

    env_dir = environ.get("FIREWALLS_DIR")
    if env_dir:
        p = Path(env_dir).expanduser().resolve()
        if p.is_dir() and p not in search_dirs:
            search_dirs.append(p)

    user_config_dir = Path.home() / ".config" / "firewalls" / "machines"
    if user_config_dir.is_dir() and user_config_dir not in search_dirs:
        search_dirs.append(user_config_dir)

    if project_root.is_dir() and project_root not in search_dirs:
        search_dirs.append(project_root)

    return search_dirs


def get_available_machines(search_dirs: list[Path]) -> dict[str, Path]:
    """Find all configured machine directories (containing an etc/ folder).

    Args:
        search_dirs: List of directory paths to scan.

    Returns:
        dict[str, Path]: Mapping of machine names to their directory paths.
    """
    machines: dict[str, Path] = {}
    for sdir in search_dirs:
        if not sdir.is_dir():
            continue
        try:
            for item in sdir.iterdir():
                if item.is_dir() and (item / "etc").is_dir() and not item.name.startswith("."):
                    if item.name not in machines:
                        machines[item.name] = item
        except PermissionError:
            continue
    return machines


def resolve_machine_path(machine_arg: str, search_dirs: list[Path]) -> tuple[str, Path | None]:
    """Resolve a machine argument into its identifier and directory path.

    Supports direct relative/absolute directory paths or machine identifiers
    found within any of the configured search directories.

    Args:
        machine_arg: Machine name or filesystem path provided by the user.
        search_dirs: List of candidate base directories.

    Returns:
        tuple[str, Path | None]: Tuple containing the machine name and the
        resolved directory Path, or (machine_arg, None) if not found.
    """
    candidate = Path(machine_arg).expanduser()
    # Check if a direct directory path was passed
    if candidate.is_dir() and (candidate / "etc").is_dir():
        return candidate.resolve().name, candidate.resolve()

    # Search in configured directories
    for sdir in search_dirs:
        candidate_dir = sdir / machine_arg
        if candidate_dir.is_dir() and (candidate_dir / "etc").is_dir():
            return machine_arg, candidate_dir.resolve()

    return machine_arg, None


def ensure_root() -> None:
    """Ensure the script is being executed with root privileges.

    Raises:
        SystemExit: If the effective user ID is not 0 (root).
    """
    if geteuid() != 0:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} This script must be executed with root privileges.")
        exit(1)


def copy_configuration(source_etc: Path, target_etc: Path = Path("/etc")) -> None:
    """Copy configuration files from the machine etc directory to system /etc.

    Uses rsync if available to preserve symlinks and attributes, or falls
    back to standard file tree copy.

    Args:
        source_etc: Source path to the machine's etc/ directory.
        target_etc: Target system directory path (defaults to /etc).

    Raises:
        RuntimeError: If rsync synchronization fails.
    """
    if which("rsync"):
        cmd = ["rsync", "-avh", "--keep-dirlinks", f"{source_etc}/", f"{target_etc}/"]
        res = run(cmd)
        if res.returncode != 0:
            raise RuntimeError(f"rsync synchronization failed with exit code {res.returncode}")
    else:
        for root, dirs, files in walk(source_etc):
            rel_path = Path(root).relative_to(source_etc)
            dest_dir = target_etc / rel_path
            dest_dir.mkdir(parents=True, exist_ok=True)
            for file in files:
                src_file = Path(root) / file
                dest_file = dest_dir / file
                copy2(src_file, dest_file)


def fix_firewalld_permissions(firewalld_path: Path = Path("/etc/firewalld")) -> None:
    """Set root ownership and standard secure permissions under /etc/firewalld.

    Sets directory permissions to 0750 and file permissions to 0644. Does not
    modify permissions of parent directories such as /etc.

    Args:
        firewalld_path: Target path to the firewalld directory. Defaults to /etc/firewalld.
    """
    if not firewalld_path.exists():
        return

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
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Could not adjust permissions in {firewalld_path}: {e}")


def ensure_log_directory(log_dir: Path = Path("/var/log/firewalld")) -> None:
    """Ensure /var/log/firewalld exists with secure permissions (0750, root:root).

    Args:
        log_dir: Directory path for dedicated firewalld logs. Defaults to /var/log/firewalld.
    """
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        chown(log_dir, user="root", group="root")
        chmod(log_dir, 0o750)
    except Exception as e:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Could not verify or create log directory {log_dir}: {e}")


def ensure_syslog_ng_include(syslog_conf: Path = Path("/etc/syslog-ng/syslog-ng.conf")) -> None:
    """Ensure /etc/syslog-ng/syslog-ng.conf includes modular conf.d/*.conf files.

    Places the include directive before default log/destination definitions so
    flags(final) in modular configurations take priority.

    Args:
        syslog_conf: Path to syslog-ng main configuration file.
    """
    if not syslog_conf.is_file():
        return
    try:
        content = syslog_conf.read_text(encoding="utf-8")
        include_line = '@include "/etc/syslog-ng/conf.d/*.conf"'

        # Remove misplaced include lines to ensure correct ordering
        lines = [line for line in content.splitlines() if "conf.d/*.conf" not in line]
        clean_content = "\n".join(lines).rstrip() + "\n"

        target_marker = "destination messages"
        if target_marker in clean_content:
            parts = clean_content.split(target_marker, 1)
            new_content = (
                parts[0]
                + f"# Include modular configuration files (before default destinations/logs)\n{include_line}\n\n"
                + target_marker
                + parts[1]
            )
        else:
            log_marker = "log {"
            if log_marker in clean_content:
                parts = clean_content.split(log_marker, 1)
                new_content = (
                    parts[0]
                    + f"# Include modular configuration files\n{include_line}\n\n"
                    + log_marker
                    + parts[1]
                )
            else:
                new_content = clean_content + f"\n{include_line}\n"

        if new_content != content:
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Configuring conf.d include directive in {syslog_conf}...")
            syslog_conf.write_text(new_content, encoding="utf-8")
    except Exception as e:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Could not update {syslog_conf}: {e}")


def reload_syslog_service() -> None:
    """Ensure syslog-ng daemon is running or reloaded using OpenRC or systemd."""
    ensure_syslog_ng_include()
    if which("rc-service"):
        print(f"{Fore.CYAN}[3/5]{Style.RESET_ALL} Managing syslog-ng service with OpenRC...")
        res = run(["rc-service", "syslog-ng", "status"], capture_output=True, text=True)
        if res.returncode == 0:
            print("        Restarting/Reloading syslog-ng with OpenRC...")
            run(["rc-service", "syslog-ng", "restart"])
        else:
            print("        Starting syslog-ng service with OpenRC...")
            run(["rc-service", "syslog-ng", "start"])
    elif which("systemctl"):
        print(f"{Fore.CYAN}[3/5]{Style.RESET_ALL} Managing syslog-ng service with systemd...")
        res = run(["systemctl", "is-active", "--quiet", "syslog-ng"])
        if res.returncode == 0:
            run(["systemctl", "reload-or-restart", "syslog-ng"])
        else:
            run(["systemctl", "start", "syslog-ng"])


def reload_sysctl_settings(source_etc: Path) -> None:
    """Reload kernel sysctl parameters if sysctl.d configuration exists in the deployed machine.

    Args:
        source_etc: Source etc/ directory Path of the deployed machine.
    """
    sysctl_dir = source_etc / "sysctl.d"
    if not sysctl_dir.is_dir():
        return

    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Detected sysctl.d configuration. Applying kernel parameters with sysctl...")
    if which("sysctl"):
        res = run(["sysctl", "--system"])
        if res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} sysctl parameters applied successfully.")
        else:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} sysctl --system exited with code {res.returncode}.")
    else:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} 'sysctl' binary not found in PATH.")


def reload_firewalld() -> None:
    """Check firewalld status and reload or start the service using OpenRC or systemd.

    Raises:
        SystemExit: If firewall-cmd is missing, reload fails, or the service
        cannot be started.
    """
    if not which("firewall-cmd"):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} 'firewall-cmd' is not installed or not found in PATH.")
        print(f"        On Gentoo Linux, install it with: {Fore.YELLOW}emerge --ask net-firewall/firewalld{Style.RESET_ALL}")
        exit(1)

    state_res = run(["firewall-cmd", "--state"], capture_output=True, text=True)
    is_running = state_res.returncode == 0

    if is_running:
        print(f"{Fore.CYAN}[4/5]{Style.RESET_ALL} Reloading firewalld rules...")
        reload_res = run(["firewall-cmd", "--reload"])
        if reload_res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Configuration reloaded successfully in firewalld.")
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} firewalld reload failed. Please check XML configuration files.")
            exit(1)
    else:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} firewalld is not running.")
        if which("rc-service"):
            print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Detected OpenRC. Starting firewalld service...")
            start_res = run(["rc-service", "firewalld", "start"])
            if start_res.returncode == 0:
                print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} firewalld service started successfully.")
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to start firewalld service with OpenRC.")
                exit(1)
        elif which("systemctl"):
            print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Detected systemd. Starting firewalld service...")
            start_res = run(["systemctl", "start", "firewalld"])
            if start_res.returncode == 0:
                print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} firewalld service started successfully.")
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to start firewalld service with systemd.")
                exit(1)
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not determine service manager to start firewalld.")
            print("        Please start the service manually.")
            exit(1)


def run_post_deploy_script(machine_dir: Path) -> None:
    """Execute optional post_deploy.sh script for the machine if present.

    Args:
        machine_dir: Directory path for the machine being deployed.
    """
    script_names = ["post_deploy.sh", "post_deploy"]
    target_script = None
    for sname in script_names:
        candidate = machine_dir / sname
        if candidate.is_file():
            target_script = candidate
            break

    if not target_script:
        return

    print(f"{Fore.CYAN}[5/5]{Style.RESET_ALL} Executing post-deployment script ({target_script.name})...")
    try:
        chmod(target_script, 0o755)
        res = run([str(target_script)])
        if res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Post-deployment script finished successfully.")
        else:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Post-deployment script exited with code {res.returncode}.")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error running post-deployment script: {e}")


def stop_firewalld() -> int:
    """Stop firewalld service using OpenRC or systemd.

    Returns:
        int: 0 on success, 1 on failure.
    """
    ensure_root()
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Stopping firewalld service                          {Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")

    if which("rc-service"):
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Running OpenRC: rc-service firewalld stop...")
        res = run(["rc-service", "firewalld", "stop"])
        if res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} firewalld service stopped successfully.")
            return 0
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to stop firewalld service with OpenRC.")
            return 1
    elif which("systemctl"):
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Running systemd: systemctl stop firewalld...")
        res = run(["systemctl", "stop", "firewalld"])
        if res.returncode == 0:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} firewalld service stopped successfully.")
            return 0
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to stop firewalld service with systemd.")
            return 1
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not determine service manager to stop firewalld.")
        return 1


def main() -> int:
    """Main CLI entrypoint for deployment and service control.

    Returns:
        int: Exit status code (0 for success, non-zero for error).
    """
    project_root = get_project_root()

    # Pre-parse -d/--configs-dir to discover machines for help epilog
    pre_parser = ArgumentParser(add_help=False)
    pre_parser.add_argument("-d", "--configs-dir", type=Path)
    pre_args, _ = pre_parser.parse_known_args()

    search_dirs = get_search_directories(project_root, pre_args.configs_dir)
    available_machines = get_available_machines(search_dirs)

    machine_list_str = (
        ", ".join(f"{name} ({path})" for name, path in available_machines.items())
        if available_machines
        else "None found"
    )

    parser = ArgumentParser(
        prog="deploy",
        description="Deploy firewalld configuration for a machine on Gentoo Linux and reload or stop the service.",
        formatter_class=RawDescriptionHelpFormatter,
        epilog=(
            f"Detected machines:\n  {machine_list_str}\n\n"
            f"Search directories:\n  "
            + "\n  ".join(str(d) for d in search_dirs)
            + "\n\nSpecial options:\n  stop                  Stop the system firewalld service."
        ),
    )
    parser.add_argument(
        "machine",
        nargs="?",
        help="Machine name or directory path to deploy (e.g., example, /path/to/machine) or 'stop' to stop firewalld",
    )
    parser.add_argument(
        "-d",
        "--configs-dir",
        type=Path,
        help="Directory containing machine configuration folders (overrides FIREWALLS_DIR)",
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop the system firewalld service",
    )

    args = parser.parse_args()

    if args.stop or args.machine == "stop":
        return stop_firewalld()

    if not args.machine:
        parser.print_help()
        return 1

    # Re-evaluate search dirs if --configs-dir was supplied
    search_dirs = get_search_directories(project_root, args.configs_dir)
    machine_name, machine_dir = resolve_machine_path(args.machine, search_dirs)

    if not machine_dir:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Configuration for machine '{args.machine}' not found.")
        print("        Search directories examined:")
        for sdir in search_dirs:
            print(f"        - {sdir}")
        if available_machines:
            print(f"\n{Fore.YELLOW}Available machines:{Style.RESET_ALL}")
            for m_name, m_path in available_machines.items():
                print(f"        - {m_name}: {m_path}")
        return 1

    source_etc = machine_dir / "etc"
    if not source_etc.is_dir():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Missing 'etc' subfolder in '{machine_dir}': {source_etc}")
        return 1

    # Require root privileges
    ensure_root()

    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Firewalld Deployment (Gentoo) - Machine: {Fore.GREEN}{machine_name}{Fore.CYAN}  {Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Source Path: {Style.DIM}{machine_dir}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")

    print(f"{Fore.CYAN}[1/5]{Style.RESET_ALL} Deploying configuration files...")
    print(f"      Source:      {source_etc}/")
    print(f"      Destination: /etc/")

    try:
        copy_configuration(source_etc, Path("/etc"))
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File copy error: {e}")
        return 1

    print(f"{Fore.CYAN}[2/5]{Style.RESET_ALL} Adjusting permissions and directories...")
    fix_firewalld_permissions(Path("/etc/firewalld"))
    ensure_log_directory(Path("/var/log/firewalld"))

    reload_sysctl_settings(source_etc)
    reload_syslog_service()
    reload_firewalld()

    run_post_deploy_script(machine_dir)

    print(f"{Fore.GREEN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  Deployment completed successfully for '{machine_name}'  {Style.RESET_ALL}")
    print(f"{Fore.GREEN}======================================================{Style.RESET_ALL}")
    return 0


if __name__ == "__main__":
    exit(main())
