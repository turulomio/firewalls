# Firewalls Project (firewalld on Gentoo Linux)

## 📌 Project Purpose
This project centralizes and manages `firewalld` configurations for machines running **Gentoo Linux**. It allows firewall rules to be version-controlled in git and easily deployed to target systems via a Python CLI tool managed with **Poetry**.

---

## 🗂️ Repository Structure

- The public repository centralizes the CLI tools, monitors, probes, and a clean baseline template (`example/`).
- Specific (private) machine configurations reside in a separate private repository or external directory (managed via `FIREWALLS_DIR`, `--configs-dir`, or direct paths).
- Inside each machine configuration directory:
  - `<MACHINE_NAME>.md` (e.g., `EXAMPLE.md` or `<MACHINE>.md`): Uppercase Markdown document describing the functional security policy, active rules, and authorized services.
  - `post_deploy.sh` *(Optional)*: Executable shell script run automatically after machine deployment finishes (e.g., to dynamically resolve hostnames into IPSets).
  - An `etc/` subdirectory mirroring the real structure copied to `/etc/` on the destination host:
  ```text
  <machine_name>/
  ├── <MACHINE_NAME>.md
  ├── post_deploy.sh
  └── etc/
      ├── firewalld/
      │   ├── firewalld.conf
      │   ├── lockdown-whitelist.xml
      │   ├── zones/
      │   ├── services/
      │   ├── ipsets/
      │   ├── icmptypes/
      │   ├── helpers/
      │   └── policies/
      ├── syslog-ng/conf.d/
      ├── logrotate.d/
      └── sysctl.d/
  ```
- **Python Source Code**:
  - `firewalls/`: Python package containing CLI logic (`firewalls/cli.py`), runtime log manager (`firewalls/log_control.py`), inbound traffic monitor (`firewalls/log_ingress.py`), outbound traffic monitor (`firewalls/log_egress.py`), live denial dashboard (`firewalls/monitor.py`), and connectivity probes (`firewalls/probes.py`).
  - `AI_PROMPT.md`: Guide and master prompt for generating new machine configurations with Artificial Intelligence.
  - `pyproject.toml`: Project configuration, dependencies, and console scripts (`firewalls_deploy`, `firewalls_log_ingress`, `firewalls_log_egress`, `firewalls_monitor`, `firewalls_probes`) managed with **Poetry**.

---

## 🛠️ Tools and Conventions

1. **Dependency Management and Packaging**:
   - Managed with **Poetry** (`pyproject.toml`).
   - Terminal styling with `colorama`.
   - Available console commands registered in Poetry:
     - `poetry run firewalls_deploy <machine_name_or_path> [-d CONFIGS_DIR]`
     - `poetry run firewalls_log_ingress`
     - `poetry run firewalls_log_egress`
     - `poetry run firewalls_monitor [-n INTERVAL] [-p TOP]`
     - `poetry run firewalls_probes [-H HOST] [-p PORT] [-proto {tcp,udp}] [-t TIMEOUT] [-c COUNT] [-l]`

2. **Target Operating System**:
   - **Gentoo Linux**.
   - Supports service management with either **OpenRC** (`rc-service firewalld <action>`) or **systemd** (`systemctl <action> firewalld`).

3. **Deployment Rules (`deploy`)**:
   - **Mandatory Parameter**: Machine name or filesystem path to deploy.
   - **Path Resolution**: Looks in `--configs-dir`, `$FIREWALLS_DIR`, `~/.config/firewalls/machines/`, repository root, or direct path.
   - **Execution & Privileges**: Must be executed directly with `root` privileges. No internal `sudo` elevation logic.
   - **File Copy**: Recursively synchronizes `<machine>/etc/` to `/etc/` preserving attributes and links.
   - **File Permissions**: **Parent `/etc` permissions are never modified**. Enforces `root:root` ownership and standard permissions (`0750` directories, `0644` files) strictly on items written under `/etc/firewalld`.
   - **Automatic Reload**: If `firewalld` is active, executes `firewall-cmd --reload`. If stopped, attempts to start it via the system service manager.

4. **Logging Configuration (`syslog-ng`)**:
   - Requires inclusion of `@include "/etc/syslog-ng/conf.d/*.conf"` in `/etc/syslog-ng/syslog-ng.conf` before catch-all destinations.

---

## ➕ Adding a New Machine
To configure a new machine:
1. Use the instructions and master prompt in `AI_PROMPT.md` to generate the configuration from the `example/` template.
2. Store the machine folder in a private repository or external directory (e.g. `~/my-firewalls/<new_machine>`).
3. Deploy with: `poetry run firewalls_deploy ~/my-firewalls/<new_machine>` (or by setting `export FIREWALLS_DIR=~/my-firewalls`).
