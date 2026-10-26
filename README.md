# Firewalls Configuration

Centralized management and deployment of `firewalld` configurations for Gentoo Linux systems, packaged and managed with **Poetry**.

---

## 🗂️ Project Structure

The public repository contains the CLI deployment tool, log streaming monitors, connectivity probes, and a clean template configuration (`example/`). Machine-specific configurations (private workstations, production servers) can be maintained in a separate private repository or external directory:

```text
firewalls/
├── pyproject.toml                # Poetry package configuration and dependencies
├── firewalls/                    # Python package containing CLI tools
│   ├── __init__.py
│   ├── cli.py                    # Deployment and service control
│   ├── log_control.py            # Dynamic runtime LogDenied manager
│   ├── monitor.py                # Live real-time dashboard
│   ├── log_ingress.py            # Inbound blocked traffic monitor
│   ├── log_egress.py             # Outbound blocked traffic monitor
│   └── probes.py                 # Network connectivity probes
├── AI_PROMPT.md                  # Master prompt and guide for generating configurations with AI
├── README.md
└── example/                      # Clean machine configuration template
    ├── EXAMPLE.md                # Functional documentation of rules and services
    ├── post_deploy.sh.example    # Optional post-deployment script template
    └── etc/
        ├── firewalld/
        │   ├── firewalld.conf    # Main firewalld configuration
        │   ├── lockdown-whitelist.xml
        │   ├── zones/            # Zone definitions (e.g. public.xml)
        │   ├── services/         # Custom service definitions
        │   ├── ipsets/           # IPSet definitions (e.g. trusted-dns.xml)
        │   ├── icmptypes/        # ICMP type definitions
        │   ├── helpers/          # Connection helpers
        │   └── policies/         # Egress and inter-zone policies (egress-policy.xml)
        ├── syslog-ng/conf.d/     # Log routing into /var/log/firewalld/
        ├── logrotate.d/          # Log rotation configuration
        └── sysctl.d/             # Kernel network hardening (rp_filter, anti-spoofing)
```

---

## 🤖 Generating Machine Configurations with AI

To easily generate a customized firewall configuration using an AI assistant (Claude, Gemini, ChatGPT, Antigravity, etc.), refer to **[AI_PROMPT.md](AI_PROMPT.md)**. It provides a master prompt ready to customize with your machine's role, network interfaces, and allowed services.

---

## 🚀 Usage

All commands are managed through **Poetry**:

### 1. Deploying a Machine Configuration

Machine configurations can reside in any local directory or private git repository:

1. **Direct path** (absolute or relative):
   ```bash
   poetry run firewalls_deploy /path/to/my-firewalls/my_machine
   ```

2. **Using the `--configs-dir` (`-d`) option**:
   ```bash
   poetry run firewalls_deploy my_machine --configs-dir /path/to/my-firewalls
   ```

3. **Using the environment variable** (Recommended):
   ```bash
   export FIREWALLS_DIR="$HOME/my-firewalls"
   poetry run firewalls_deploy my_machine
   ```

4. **Template or repository machines** (also checks `~/.config/firewalls/machines/`):
   ```bash
   poetry run firewalls_deploy example
   ```

### 2. Stopping the `firewalld` Service

```bash
poetry run firewalls_deploy stop
```

### What `firewalls_deploy` Does:
1. Resolves and validates the machine configuration across search paths (`--configs-dir`, `$FIREWALLS_DIR`, `~/.config/firewalls/machines/`, direct path, or local directory).
2. Verifies `root` privileges.
3. Synchronizes `<machine>/etc/` into system `/etc/` preserving permissions, symlinks, and directory structure.
4. Enforces `root:root` ownership and secure permissions (`0750` directories, `0644` files) strictly on files written under `/etc/firewalld`, without modifying parent directory permissions of `/etc`.
5. Re-applies kernel network security parameters from `/etc/sysctl.d/` if present.
6. Configures and restarts/reloads `syslog-ng` to isolate firewall logs into `/var/log/firewalld/`.
7. Reloads `firewalld` rules via `firewall-cmd --reload` (or starts the service with OpenRC / systemd if stopped).
8. Automatically executes the optional `post_deploy.sh` script if present in the machine folder.

---

## 📊 Real-Time Monitoring and Log Analysis

You can monitor, tally, or summarize blocked events with the built-in CLI tools:

```bash
# Monitor blocked incoming connections (Ingress)
poetry run firewalls_log_ingress
poetry run firewalls_log_ingress --summary   # Displays ranked summary

# Monitor blocked outgoing connections (Egress)
poetry run firewalls_log_egress
poetry run firewalls_log_egress --summary    # Displays ranked summary

# Live interactive dashboard (Ingress + Egress with reverse DNS PTR)
poetry run firewalls_monitor                            # Default refresh (3s), top 20 rankings, DNS resolution
poetry run firewalls_monitor -n 2 -p 5                  # Refresh every 2s showing top 5 entries
poetry run firewalls_monitor --no-resolve               # Show raw IP addresses without reverse DNS
```

---

## 🧪 Connectivity Probes (`firewalls_probes`)

The `firewalls_probes` command tests connectivity for both **outgoing (egress)** and **incoming (ingress / listen)** traffic to validate that firewall policies work as expected.

### Command Options

| Parameter | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--host` | `-H` | Target hostname or IP address for outbound probes | `kde.org` |
| `--port` | `-p` | Port number to probe | `1555` |
| `--protocol` | `-proto` | Transport protocol (`tcp` or `udp`) | `tcp` |
| `--timeout` | `-t` | Maximum socket timeout in seconds | `5.0` |
| `--count` | `-c` | Number of probe iterations | `1` |
| `--listen` | `-l` | **Listen Mode (Ingress)**: Opens port locally to wait for incoming connections | Disabled (Outbound) |
| `--bind` | `-b` | Local interface IP address to bind in listen mode | `0.0.0.0` |

---

### Recommended Verification Test Suite

#### 1. Outgoing Permitted Traffic (Egress - Expected Success)

- **Standard Web Traffic (HTTP/HTTPS)**:
  ```bash
  poetry run firewalls_probes -H kde.org -p 80 -proto tcp
  poetry run firewalls_probes -H kde.org -p 443 -proto tcp
  ```
- **Gentoo Portage Sync (rsync)**:
  ```bash
  poetry run firewalls_probes -H rsync.gentoo.org -p 873 -proto tcp
  ```
- **DNS Resolution and Time Sync (NTP)**:
  ```bash
  poetry run firewalls_probes -H 1.1.1.1 -p 53 -proto udp
  poetry run firewalls_probes -H pool.ntp.org -p 123 -proto udp
  ```

#### 2. Outgoing Blocked Traffic (Zero Trust - Expected Drop)

- **Unauthorized outbound port (e.g., TCP 1555)**:
  ```bash
  poetry run firewalls_probes -H kde.org -p 1555 -proto tcp -t 3.0
  ```
  *Expected result*: `[FAILED]` due to `Connection timed out`.

- **Outbound SSH to external host (TCP 22)**:
  ```bash
  poetry run firewalls_probes -H github.com -p 22 -proto tcp -t 3.0
  ```
  *Expected result*: `[FAILED]` (if outbound SSH is not explicitly allowed).

#### 3. Incoming Traffic (Ingress / Listen Mode)

- **Test if a local port accepts incoming connections**:
  ```bash
  # Listens on port 8080 locally for up to 10 seconds waiting for an incoming connection
  poetry run firewalls_probes -l -p 8080 -t 10.0
  ```
- **Listen on local UDP port**:
  ```bash
  poetry run firewalls_probes -l -p 51820 -proto udp -t 10.0
  ```

#### 4. Integrated Verification with Live Monitor

To visually confirm that packet drops are recorded accurately:

1. In one terminal, launch the live dashboard:
   ```bash
   poetry run firewalls_monitor -a
   ```
2. In a second terminal, execute a blocked probe:
   ```bash
   poetry run firewalls_probes -H kde.org -p 1555
   ```
3. Observe the denial registered in real time under the **DENIED OUTGOING (EGRESS)** panel, complete with destination IP and reverse DNS PTR hostname.

---

## 🔒 Log Architecture and `dmesg` Protection

To prevent firewall drop logs from flooding the kernel ring buffer (`dmesg`) and `/var/log/messages`:

1. **On-Demand Drop Logging (`LogDenied=off` by default)**:
   - Traditionally, setting `LogDenied=all` in `firewalld` triggers `printk()` calls at the kernel level via `nf_log_syslog`, polluting `dmesg` with local network broadcast and drop packets.
   - **Dynamic Solution**: In `firewalld.conf`, `LogDenied` is set to `off` permanently. During normal operation, the firewall operates completely silently.
   - **Automatic CLI Activation**:
     - When starting `firewalls_log_ingress`, `firewalls_log_egress`, or `firewalls_monitor` (run as `root`), they dynamically invoke:
       ```bash
       firewall-cmd --set-log-denied=all
       ```
     - Upon exiting or pressing **Ctrl+C**, the signal handler immediately restores:
       ```bash
       firewall-cmd --set-log-denied=off
       ```
     - Kernel drop logging only takes place while an administrator is actively monitoring traffic.

2. **syslog-ng Routing**:
   - `syslog-ng` captures firewall drops and routes them exclusively to `/var/log/firewalld/denied.log`.
   - Includes a `throttle(30)` directive to prevent disk exhaustion from log flooding attacks.
   - `firewalls_deploy` automatically configures `@include "/etc/syslog-ng/conf.d/*.conf"` before catch-all rules, guaranteeing with `flags(final);` that firewall drops do not leak into `/var/log/messages`.

---

## ➕ Adding a New Machine

1. Use the instructions and master prompt in **[AI_PROMPT.md](AI_PROMPT.md)** with an AI assistant, or copy the `example/` template:
   ```bash
   mkdir -p ~/my-firewalls/server1
   cp -r example/* ~/my-firewalls/server1/
   ```
2. Customize the XML files in `~/my-firewalls/server1/etc/firewalld/` for your host.
3. Deploy with:
   ```bash
   poetry run firewalls_deploy ~/my-firewalls/server1
   # Or with FIREWALLS_DIR exported:
   poetry run firewalls_deploy server1
   ```
