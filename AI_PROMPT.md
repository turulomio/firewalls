# 🤖 Guide for Configuring New Machines with AI

This document describes how to use an Artificial Intelligence assistant (Claude, Gemini, ChatGPT, Antigravity, etc.) to generate a complete, production-ready firewalld configuration for any machine or server on Gentoo Linux.

---

## 🏗️ Firewall Architecture Principles

Every configuration generated for this framework follows a strict **Bidirectional Zero-Trust** model:

1. **Default Inbound Denial (*Ingress Filtering* - `zones/public.xml`)**:
   - `target="DROP"` on the zone bound to the physical network interface.
   - No external listening ports are exposed unless the machine operates as a server with authorized services (e.g., SSH restricted by IP, HTTP/HTTPS).
2. **Default Outbound Denial (*Egress Filtering* - `policies/egress-policy.xml`)**:
   - `target="DROP"` from `HOST` to `ANY`.
   - Only strictly required outbound traffic is allowed (HTTP/HTTPS, NTP, DHCP, and restricted DNS).
3. **DNS Anti-Exfiltration Protection (`ipsets/trusted-dns.xml`)**:
   - Outbound DNS lookups are strictly locked down to an IPSet containing approved resolvers (e.g., Cloudflare, Quad9, Google, or local enterprise DNS).
4. **Kernel Hardening and Log Isolation**:
   - Sysctl security parameters (`rp_filter=1`, reject ICMP redirects, log martian packets).
   - Dedicated `syslog-ng` routing sending denied packets to `/var/log/firewalld/denied.log` with rate limiting (`throttle(30)`).
   - `LogDenied=off` by default in `firewalld.conf` to keep the kernel ring buffer (`dmesg`) clean.

---

## 📋 Required Structure for Each Machine

Each machine configuration directory must follow this filesystem structure (e.g., `my-server/`):

```text
<machine_name>/
├── <MACHINE_NAME>.md           # Functional rule documentation
├── post_deploy.sh              # (Optional) Executable post-deployment script
└── etc/
    ├── firewalld/
    │   ├── firewalld.conf
    │   ├── lockdown-whitelist.xml
    │   ├── zones/
    │   │   └── public.xml       # Inbound rules (Ingress)
    │   ├── policies/
    │   │   └── egress-policy.xml# Outbound rules (Egress)
    │   ├── ipsets/
    │   │   └── trusted-dns.xml
    │   └── services/            # Custom XML service definitions (if needed)
    ├── syslog-ng/conf.d/
    │   └── firewalld.conf       # Log isolation into /var/log/firewalld/
    ├── logrotate.d/
    │   └── firewalld            # Log rotation
    └── sysctl.d/
        └── 99-firewall-hardening.conf
```

---

## 💬 Master AI Prompt Template

Copy and paste the following prompt into your AI assistant, filling in the bracketed placeholders `[...]`:

```text
Act as a Senior Systems and Network Security Administrator specializing in firewalld and Gentoo Linux.

I need you to generate a complete firewall configuration for a machine with the following requirements:

- Machine Name: [MACHINE_NAME] (e.g., web-prod-01, dev-laptop, local-nas)
- Role / Purpose: [ROLE] (e.g., Nginx web server with PostgreSQL / Developer workstation / File storage NAS)
- Physical Network Interface: [INTERFACE] (e.g., eth0, eno1, enp4s0)
- Inbound Traffic Allowed (Ingress):
  * [List services or ports, e.g.: SSH (port 22) only from IP 192.168.1.100, HTTP/HTTPS ports 80 and 443 open to all]
- Outbound Traffic Allowed (Egress):
  * [List required outbound connections, e.g.: Standard web (HTTP/HTTPS), DNS restricted to 1.1.1.1 and 8.8.8.8, NTP, backups to backup.mydomain.com on port 2222, etc.]
- Special IPs or Dynamic Hostnames: [Specify if any dynamic DNS or dynamic IPSet resolution is required]

Please generate:
1. '<MACHINE_NAME>.md': Functional Markdown documentation explaining the architecture, ingress/egress rule matrix, port justifications, and test procedures.
2. Necessary firewalld XML files:
   - 'etc/firewalld/zones/public.xml'
   - 'etc/firewalld/policies/egress-policy.xml'
   - 'etc/firewalld/ipsets/trusted-dns.xml' (and any additional custom IPSets)
   - 'etc/firewalld/services/<service>.xml' (if defining non-standard services)
3. 'post_deploy.sh' (if dynamic hostname resolution into an IPSet is needed upon deployment).
4. Suggested probe commands using 'poetry run firewalls_probes' to test both allowed traffic and blocked traffic.

Ensure strict firewalld syntax compliance (target="DROP", valid rich rules, etc.) and compatibility with Gentoo Linux (OpenRC and systemd).
```

---

## 🚀 Deploying the Generated Configuration

Once the configuration files are generated in your private repository or directory (e.g., `~/my-firewalls/<machine_name>/`):

### Option 1: Direct path
```bash
poetry run firewalls_deploy ~/my-firewalls/<machine_name>
```

### Option 2: Using the `--configs-dir` parameter
```bash
poetry run firewalls_deploy <machine_name> --configs-dir ~/my-firewalls
```

### Option 3: Using the environment variable (Recommended)
Add to your shell profile (`~/.bashrc`):
```bash
export FIREWALLS_DIR="$HOME/my-firewalls"
```
Then deploy by name:
```bash
poetry run firewalls_deploy <machine_name>
```

---

## 🔍 Validation and Monitoring

After deploying, validate firewall behavior using the built-in CLI tools:

1. **Live Dashboard**:
   ```bash
   poetry run firewalls_monitor
   ```
2. **Blocked Packets Log Tailing**:
   ```bash
   poetry run firewalls_log_ingress
   poetry run firewalls_log_egress
   ```
3. **Connectivity Probes**:
   ```bash
   # Test allowed outbound HTTP traffic
   poetry run firewalls_probes -H kde.org -p 80

   # Test blocked outbound traffic
   poetry run firewalls_probes -H 1.1.1.1 -p 22 -t 2
   ```
