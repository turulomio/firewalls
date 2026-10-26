# Firewall Configuration: [MACHINE_NAME]

## 📋 Machine Overview
- **Hostname / Identifier**: `[MACHINE_NAME]` (e.g., `web-server`, `dev-laptop`)
- **Role**: [Workstation / Web Server / NAS / Local Router]
- **Network Interface**: `[INTERFACE]` (e.g., `eth0`, `eno1`, `wlan0`)
- **Operating System**: Gentoo Linux
- **Firewall Backend**: `nftables`
- **Default Zone**: `public` (bound to `[INTERFACE]`, target `DROP`)
- **Egress Policy**: `egress-policy` (target `DROP`, `HOST` -> `ANY`)
- **Security Model**: **Dual Default Deny (Bidirectional Zero Trust)**.
  - **Ingress**: No open ports by default unless explicitly permitted. Unsolicited incoming packets are discarded (`DROP`).
  - **Egress**: Only explicitly authorized outgoing connections are allowed (strict DNS, NTP, HTTP/HTTPS, etc.). Any other outbound traffic is blocked and dropped (`DROP`).

---

## 🛡️ Active Rules and Functional Behavior

### 1. Outgoing Traffic (*Egress Filtering* - `policies/egress-policy.xml`)
- **Policy**: **DEFAULT DENY (Target `DROP`)**.
- **Logging**: Dropped connections logged to `/var/log/firewalld/denied.log`.

| Service / Port | Protocol | Status | Functional Justification |
| :--- | :--- | :--- | :--- |
| `http` | TCP (80) | **Allowed** | Standard web browsing and package repository downloads. |
| `https` | TCP (443) / UDP (443) | **Allowed** | Secure web browsing and HTTP/3 (QUIC). |
| `dns` (Restricted) | UDP / TCP (53) | **Allowed (IPSet)** | DNS queries restricted to the `trusted-dns` IPSet to prevent DNS tunneling and data exfiltration. |
| `ntp` | UDP (123) | **Allowed** | System time synchronization. |
| `dhcp` | UDP (67, 68) | **Allowed** | Local network IPv4 DHCP lease renewal (if applicable). |
| `rsync` | TCP (873) | **Optional** | Gentoo Portage tree synchronization (`emerge --sync`). |
| **Anti-Spoofing** | `127.0.0.0/8` outbound | **DENIED (DROP)** | Immediate drop for packets with spoofed loopback source addresses. |
| **Any other outbound** | All | **DENIED (DROP)** | Strict drop for uncatalogued outbound traffic. |

### 2. Incoming Traffic (*Ingress Filtering* - `zones/public.xml`)
- **Zone**: `public` (Target: `DROP`, Interface: `[INTERFACE]`)
- **Policy**: **DEFAULT DENY (Target `DROP`)**.

| Service / Port | Protocol | Status | Functional Justification |
| :--- | :--- | :--- | :--- |
| `ssh` | TCP (22) | **Configurable** | Disabled by default on workstations; restrict to administration IPs on servers. |
| **Any other inbound** | All | **DENIED (DROP)** | Absolute drop of all unsolicited incoming traffic. |

---

## 🔒 Security Mechanisms and System Hardening

1. **D-Bus Lockdown (`Lockdown=yes`)**: Protects `firewalld` so non-privileged processes cannot alter rules via D-Bus.
2. **Strict DNS Filtering (`trusted-dns`)**: Prevents malware from querying arbitrary rogue DNS resolvers.
3. **Kernel Hardening (`sysctl.d/99-firewall-hardening.conf`)**:
   - `rp_filter = 1` (Strict IPv4 reverse path filtering / anti-spoofing).
   - `accept_redirects = 0` (Prevention of ICMP redirect attacks).
   - `log_martians = 1` (Kernel logging of martian / impossible source addresses).
4. **Dedicated Logging (`syslog-ng` + `logrotate`)**:
   - Denied events routed to `/var/log/firewalld/denied.log` with rate limiting (`throttle(30)`).
   - Keeps `/var/log/messages` and `dmesg` clean and noise-free.
