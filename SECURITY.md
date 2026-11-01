# 🛡️ Sentinel DPI Security Architecture & Memory Safety Guidelines

## 1. Memory Safety Standards
Because `sentinel-dpi` processes untrusted raw network frames directly from L2/L3 capture drivers, strict memory safety controls are enforced:
- **Defensive Bounds Checking**: Every variable-length header offset (802.1Q VLAN, IPv6 extension headers, TCP options, TLS ClientHello session/extension vectors, and DNS labels) validates remaining payload capacity before dereferencing.
- **Buffer Zero-Copy**: Raw payload views use `std::string_view` and `const uint8_t*` slices guarded by explicit length descriptors.
- **Sanitizers**: Automated CI builds compile with `-fsanitize=address,undefined` to guarantee zero heap overflows or use-after-free conditions.

---

## 2. Threat Vector Classification & Heuristics

| Threat Class | Signature / Pattern | Sentinel DPI Mitigation |
| :--- | :--- | :--- |
| **Xmas Port Scan** | `FIN + PSH + URG` flags active simultaneously | Immediately flagged as `CRITICAL_THREAT`; packet dropped; origin IP quarantined. |
| **NULL Stealth Scan** | TCP header flags equal `0x00` | Flagged as reconnaissance attack; dropped. |
| **Remote Code Execution (RCE)** | Unencrypted payload matching `/bin/sh`, `/bin/bash` strings | Deep payload inspector triggers alert; terminates TCP session with RST injection. |
| **DNS Tunneling / Exfiltration** | Subdomain Shannon entropy $H > 3.8$ with high query frequency | Flagged for algorithmic entropy anomaly; domain added to dynamic blocklist. |

---

## 3. Vulnerability Reporting
Please report security bugs to **`dattarupraj@gmail.com`**.
