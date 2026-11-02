# Sentinel DPI Engine Architecture

\`\`\`
[NIC / PCAP] ---> [FastPathRing] ---> [5-Tuple Load Balancer]
                                              |
     +-------------------+--------------------+--------------------+
     |                   |                    |                    |
[DPI Parser]       [DNS Tunneling]       [TLS JA3 Hash]       [HTTP/2 Frames]
  (VLAN/IPv6)     (Shannon Entropy)     (Client Hello)       (RST Detection)
     |                   |                    |                    |
     +-------------------+--------------------+--------------------+
                                 |
                     [Threat Mitigation / Alerts]
\`\`\`
