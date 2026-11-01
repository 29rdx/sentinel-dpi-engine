#include "dpi_engine.h"
#include <iostream>
#include <iomanip>
#include <vector>

using namespace SentinelDPI;

void printBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║               SENTINEL-DPI • ENTERPRISE THREAT ENGINE            ║
║       Multi-Threaded Deep Packet Inspection & Threat Firewall    ║
║               Engineered by Rupraj Datta (@29rdx)                ║
╚══════════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <input.pcap> <output.pcap> [options]\n\n"
              << "Options:\n"
              << "  --block-ip <ip>       Block specific IP address\n"
              << "  --block-domain <dom>  Block domain name or wildcard (e.g. *.tiktok.com)\n"
              << "  --block-app <app>     Block application (YouTube, Netflix, Facebook, BitTorrent)\n"
              << "  --rules <file>        Load blocking rules from configuration file\n"
              << "  --lbs <n>             Number of LoadBalancer worker threads (default: 2)\n"
              << "  --fps <n>             FastPath worker threads per LB (default: 4)\n\n"
              << "Examples:\n"
              << "  " << prog << " capture.pcap filtered.pcap --block-domain *.adservice.com\n"
              << "  " << prog << " traffic.pcap clean.pcap --block-app BitTorrent\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    printBanner();

    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    std::string input_pcap = argv[1];
    std::string output_pcap = argv[2];

    DPIConfig config;
    config.num_lbs = 2;
    config.fps_per_lb = 4;

    std::vector<std::string> ips_to_block;
    std::vector<std::string> domains_to_block;
    std::vector<std::string> apps_to_block;

    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            ips_to_block.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            domains_to_block.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            apps_to_block.push_back(argv[++i]);
        } else if (arg == "--rules" && i + 1 < argc) {
            config.rules_file = argv[++i];
        } else if (arg == "--lbs" && i + 1 < argc) {
            config.num_lbs = std::stoul(argv[++i]);
        } else if (arg == "--fps" && i + 1 < argc) {
            config.fps_per_lb = std::stoul(argv[++i]);
        }
    }

    DPIEngine engine(config);
    if (!engine.initialize()) {
        std::cerr << "[!] Engine initialization failed.\n";
        return 1;
    }

    for (const auto& ip : ips_to_block) engine.getRuleManager().addBlockedIP(ip);
    for (const auto& dom : domains_to_block) engine.getRuleManager().addBlockedDomain(dom);
    for (const auto& app : apps_to_block) {
        if (app == "YouTube") engine.getRuleManager().addBlockedApp(ApplicationType::YOUTUBE);
        else if (app == "Netflix") engine.getRuleManager().addBlockedApp(ApplicationType::NETFLIX);
        else if (app == "Facebook") engine.getRuleManager().addBlockedApp(ApplicationType::FACEBOOK);
        else if (app == "BitTorrent") engine.getRuleManager().addBlockedApp(ApplicationType::BITTORRENT);
    }

    std::cout << "[*] Loading input stream: " << input_pcap << "\n";
    std::cout << "[*] Active Worker Pool:   " << config.num_lbs << " LoadBalancers, " 
              << (config.num_lbs * config.fps_per_lb) << " FastPath workers\n";
    std::cout << "[*] Active Rules:         " << engine.getRuleManager().ipRuleCount() << " IPs, "
              << engine.getRuleManager().domainRuleCount() << " Domains, "
              << engine.getRuleManager().appRuleCount() << " Apps\n";
    std::cout << "[*] Processing packets in parallel...\n";

    if (!engine.processFile(input_pcap, output_pcap)) {
        return 1;
    }

    DPIStats stats = engine.getStats();
    ThreatDetector::ThreatReport threats = engine.getThreatDetector().getReport();

    std::cout << "\n═══════════════════ EXECUTION SUMMARY ═══════════════════\n";
    std::cout << "  Total Packets Analyzed:   " << stats.total_packets_read << "\n";
    std::cout << "  Packets Forwarded:        " << stats.total_packets_forwarded << " (Clean)\n";
    std::cout << "  Packets Dropped:          " << stats.total_packets_dropped << " (Filtered / Neutralized)\n";
    std::cout << "  Elapsed Time:             " << std::fixed << std::setprecision(4) << stats.elapsed_seconds << " seconds\n";
    std::cout << "  Throughput Rate:          " << std::setprecision(2) << (stats.mpps * 1e6) << " packets/sec (" 
              << stats.mbps << " Mbps)\n";
    std::cout << "\n════════════════════ THREAT TELEMETRY ════════════════════\n";
    std::cout << "  TCP SYN Floods Blocked:   " << threats.syn_floods << "\n";
    std::cout << "  TCP Xmas Scans Neutralized:" << threats.xmas_scans << "\n";
    std::cout << "  TCP NULL Scans Dropped:   " << threats.null_scans << "\n";
    std::cout << "  DNS Tunneling Exfiltration:" << threats.dns_tunnels << "\n";
    std::cout << "  Malicious RCE Signatures: " << threats.malicious_signatures << "\n";
    std::cout << "  Total Security Incidents: " << threats.total_threats() << "\n";
    std::cout << "══════════════════════════════════════════════════════════\n";
    std::cout << "[✓] Clean output written to: " << output_pcap << "\n\n";

    return 0;
}
