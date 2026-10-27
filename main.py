#!/usr/bin/env python3

import argparse
from utils.logger import log_banner, log_info, log_succes, log_warning, log_error
from modules.network_scanner import run_network_scan
from modules.dns_recon import run_dns_recon
from modules.ai_analyzer import analyze_with_ai
from modules.report_exporter import save_security_report
from modules.subdomain_scanner import run_subdomain_enum
from modules.vuln_scanner import VulnerabilityScanner

def main():
    log_banner()

    # CLI arguments
    parser = argparse.ArgumentParser(description="AI-Driven offensive Python Toolkit - Network Recon")
    parser.add_argument("-t", "--target", dest="target", help="Target IP address for Port Scan")
    parser.add_argument("-d", "--domain", dest="domain", help="Target Domain for DNS Reconnaissance")
    parser.add_argument("-s", "--subdomain", dest="subdomain", help="Target Domain for Subdomain Enumeration")
    parser.add_argument("-v", "--vuln", action="store_true", help="Run Vulnerability Scanner checks")
    parser.add_argument("-o", "--output", action="store_true", help="Automatically save the AI report to a markdown file")
    parser.add_argument("-r", "--report", action="store_true", help="Generate AI security analysis and save report")
    args = parser.parse_args()

    if not args.target and not args.domain and not args.subdomain:
        log_warning("No action specified! Use -t for Port Scan, or -d for DNS Recon, or -s for Subdomain Enum, or -v for Vuln Scan.")
        parser.print_help()
        return

    log_info("Initializing toolkit modules...")

    scan_details = ""
    target_name = ""
    scan_type = ""

    if args.target:
        open_ports_summary = run_network_scan(args.target)
        scan_details = f"Target IP: {args.target}\nDiscovered open ports and banners: {open_ports_summary}"
        target_name = args.target
        scan_type = "PortScan"

    elif args.target and args.vuln:
        log_info(f"[*] Running Vulnerability Scanner on {args.target}...")
        scanner = VulnerabilityScanner(args.target)
        vuln_results = scanner.run_all_checks()

        scan_details = f"Target IP: {args.target}\nDiscovered Vulnerabilities:\n"
        if vuln_results:
            for v in vuln_results:
                scan_details += f"- Port {v['port']} ({v['service']}): {v['issue']} [Severity: {v['severity']}]\n"
                print(f" [Severity: {v['severity']}] {v['service']} -> {v['issue']}")
        else:
            scan_details += "No common vulnerabilities found.\n"
            print("[-] No common vulnerabilities found.")

        target_name = args.target
        scan_type = "VulnScan"

    elif args.domain:
       dns_results_text = run_dns_recon(args.domain)
       if dns_results_text:
           dns_details = f"Target Domain: {args.domain}\nDNS Records:\n{dns_results_text}"
           target_name = args.domain
           scan_type = "DNSRecon"

    elif args.subdomain:
        sub_results_text = run_subdomain_enum(args.subdomain)
        if sub_results_text:
            sub_details = f"Target Domain for Subdomains: {args.subdomain}\nActive Subdomain:\n{sub_results_text}"
            target_name = args.subdomain
            scan_type ="SubdomainEnum"

    if args.report and scan_details:
            log_info("\n[*] Generating AI Security Analysis Report for {target_name}...")
            ai_report = analyze_with_ai(scan_details)
            if ai_report:
                print(ai_report)
                if args.output:
                    save_security_report(target_name, ai_report, scan_type=scan_type)
            else:
                log_warning("Could not generate AI report. Make sure qwen is running locally.")
    elif not args.report and scan_details:
        log_info("[*] Scan completed. Use -r or --report if you want to generate an AI security report.")

if __name__ == "__main__":
    main()