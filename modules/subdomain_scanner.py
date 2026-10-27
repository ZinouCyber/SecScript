import socket
from rich.table import Table
from rich.console import Console

console = Console()

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "web",
    "server", "firewall", "dns", "ns2", "vpn", "ix", "mx", "loadbalancer",
    "admin", "api", "dev", "test", "staging", "dashboard", "portal", "shop"
]

def run_subdomain_enum(domain):
    """
    Performs subdomain enumeration on the target domain and returns a rich table and summary.
    """
    print(f"[*] Starting Subdomain Enumeration for domain: {domain}")

    table = Table(title=f"Subdomain Enumeration Results for {domain}")
    table.add_column("Subdomain", style="cyan", no_wrap=True)
    table.add_column("IP Address", style="magenta")
    table.add_column("Status", style="green")

    found_any = False
    ai_summary_lines = []

    for sub in COMMON_SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        try:
            target_ip = socket.gethostbyname(full_domain)
            table.add_row(full_domain, target_ip, "Active")
            found_any = True
            ai_summary_lines.append(f"Subdomain: {full_domain} resolves to IP: {target_ip}")
        except socket.gaierror:
            continue
        except Exception as e:
            continue

    if found_any:
        console.print(table)
        print(f"[+] Subdomain Enumeration completed for {domain}")
    else:
        print(f"[-] No active subdomains found for {domain}")

    return "\n".join(ai_summary_lines)