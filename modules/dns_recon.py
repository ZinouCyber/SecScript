import dns.resolver
import time
from rich.console import Console
from rich.table import Table
from utils.logger import log_info, log_succes, log_error, log_warning

console = Console()

DNS_RECORDS = ["A", "AAAA", "CNAME", "MX", "TXT", "SOA"]

def run_dns_recon(domain):
    """
    Performs comprehensive DNS Reconnaissance on the target domain using dnspython and rich tables
    and a text summary for AI analysis.
    """
    log_info(f"[*]Starting DNS Reconnaissance for domain: {domain}")

    resolver = dns.resolver.Resolver()

    table = Table(title=f"DNS Reconnaissance Results for {domain}")
    table.add_column("Record Type", style="cyan", no_wrap=True)
    table.add_column("Result", style="magenta")
    table.add_column("Response Time (ms)", style="green")

    found_any = False 
    ai_summary_lines = []

    for rtype in DNS_RECORDS:
        start_time = time.time()
        try:
            answers = resolver.resolve(domain, rtype)
            elapsed_time = round((time.time() - start_time) * 1000, 2)

            results_list = [str(rdata) for rdata in answers]
            results_str = "\n".join(results_list)

            table.add_row(rtype, results_str, f"{elapsed_time} ms")
            found_any = True

            ai_summary_lines.append(f"Record {rtype}: {results_str}")

        except dns.resolver.NoAnswer:
            table.add_row(rtype, "No record found.", "-")
        except dns.resolver.NXDOMAIN:
            log_error(f"Domain {domain} does not exist.")
            return
        except Exception as e:
            table.add_row(rtype, f"Error: {type(e).__name__}", "-")

    if found_any:
       console.print(table)
       log_succes(f"[+]DNS Reconnaissance completed for {domain}")
    else:
        log_warning(f"[-]No DNS records could be retrieved for {domain}") 

    return "\n".join(ai_summary_lines)