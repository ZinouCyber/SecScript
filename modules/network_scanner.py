import socket
from concurrent.futures import ThreadPoolExecutor
from utils.logger import log_info, log_succes, log_error, log_warning

def grab_banner(sock):
    """
    Attempts to read the initial response (banner) sent by the service on the open port.
    """
    try:
        sock.send(b'Head / HTTP/1.1\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner
    except Exception:
        return None

def scan_port(target_host, port):
    """
    Scans a specific TCP port on the target host and returns the port if open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)

        result = sock.connect_ex((target_host, port))

        if result == 0:
            banner = grab_banner(sock)
            if banner:
                clean_banner = banner.split('\n')[0]
                log_succes(f"Port {port}: OPEN | Banner: {clean_banner}")
            else:
                log_succes(f"Port {port}: OPEN | Banner: Unknown/No response")

            sock.close()
            return port

        sock.close()
        return None
    except Exception:
        return None

def run_network_scan(target_host, ports=[21, 22, 23, 24, 25, 53, 80, 110, 443, 445, 3306, 8080]):
    """
    Performs a multi-threaded port scan on the target host using ThreadPoolExecutor.
    """
    log_info(f"Starting network scan on target: {target_host}")

    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        log_error(f"Could not resolve hostname: {target_host}")
        return

    open_ports = []
    max_threads = min(10, len(ports))

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, target_host, port): port for port in ports}

        for future in futures:
            try:
                res = future.result()
                if res is not None:
                    if res not in open_ports:
                        open_ports.append(res)
            except Exception:
                pass
    
    if open_ports:
        log_succes(f"Scan complete. Open ports detected: {len(open_ports)} open port(s)!")
    else:
        log_warning("Scan complete. No open ports detected from the given list.")

    return open_ports