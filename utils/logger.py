# Formatting and printing messages in the terminal

import sys
from config import Colors

def log_info(message: str):
    print(f"{Colors.BLEU}[*] {message}{Colors.RESET}")

def log_succes(message: str):
    print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")

def log_warning(message: str):
    print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")

def log_error(message: str):
    print(f"{Colors.RED}[-] {message}{Colors.RESET}")

def log_banner():
    print(r"""
    ███████╗███████╗ ██████╗███████╗ ██████╗██████╗ ██╗██████╗ ████████╗
    ██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝
    ███████╗█████╗  ██║     ███████╗██║     ██████╔╝██║██████╔╝   ██║   
    ╚════██║██╔══╝  ██║     ╚════██║██║     ██╔══██╗██║██╔═══╝    ██║   
    ███████║███████╗╚██████╗███████║╚██████╗██║  ██║██║██║        ██║   
    ╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   
    """)
    print("  [*] SecScript - Advanced CLI Security & Recon Toolkit")
    print("  [*] Developed by: Zineddine Mouri | #BuildInPublic\n")