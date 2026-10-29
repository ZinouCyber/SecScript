import socket 

class VulnerabilityScanner:
    def __init__(self, target_ip):
      self.target_ip = target_ip
      self.vulnerabilities = []

    def check_web_services(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((self.target_ip, 80)) == 0:
                self.vulnerabilities.append({
                    "port": 80,
                    "service": "HTTP (80/tcp)",
                    "severity": "INFO/LOW",
                    "issue": "HTTP Web Service Open",
                    "description": "Standard unencrypted web server port is open."
                })
            s.close()
        except Exception:
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((self.target_ip, 443)) == 0:
                self.vulnerabilities.append({
                    "port": 443,
                    "service": "HTTPS (443/tcp)",
                    "severity": "INFO/LOW",
                    "issue": "HTTPS Web Service Open",
                    "description": "Secure encrypted web server port is open."
                })
            s.close()
        except Exception:
            pass

    def check_nfs_share(self):
        try:
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           s.settimeout(2)
           results = s.connect_ex((self.target_ip, 2049))
           if results == 0:
               self.vulnerabilities.append({
                   "port": 2049,
                   "service": "NFS (2049/tcp)",
                   "severity": "MEDIUM",
                   "issue": "NFS Shares World Readable / Accessible",
                   "description": "The NFS service is open. Unauthenticated access may be possible." 
               })
           s.close()
        except Exception as e:
            pass

    def check_ftp_anonymous(self):
        try:
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           s.settimeout(2)
           if s.connect_ex((self.target_ip, 21)) == 0:
               banner = s.recv(1024).decode('utf-8', errors='ignore')
               self.vulnerabilities.append({
                   "port": 21,
                   "service": "FTP (21/tcp)",
                   "severity": "INFO/LOW",
                   "issue": "FTP Service Open",
                   "desciption": f"FTP banner detected: {banner.strip()}"
               })
           s.close()
        except Exception:
            pass

    def check_ssh_banner(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((self.target_ip, 22)) == 0:
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                self.vulnerabilities.append({
                    "port": 22,
                    "service": "SSH (22/tcp)",
                    "severity": "INFO/LOW",
                    "issue": "SSH Service Open",
                    "description": f"SSH banner detected: {banner.strip()}"
                })
            s.close()
        except Exception:
            pass

    def check_telnet(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((self.target_ip, 23)) == 0:
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                self.vulnerabilities.append({
                    "port": 23,
                    "service": "Telnet (23/tcp)",
                    "severity": "HIGH",
                    "issue": "Unencrypted Telnet Service Open",
                    "description": "Telnet transmits data in plaintext and should be disabled."
                })
            s.close()
        except Exception:
            pass

    def check_smb(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((self.target_ip, 445)) == 0:
                self.vulnerabilities.append({
                    "port": 445,
                    "service": "SMB (445/tcp)",
                    "severity": "MEDIUM",
                    "issue": "SMB Service Exposed",
                    "description": "SMB service is open and might be vulnerable to enumeration or exploits."
                })
            s.close()
        except Exception:
            pass 

    def run_all_checks(self):
        print(f"[*] Starting Vulnerability Scannig on {self.target_ip}...")
        self.check_nfs_share()
        self.check_ftp_anonymous()
        self.check_ssh_banner()
        self.check_telnet()
        self.check_web_services()
        self.check_smb()
        return self.vulnerabilities