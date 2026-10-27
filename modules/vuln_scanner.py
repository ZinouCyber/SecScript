import socket 

class VulnerabilityScanner:
    def __init__(self, target_ip):
      self.target_ip = target_ip
      self.vulnerabilities = []

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

    def run_all_checks(self):
        print(f"[*] Starting Vulnerability Scannig on {self.target_ip}...")
        self.check_nfs_share()
        self.check_ftp_anonymous()
        return self.vulnerabilities

  