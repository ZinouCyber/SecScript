import requests
from urllib.parse import urlparse

class WebTester:
    def __init__(self, target_url):
        clean_target = target_url.replace("https://", "").replace("http://", "").rstrip("/")
        self.target_url = "https://" + clean_target

        self.results = {
            "target": self.target_url,
            "security_headers": [],
            "found_paths": [],
            "server_info": ""
        }

    def check_headers(self):
        print(f"[*] Analyzing Security Headers for {self.target_url}...")
        try:
            response = requests.get(self.target_url, timeout=5, allow_redirects=True)
            headers = response.headers

            self.results["server_info"] = headers.get("Server", "Unknown")

            security_headers = [
                "X-Frame-Options",
                "X-XSS-Protection",
                "X-Content-Type-Options",
                "Strict-Transport-Security",
                "Content-Security-Policy"
            ]

            for header in security_headers:
                if header in headers:
                    self.results["security_headers"].append({
                        "header": header,
                        "status": "Present",
                        "value": headers[header]
                    })
                else:
                    self.results["security_headers"].append({
                        "header": header,
                        "status": "Missing",
                        "recommendation": "Consider implementing this header for better security."
                    })
        except Exception as e:
            print(f"[-] Error connecting to target for headers check: {e}")

    def scan_sensitive_paths(self):
        print(f"[*] Scanning for sensitive paths & directories...")
        common_paths = [
            "/admin",
            "/login",
            "/administrator",
            "/robots.txt",
            "/sitemap.xml",
            "/.git/HEAD",
            "/config.env",
            "/backup.zip",
            "/api/v1/"
        ]

        for path in common_paths:
            url = self.target_url.rstrip("/") + path
            try:
                response = requests.get(url, timeout=3, allow_redirects=False)
                if response.status_code == 200:
                    self.results["found_paths"].append({"path": path, "code": 200, "status": "Accessible"})
                elif response.status_code == 403:
                    self.results["found_paths"].append({"path": path, "code": 403, "status": "Forbidden (Exists)"})
            except Exception:
                pass

    def run_web_tests(self):
        print(f"[+] Starting Web Testing Suite on: {self.target_url}")
        self.check_headers()
        self.scan_sensitive_paths()
        return self.results