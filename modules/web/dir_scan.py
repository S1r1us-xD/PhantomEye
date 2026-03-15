import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import OutputFormatter
from config.settings import Settings
from config.wordlists import Wordlists

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DirScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.base_url = target if target.startswith("http") else f"http://{target}"
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = Settings.USER_AGENTS[0]
        self.session.verify = False
        self.threads  = Settings.MAX_THREADS

    def _get(self, url):
        try:
            return self.session.get(
                url, timeout=Settings.READ_TIMEOUT,
                verify=False, allow_redirects=False,
            )
        except Exception:
            return None

    def directory_bruteforce(self, wordlist_path=None):
        self.logger.section("Directory & File Brute-force")
        wordlist = Wordlists.load(wordlist_path)
        self.logger.info(f"Testing {len(wordlist)} paths on {self.base_url}")
        found = []

        def check(path):
            r = self._get(f"{self.base_url}/{path.lstrip('/')}")
            if r and r.status_code not in [404, 400, 410]:
                return path, r.status_code, len(r.content)
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(check, p): p for p in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, code, size = result
                    found.append(result)
                    sev = "high" if code == 200 else "medium"
                    url = f"{self.base_url}/{path.lstrip('/')}"
                    self.logger.finding(sev, f"[{code}] {url}  ({size}b)")
                    self.findings.append(OutputFormatter.finding(
                        "web/dirs", sev.upper(),
                        f"Accessible Path: /{path}",
                        f"HTTP {code} on {url}",
                        evidence=f"Status: {code}, Size: {size}b",
                        recommendation="Review and restrict access to sensitive paths.",
                    ))

        self.logger.info(f"Brute-force complete — {len(found)} path(s) found")
        return found

    def dangerous_file_scan(self):
        self.logger.section("Dangerous File Scan")
        found = []
        for fname in Settings.DANGEROUS_FILES:
            r = self._get(f"{self.base_url}/{fname}")
            if r and r.status_code == 200:
                self.logger.finding("high", f"Dangerous file accessible: /{fname}")
                found.append(fname)
                self.findings.append(OutputFormatter.finding(
                    "web/dirs", "HIGH",
                    f"Dangerous File Exposed: {fname}",
                    f"Sensitive file is publicly accessible.",
                    evidence=r.text[:200] if r.text else "",
                    recommendation=f"Remove or restrict access to {fname}.",
                ))
        if not found:
            self.logger.info("No dangerous files found")
        return found

    def run(self):
        self.directory_bruteforce()
        self.dangerous_file_scan()
