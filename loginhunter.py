import requests
import argparse
from bs4 import BeautifulSoup

def load_file(filename):
    with open(filename, "r") as f:
        return [line.strip().rstrip("/") for line in f if line.strip()]

def get_site_headers(domain):
    try:
        r = requests.get(domain, timeout=5)
        return dict(r.request.headers)
    except requests.RequestException:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/117.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close"
        }

def scan(domains_file, logins_file, results_only=False):
    domains = load_file(domains_file)
    login_paths = load_file(logins_file)
    keywords = ["username", "user", "email", "password", "pass", "login", "signin", "logon", "auth"]

    print("[*] Starting scan...\n")

    for domain in domains:
        headers = get_site_headers(domain)
        domain_has_results = False

        for path in login_paths:
            url = f"{domain}{path}"
            try:
                r = requests.get(url, timeout=5, headers=headers)
                if r.status_code == 200:
                    found_words = []
                    soup = BeautifulSoup(r.text.lower(), "html.parser")
                    page_text = soup.get_text(separator=" ")

                    for kw in keywords:
                        if kw in page_text:
                            found_words.append(kw)

                    if found_words:
                        if not domain_has_results:
                            print(f"--- Scanning: {domain} ---")
                            domain_has_results = True
                        print(f"[+] {url} -> {found_words}")
                    elif not results_only:
                        if not domain_has_results:
                            print(f"--- Scanning: {domain} ---")
                            domain_has_results = True
                        print(f"[?] {url} -> Page exists but no login keywords found")

            except requests.RequestException:
                if not results_only:
                    if not domain_has_results:
                        print(f"--- Scanning: {domain} ---")
                        domain_has_results = True
                    print(f"[!] Could not connect to {url}")

        if domain_has_results:
            print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LoginHunter - Find potential login pages on target domains")
    parser.add_argument("-ld", "--domains", required=True, help="File with list of domains")
    parser.add_argument("-l", "--logins", required=True, help="File with list of login paths")
    parser.add_argument("-r", "--results-only", action="store_true", help="Show only pages with login keywords found")

    args = parser.parse_args()
    scan(args.domains, args.logins, args.results_only)
