# xss_scanner.py
import requests
import pandas as pd
from tqdm import tqdm
from pathlib import Path
import json
from bs4 import BeautifulSoup
from utils import log
from urllib.parse import urljoin
from dotenv import load_dotenv
import os

load_dotenv()

USER = os.getenv("WS_USERNAME", "admin")
PASS = os.getenv("WS_PASSWORD", "password")

RESULTS_DIR = Path.cwd() / "results"
CRAWL_FILE = RESULTS_DIR / "week2_crawl_results.json"
XSS_OUTPUT = RESULTS_DIR / "week4_xssscan_results.csv"

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<svg/onload=alert('XSS')>",
    "<img src=x onerror=alert(1)>"
]


# -----------------------------
# LOGIN (same reliable method as crawler)
# -----------------------------
def login(session, target):
    login_page = urljoin(target, "/login.php")
    res = session.get(login_page)
    soup = BeautifulSoup(res.text, "lxml")

    # extract CSRF token
    token = ""
    token_field = None
    for inp in soup.find_all("input"):
        name = inp.get("name", "")
        if "token" in name:
            token_field = name
            token = inp.get("value", "")
            break

    payload = {
        "username": USER,
        "password": PASS,
        "Login": "Login",
        "submitted": "1"
    }
    if token_field:
        payload[token_field] = token

    post = session.post(login_page, data=payload)

    if "Logout" in post.text:
        log(2, "Login successful (XSS scanner session)")
    else:
        log(2, "Login FAILED for XSS module!")

    return session


def is_reflected(text, payload):
    return payload in text


def run_xss(target="http://localhost"):
    log(1, "Running DVWA XSS Scanner (Authenticated Mode)")

    # load Week 2 data
    if not CRAWL_FILE.exists():
        log(3, "Week 2 results missing!")
        return

    with open(CRAWL_FILE, "r", encoding="utf-8") as f:
        pages = json.load(f)

    # create session and login
    session = requests.Session()
    session = login(session, target)

    # known endpoints
    xss_r = target + "/vulnerabilities/xss_r/"
    xss_s = target + "/vulnerabilities/xss_s/"
    xss_d = target + "/vulnerabilities/xss_d/"

    test_urls = {xss_r, xss_s, xss_d}

    for p in pages:
        if "xss" in p["url"]:
            test_urls.add(p["url"])

    test_urls = list(test_urls)
    log(4, f"Total XSS endpoints to test: {len(test_urls)}")

    findings = []

    # -----------------------------
    # TEST EACH URL
    # -----------------------------
    for url in tqdm(test_urls, desc="Testing XSS"):

        # REFLECTED XSS
        if "xss_r" in url:
            for payload in XSS_PAYLOADS:
                test_url = f"{url}?name={payload}&Submit=Submit"
                try:
                    r = session.get(test_url, timeout=5)
                    if is_reflected(r.text, payload):
                        log(4, f"VULNERABLE (Reflected) → {test_url}")
                        findings.append([
                            "XSS (Reflected)",
                            test_url,
                            "name",
                            payload,
                            "Payload reflected in response",
                            "High"
                        ])
                        break
                except:
                    pass

        # STORED XSS
        if "xss_s" in url:
            for payload in XSS_PAYLOADS:
                try:
                    post_data = {
                        "txtName": payload,
                        "mtxMessage": payload,
                        "btnSign": "Sign Guestbook"
                    }
                    # submit payload
                    session.post(url, data=post_data, timeout=5)
                    # reload page to check stored
                    r2 = session.get(url, timeout=5)
                    if is_reflected(r2.text, payload):
                        log(4, f"VULNERABLE (Stored) → {url}")
                        findings.append([
                            "XSS (Stored)",
                            url,
                            "txtName/mtxMessage",
                            payload,
                            "Stored payload visible",
                            "High"
                        ])
                        break
                except:
                    pass

        # DOM XSS
        if "xss_d" in url:
            try:
                r = session.get(url, timeout=5)
                html = r.text.lower()
                dom_sinks = ["document.write", "innerhtml", "location.hash"]
                if any(s in html for s in dom_sinks):
                    log(4, f"VULNERABLE (DOM) → {url}")
                    findings.append([
                        "XSS (DOM)",
                        url,
                        "N/A",
                        "N/A",
                        "Dangerous DOM sink detected",
                        "Medium"
                    ])
            except:
                pass

    # -----------------------------
    # SAVE RESULTS
    # -----------------------------
    df = pd.DataFrame(findings, columns=[
        "module", "endpoint", "parameter", "payload", "evidence", "severity"
    ])
    df.to_csv(XSS_OUTPUT, index=False)

    log(5, f"XSS scan complete. Results saved to: {XSS_OUTPUT}")
    print()
