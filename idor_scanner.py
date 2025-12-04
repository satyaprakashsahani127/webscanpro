# idor_scanner.py
import requests
import pandas as pd
from pathlib import Path
from utils import log
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os

load_dotenv()

USER = os.getenv("WS_USERNAME", "admin")
PASS = os.getenv("WS_PASSWORD", "password")

RESULTS_DIR = Path.cwd() / "results"
IDOR_OUTPUT = RESULTS_DIR / "week6_idor_results.csv"


# --------------------------
# LOGIN (same as Week 2 & 4)
# --------------------------
def login(session, target):
    login_page = urljoin(target, "/login.php")
    res = session.get(login_page)
    soup = BeautifulSoup(res.text, "lxml")

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
        "Login": "Login"
    }
    if token_field:
        payload[token_field] = token

    post = session.post(login_page, data=payload)

    if "Logout" in post.text:
        log(2, "Session login successful (IDOR scanner)")
    else:
        log(2, "Login FAILED for IDOR module!")

    return session


# --------------------------
# IDOR DETECTION LOGIC
# --------------------------
def detect_horizontal(session, base, param="id"):
    """
    Test IDOR by changing ID=1 → ID=2 → ID=3.
    DVWA guestbook pages are good examples.
    """
    findings = []

    for uid in [1, 2, 3]:
        test_url = f"{base}?{param}={uid}"
        try:
            r = session.get(test_url, timeout=5)
            if "First name" in r.text or "Message" in r.text:
                # DVWA often displays user content directly
                findings.append([
                    "IDOR-Horizontal",
                    test_url,
                    param,
                    uid,
                    "User data accessed without permission",
                    "High"
                ])
                log(4, f"Horizontal Escalation → {test_url}")
        except:
            pass

    return findings


def detect_file_traversal(session, base):
    """
    DVWA 'File Inclusion' page can be tested for directory traversal IDOR.
    """
    findings = []
    payload = "../../../../etc/passwd"

    test_url = f"{base}?page={payload}"
    try:
        r = session.get(test_url, timeout=5)
        if "root:x:" in r.text:
            log(4, f"IDOR (File Traversal) → {test_url}")
            findings.append([
                "IDOR-FileTraversal",
                test_url,
                "page",
                payload,
                "/etc/passwd accessed",
                "Critical"
            ])
    except:
        pass

    return findings


def detect_vertical(session, private_page):
    """
    Try accessing admin-only pages WITHOUT admin role.
    Since DVWA has single admin password, simulate by clearing session.
    """
    findings = []
    try:
        s2 = requests.Session()   # not logged in
        r = s2.get(private_page, timeout=5)
        if "Login" not in r.text:
            log(4, f"Vertical Escalation → {private_page}")
            findings.append([
                "IDOR-Vertical",
                private_page,
                "N/A",
                "N/A",
                "Protected page accessible without login",
                "High"
            ])
    except:
        pass

    return findings


# --------------------------
# MAIN ENTRY
# --------------------------
def run_idor(target="http://localhost"):
    log(1, "Running IDOR & Access Control Scanner")

    session = requests.Session()
    session = login(session, target)

    findings = []

    # DVWA pages to test
    file_inclusion = target + "/vulnerabilities/fi/"
    guestbook = target + "/vulnerabilities/xss_s/"
    admin_page = target + "/vulnerabilities/exec/"

    # Run test modules
    findings += detect_file_traversal(session, file_inclusion)
    findings += detect_horizontal(session, guestbook, "id")
    findings += detect_vertical(session, admin_page)

    # Save results
    df = pd.DataFrame(findings, columns=[
        "module", "endpoint", "parameter", "payload", "evidence", "severity"
    ])
    df.to_csv(IDOR_OUTPUT, index=False)

    log(5, f"IDOR tests completed. Results saved to: {IDOR_OUTPUT}\n")
