# auth_tester.py
import requests
import time
import csv
from pathlib import Path
from dotenv import load_dotenv
from utils import log

load_dotenv()

RESULTS_DIR = Path.cwd() / "results"
RESULTS_DIR.mkdir(exist_ok=True)
OUT_CSV = RESULTS_DIR / "week5_auth_session_results.csv"

# short list of common creds for demo (do not brute-force external targets)
COMMON_CREDS = [
    ("admin","password"),
    ("admin","admin"),
    ("guest","guest"),
    ("admin","12345")
]

def check_cookie_flags(res):
    """Return list of issues found in cookies"""
    issues = []
    cookies = res.cookies
    # requests.Response.cookies doesn't expose flags; inspect Set-Cookie headers
    sc = res.headers.get("Set-Cookie", "")
    if sc:
        # crude checks: if Secure or HttpOnly strings present
        if "Secure" not in sc:
            issues.append("cookie_missing_Secure")
        if "HttpOnly" not in sc and "httponly" not in sc.lower():
            issues.append("cookie_missing_HttpOnly")
    return issues

def run_auth_tests(target="http://localhost"):
    log(1, "Running Authentication & Session Tests")
    log(2, f"Target: {target} -- Loading auth tests")

    findings = []

    login_url = f"{target.rstrip('/')}/login.php"

    # 1) Test common/weak credentials (non-intrusive)
    log(3, "Testing for weak/default credentials (limited list)")
    for u,p in COMMON_CREDS:
        try:
            s = requests.Session()
            # perform GET to fetch token if present
            page = s.get(login_url, timeout=6)
            token = ""
            # try to find token in body (simple)
            if "user_token" in page.text:
                # crude extraction
                import re
                m = re.search(r'name=["\']?(user_token)["\']? value=["\']?([^"\' >]+)', page.text)
                if m:
                    token = m.group(2)
            payload = {"username": u, "password": p, "Login": "Login"}
            if token:
                payload["user_token"] = token
            resp = s.post(login_url, data=payload, timeout=6)
            if "Login failed" not in resp.text and resp.status_code == 200 and "Logout" in resp.text:
                log(4, f"WEAK CREDENTIALS FOUND: {u}:{p}")
                findings.append(["auth","/login.php","username", f"{u}:{p}", "Weak/default credentials allowed", "High"])
                break
        except Exception as e:
            continue

    # 2) Check cookie flags on login (using a valid login)
    log(5, "Checking Set-Cookie flags on login response")
    try:
        s2 = requests.Session()
        # attempt login with known good from .env if present
        from os import getenv
        good_user = getenv("WS_USERNAME", "admin")
        good_pass = getenv("WS_PASSWORD", "password")
        # fetch token
        p1 = s2.get(login_url, timeout=6)
        token = ""
        if "user_token" in p1.text:
            import re
            m = re.search(r'name=["\']?(user_token)["\']? value=["\']?([^"\' >]+)', p1.text)
            if m:
                token = m.group(2)
        payload = {"username": good_user, "password": good_pass, "Login": "Login"}
        if token:
            payload["user_token"] = token
        r = s2.post(login_url, data=payload, timeout=6)
        cookie_issues = check_cookie_flags(r)
        if cookie_issues:
            for ci in cookie_issues:
                findings.append(["auth","/login.php","cookie","Set-Cookie", ci, "Medium"])
                log(6, f"Cookie issue: {ci}")
        else:
            log(6, "Cookie flags appear OK (Secure/HttpOnly present if set by server)")
    except Exception as e:
        log(6, f"Cookie check error: {e}")

    # 3) Session fixation (try to set sessionid before login and see if reused)
    log(7, "Testing for session fixation (best-effort)")
    try:
        sfix = requests.Session()
        # set a fake session cookie value
        sfix.cookies.set("PHPSESSID", "fixed-session-attack")
        # then login
        p = sfix.get(login_url, timeout=6)
        payload = {"username": good_user, "password": good_pass, "Login": "Login"}
        if token:
            payload["user_token"] = token
        rp = sfix.post(login_url, data=payload, timeout=6)
        # if server accepts same session id after login, it's a possible fixation
        sid_after = sfix.cookies.get("PHPSESSID")
        if sid_after == "fixed-session-attack":
            findings.append(["auth","/login.php","session","PHPSESSID","Session fixation possible", "High"])
            log(8, "Session fixation possible (server reused attacker-supplied session id)")
        else:
            log(8, "Session fixation NOT observed")
    except Exception as e:
        log(8, f"Session fixation test error: {e}")

    # 4) Simple brute-force simulation (very limited, respectful)
    log(9, "Running small brute-force simulation (limit 6 attempts) — respectful")
    brute_list = [("admin","123456"),("admin","pass123"),("admin","qwerty"),("admin","admin123")]
    attempts = 0
    for u,p in brute_list:
        if attempts >= 6:
            break
        attempts += 1
        try:
            s3 = requests.Session()
            p1 = s3.get(login_url, timeout=6)
            data = {"username": u, "password": p, "Login": "Login"}
            r3 = s3.post(login_url, data=data, timeout=6)
            if "Login failed" not in r3.text and "Logout" in r3.text:
                findings.append(["auth","/login.php","username", f"{u}:{p}", "Brute-force successful", "High"])
                log(10, f"Brute-force succeeded: {u}:{p}")
                break
        except:
            continue

    # Save findings to CSV
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["module","endpoint","parameter","payload","evidence","severity"])
        for row in findings:
            writer.writerow(row)

    log(11, f"Auth tests complete. Results written to: {OUT_CSV}")
    print()
