# main.py – Master Runner for Entire WebScanPro Project

from crawler import run_crawler
from sqli_scanner import run_sqli
from xss_scanner import run_xss
from auth_tester import run_auth_tests
from idor_scanner import run_idor
from reporter import generate_report
from utils import log

def main():
    print("\n==========================================")
    print("    WebScanPro – Automated Security Scanner")
    print("==========================================\n")

    # WEEK 1 is manual (setup), so we start from WEEK 2
    print("\n--------------------------------------")
    print(" WEEK 2: Running Target Crawler")
    print("--------------------------------------")
    run_crawler("http://localhost")

    print("\n--------------------------------------")
    print(" WEEK 3: Running SQL Injection Scanner")
    print("--------------------------------------")
    run_sqli("http://localhost")

    print("\n--------------------------------------")
    print(" WEEK 4: Running XSS Scanner")
    print("--------------------------------------")
    run_xss("http://localhost")

    print("\n--------------------------------------")
    print(" WEEK 5: Running Auth & Session Tests")
    print("--------------------------------------")
    run_auth_tests("http://localhost")

    print("\n--------------------------------------")
    print(" WEEK 6: Running Access Control / IDOR Tests")
    print("--------------------------------------")
    run_idor("http://localhost")

    print("\n--------------------------------------")
    print(" WEEK 7: Generating Final Report")
    print("--------------------------------------")
    generate_report()

    print("\n==========================================")
    print("   WebScanPro Execution Completed!")
    print("   Reports saved in: results/ folder")
    print("==========================================\n")


if __name__ == "__main__":
    main()
