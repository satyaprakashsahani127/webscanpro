# crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from tqdm import tqdm
from pathlib import Path
from dotenv import load_dotenv
import os
from utils import log, save_json

load_dotenv()

USER = os.getenv("WS_USERNAME", "admin")
PASS = os.getenv("WS_PASSWORD", "password")

RESULTS_DIR = Path.cwd() / "results"
RESULTS_DIR.mkdir(exist_ok=True)


# ----------------------------------------
# Extract links 
# ----------------------------------------
def extract_links(base_url, html):
    soup = BeautifulSoup(html, "lxml")
    links = []

    for a in soup.find_all("a", href=True):
        full = urljoin(base_url, a['href'])

        # Skip logout
        if "logout" in full.lower():
            continue

        links.append(full)
    return links


# ----------------------------------------
# Extract forms 
# ----------------------------------------
def extract_forms(base_url, html):
    soup = BeautifulSoup(html, "lxml")
    forms = []

    for form in soup.find_all("form"):
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append(name)

        forms.append({
            "action": form.get("action", ""),
            "method": form.get("method", "GET").upper(),
            "inputs": inputs
        })
    return forms


# ----------------------------------------
# FIXED LOGIN (100% DVWA Compatible)
# ----------------------------------------
def login(session, target):
    login_page = urljoin(target, "/login.php")
    log(4, f"Fetching login page: {login_page}")

    try:
        res = session.get(login_page)
    except Exception as e:
        log(4, f"Login page connection failed: {e}")
        return session

    soup = BeautifulSoup(res.text, "lxml")

    # Detect token in ANY field name
    token = ""
    token_field = None
    for inp in soup.find_all("input"):
        name = inp.get("name", "")
        if "token" in name.lower():
            token_field = name
            token = inp.get("value", "")
            break

    log(5, f"Extracted token field = {token_field}, value = {token}")

    # First attempt (POST login)
    payload = {
        "username": USER,
        "password": PASS,
        "Login": "Login",
        "submitted": "1"
    }
    if token_field:
        payload[token_field] = token

    post = session.post(login_page, data=payload)

    # Check success
    if "Logout" in post.text or "logout" in post.text:
        log(6, "Login successful!")
        return session

    # Retry with GET format
    retry_url = f"{login_page}?username={USER}&password={PASS}&Login=Login"
    retry = session.get(retry_url)

    if "Logout" in retry.text or "logout" in retry.text:
        log(6, "Login successful on retry (GET login)!")
        return session

    log(6, "LOGIN FAILED! (Check DVWA setup or credentials)")
    return session


# ----------------------------------------
# Extract DVWA menu modules
# ----------------------------------------
def extract_dvwa_menu(session, target):
    dashboard = urljoin(target, "/")
    res = session.get(dashboard)
    soup = BeautifulSoup(res.text, "lxml")

    menu_links = []

    # DVWA’s left menu is inside div#main_menu
    menu = soup.find("div", {"id": "main_menu"})
    if not menu:
        return []

    for a in menu.find_all("a", href=True):
        full = urljoin(target, a['href'])
        if "logout" not in full.lower():
            menu_links.append(full)

    return menu_links


# ----------------------------------------
# Run crawler
# ----------------------------------------
def run_crawler(target="http://localhost", max_depth=2):
    log(1, "Running Web Crawler")
    log(2, "Loading configuration...")
    log(3, f"Starting scan: {target}")

    session = requests.Session()

    # Perform login
    session = login(session, target)

    # Extract DVWA menu links
    dvwa_links = extract_dvwa_menu(session, target)
    log(7, f"Found {len(dvwa_links)} DVWA module links")

    visited = set()
    queue = [(link, 0) for link in dvwa_links]
    crawl_data = []

    for url, depth in tqdm(queue, desc="Crawling"):
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        try:
            res = session.get(url)
        except:
            continue

        forms = extract_forms(url, res.text)
        links = extract_links(url, res.text)

        crawl_data.append({
            "url": url,
            "forms": forms,
            "links": links
        })

        # BFS
        for link in links:
            if urlparse(link).netloc == urlparse(target).netloc and link not in visited:
                queue.append((link, depth + 1))

    # Save to file
    out = RESULTS_DIR / "week2_crawl_results.json"
    save_json(str(out), crawl_data)

    log(8, f"Total pages found: {len(crawl_data)}")
    log(9, f"Crawl results saved to: {out}")
    print()
