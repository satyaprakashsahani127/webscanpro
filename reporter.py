# reporter.py – Week 7
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from utils import log
from jinja2 import Template
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

RESULTS_DIR = Path.cwd() / "results"
HTML_REPORT = RESULTS_DIR / "final_security_report.html"
PDF_REPORT = RESULTS_DIR / "final_security_report.pdf"
CHART_IMG = RESULTS_DIR / "vuln_chart.png"

CSV_FILES = [
    "week3_sqlscan_results.csv",
    "week4_xssscan_results.csv",
    "week5_auth_session_results.csv",
    "week6_idor_results.csv"
]

# -------------------------
#  MITIGATION SUGGESTIONS
# -------------------------
MITIGATION = {
    "SQL Injection": "Use prepared statements, parameterized queries and input validation.",
    "XSS (Reflected)": "Sanitize user input, implement HTML encoding and enable Content Security Policy (CSP).",
    "XSS (Stored)": "Store clean input only, use output encoding and server-side filtering.",
    "XSS (DOM)": "Avoid writing raw user input to DOM, use safe JavaScript methods.",
    "IDOR-Horizontal": "Implement access control checks before serving user-specific data.",
    "IDOR-Vertical": "Ensure privilege-level checks on sensitive endpoints.",
    "IDOR-FileTraversal": "Validate file paths, restrict directory access and disable direct file includes.",
    "auth": "Enforce strong password policy, lockout mechanism and 2FA.",
}


# -------------------------
# LOAD ALL VULN RESULTS
# -------------------------
def load_results():
    all_rows = []
    for file in CSV_FILES:
        path = RESULTS_DIR / file
        if path.exists():
            df = pd.read_csv(path)
            all_rows.append(df)

    if not all_rows:
        return pd.DataFrame()

    full = pd.concat(all_rows, ignore_index=True)

    # Attach mitigation suggestions
    fixes = []
    for m in full["module"]:
        fixes.append(MITIGATION.get(m, "Apply security best practices."))

    full["mitigation"] = fixes

    return full


# -------------------------
# CHART GENERATION
# -------------------------
def generate_chart(df):
    severity_counts = df["severity"].value_counts()

    plt.figure(figsize=(6, 4))
    severity_counts.plot(kind="bar", color=["red", "orange", "green"])
    plt.title("Vulnerability Severity Distribution")
    plt.xlabel("Severity Level")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(CHART_IMG)
    plt.close()


# -------------------------
# HTML REPORT GENERATION
# -------------------------
def generate_html(df):
    template = Template("""
    <html>
    <head>
        <title>Web Security Report</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            h1 { color: #2c3e50; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 10px; border: 1px solid #555; }
            th { background: #444; color: #fff; }
        </style>
    </head>
    <body>

        <h1>Web Application Security Testing Report</h1>
        <p><b>Total Vulnerabilities Found:</b> {{ total }}</p>

        <h2>Severity Chart</h2>
        <img src="vuln_chart.png" width="400">

        <h2>Detailed Findings</h2>
        <table>
            <tr>
                <th>Vulnerability Type</th>
                <th>Endpoint</th>
                <th>Severity</th>
                <th>Evidence</th>
                <th>Suggested Mitigation</th>
            </tr>
            {% for row in data %}
            <tr>
                <td>{{ row.module }}</td>
                <td>{{ row.endpoint }}</td>
                <td>{{ row.severity }}</td>
                <td>{{ row.evidence }}</td>
                <td>{{ row.mitigation }}</td>
            </tr>
            {% endfor %}
        </table>

    </body>
    </html>
    """)

    html = template.render(
        total=len(df),
        data=df.to_dict("records")
    )

    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write(html)


# -------------------------
# PDF REPORT GENERATION
# -------------------------
def generate_pdf(df):
    doc = SimpleDocTemplate(str(PDF_REPORT), pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("<b>Web Application Security Testing Report</b>", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"Total Vulnerabilities Found: {len(df)}", styles["Normal"]))
    story.append(Spacer(1, 12))

    if CHART_IMG.exists():
        story.append(Image(str(CHART_IMG), width=400, height=250))
        story.append(Spacer(1, 12))

    for _, row in df.iterrows():
        story.append(Paragraph(f"<b>{row['module']}:</b> {row['endpoint']} ({row['severity']})", styles["Normal"]))
        story.append(Paragraph(f"Evidence: {row['evidence']}", styles["Normal"]))
        story.append(Paragraph(f"<i>Mitigation: {row['mitigation']}</i>", styles["Normal"]))
        story.append(Spacer(1, 10))

    doc.build(story)


# -------------------------
# MAIN ENTRY
# -------------------------
def generate_report():
    log(1, "Generating Final Security Report...")

    df = load_results()

    if df.empty:
        log(2, "No vulnerability results found!")
        return

    log(3, f"Total vulnerabilities loaded: {len(df)}")

    log(4, "Generating severity chart...")
    generate_chart(df)

    log(5, "Creating HTML report...")
    generate_html(df)

    log(6, "Exporting PDF...")
    generate_pdf(df)

    log(7, f"Reports saved to: {HTML_REPORT} and {PDF_REPORT}")
    print()
