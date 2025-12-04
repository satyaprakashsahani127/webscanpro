# WebScanPro
Web Application Security Testing Tool

## Introduction
WebScanPro is an automated web application security testing tool.  
It helps to identify common security vulnerabilities in web applications.

This project is developed mainly for academic and learning purposes to understand web application security testing techniques.

---

## Objective
- To scan web applications automatically.
- To detect common web vulnerabilities.
- To help students learn practical web security concepts.
- To generate a simple vulnerability report.

---

## Features
- Website crawling
- SQL Injection testing
- Cross-Site Scripting (XSS) detection
- Authentication and session testing
- IDOR (Insecure Direct Object Reference) detection
- Vulnerability reporting

---

## Technologies Used
- Python
- Requests library
- BeautifulSoup
- Flask (for test environments)
- OWASP security concepts

---

## Project Structure
webscanpro/
|
├── crawler.py # Handles website crawling
├── sqli_scanner.py # Detects SQL Injection vulnerabilities
├── xss_scanner.py # Detects XSS vulnerabilities
├── idor_scanner.py # Detects IDOR issues
├── auth_tester.py # Tests authentication and session security
├── reporter.py # Generates final security report
├── utils.py # Helper and utility functions
├── main.py # Main execution file
└── README.md

---

## How to Run the Project

1. Clone the repository
git clone https://github.com/satyaprakashsahani127/webscanpro.git

2. Open the project directory
cd webscanpro

3. Create and activate virtual environment (optional)
python -m venv venv
venv\Scripts\activate

4. Install required libraries
pip install -r requirements.txt

5. Run the tool
python main.py
---

## Output
- Displays detected vulnerabilities in the terminal.
- Generates a final security report.

---

## Disclaimer
This project is created only for educational and learning purposes.  
Do not use this tool on real websites without proper authorization.  
The developer is not responsible for misuse of this tool.

---

## Author
Student Project  
Cyber Security and Web Application Security Testing

---

## Future Improvements
- Add CSRF vulnerability detection
- Add multi-threaded scanning
- Export report in PDF format
- Improve detection accuracy
