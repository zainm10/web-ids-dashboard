# Web-Based Intrusion Detection System (IDS) Dashboard

This project is a Flask-based web application that analyses simulated log files to detect suspicious cyber-security activity such as brute-force login attempts, unknown IP access, and restricted area access.

## Features
- Upload and analyse log files
- Detect intrusion patterns using rule-based analysis
- Display alerts with severity levels
- Store alert history in SQLite database
- Export alerts as CSV report
- Demonstrate safe vs malicious scenarios

## Technologies Used
- Python 3
- Flask
- SQLite
- Pandas
- Bootstrap

## How to Run the Project

1. Clone the repository:
2. git clone https://github.com/zainm10/web-ids-dashboard.git
cd web-ids-dashboard

2. Create virtual environment:
python3 -m venv venv
source venv/bin/activate

3. Install dependencies:
pip install -r requirements.txt

4. Run the application:
python3 app.py

5. Open in browser:
http://127.0.0.1:5000
