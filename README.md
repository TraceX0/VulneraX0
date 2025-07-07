# VulneraX0

VulneraX0 is a fake web platform that simulates a secure document vault and payment system for individuals and small businesses. Users can register, upload documents, send balances, and interact via comments — but the platform is full of intentional vulnerabilities for ethical hacking practice.

🔓 VulneraX0 – Because every “secure” platform has secrets.

## Structure
- `app.py`: Main Flask application
- `database.db`: SQLite database
- `requirements.txt`: Python dependencies
- `templates/`: HTML templates for each vulnerability demo
- `static/`: Static files (CSS, JS)

## Features & Vulnerabilities
| Feature           | Realistic Use            | Vulnerability You Can Practice |
|-------------------|-------------------------|-------------------------------|
| Login/Profile     | User dashboard          | IDOR, Broken Auth             |
| Balance Transfer  | Send funds to others    | Race Condition                |
| Search            | Search transactions     | SQLi                          |
| Comment Section   | Notes on files/payments | Stored XSS                    |
| File Upload       | Upload XML invoice      | XXE                           |

## Usage
1. Install requirements: `pip install -r requirements.txt`
2. Run: `python app.py`



