# Vulnerablility_scanner



 Web Application Vulnerability Scanner (FastAPI)

This project is a basic web vulnerability scanner API built with FastAPI.
It allows users to submit a target website URL and get a quick security assessment.
The scanner identifies common security risks, provides auto-generated mitigation tips, and keeps a history of recent scans.

 Features

Scan Endpoint (/scan)

Accepts a website URL (http/https).

Blocks localhost/loopback scans for safety.

Performs vulnerability checks (e.g., XSS, missing headers, exposed admin panels).

Auto-suggests mitigation tips based on findings.

Rate-limited to 5 scans/minute per IP.

History Endpoint (/history)

Returns a list of previously scanned URLs with results.

Logging

All scan requests are logged (scan_logs.log) with timestamp, level, and client IP.

Security & Safety

CORS enabled (default: *).

Rate limiting with slowapi
.

Blocks local addresses (localhost, 127.0.0.1).

 Project Structure
.
├── main.py                 # FastAPI app (your code)
├── scanner.py              # Vulnerability scanning logic (imported function)
├── scan_logs.log           # Log file (generated at runtime)
├── requirements.txt        # Dependencies
└── README.md               # Documentation

 Installation & Setup

Clone the repository

git clone https://github.com/Ark1414/Vulnerablility_scanner.git
cd Vulnerablility_scanner


Create virtual environment & install dependencies

python3 -m venv venv
source venv/bin/activate   # (Linux/Mac)
venv\Scripts\activate      # (Windows)

pip install -r requirements.txt


Run the FastAPI server

uvicorn main:app --reload


API will be live at:
 http://127.0.0.1:8000/docs
 (interactive Swagger UI)

 API Endpoints
 POST /scan

Request body:

{
  "url": "https://example.com"
}


Response:

{
  "url": "https://example.com",
  "vulnerabilities": [
    {"type": "XSS", "count": 2, "details": ["<script>alert(1)</script>"]}
  ],
  "risk_level": "High",
  "tips": [
    "Sanitize all user inputs to prevent XSS attacks."
  ]
}

 GET /history

Response:

{
  "history": [
    {
      "url": "https://example.com",
      "vulnerabilities": [...],
      "risk_level": "High",
      "tips": [...]
    }
  ]
}

🛠️ Tech Stack

Backend: FastAPI

Rate Limiting: SlowAPI

Data Validation: Pydantic

Logging: Python logging module

Database: In-memory list (can be extended to PostgreSQL/MySQL)

📖 Notes

This is a demo/security learning project → Not a full production-grade scanner.

Extend scanner.py with real vulnerability checks.

For real-world use, integrate DB (PostgreSQL/MySQL), authentication, and advanced analysis.
