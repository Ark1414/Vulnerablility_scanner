from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, HttpUrl
from scanner import scan_website_for_vulnerabilities
from urllib.parse import urlparse

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Logging
import logging

# Set up logging to file
logging.basicConfig(
    filename="scan_logs.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# FastAPI app and rate limiter
app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or use ["http://localhost:5500"] for Live Server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan history
scan_history = []

# Request model
class ScanRequest(BaseModel):
    url: HttpUrl

# POST /scan endpoint
@app.post("/scan")
@limiter.limit("5/minute")  # Allow 5 scans per minute per IP
async def scan_website(request: Request, body: ScanRequest):
    parsed_url = urlparse(str(body.url))

    # Validate URL scheme
    if parsed_url.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs are allowed.")

    # Block localhost and loopback
    if parsed_url.hostname in ["localhost", "127.0.0.1"]:
        raise HTTPException(status_code=400, detail="Localhost scanning is not allowed.")

    # Log the scan request
    logging.info(f"Scan requested: {body.url} from IP {request.client.host}")

    # Perform the scan
    result = await scan_website_for_vulnerabilities(str(body.url))

   # Extract and normalize vulnerability data
    vulnerabilities = []
    for v in result["vulnerabilities"]:
        vulnerabilities.append({
            "type": v["type"],
            "count": v.get("count", 1),
            "details": v.get("details", [])
        })
    risk_level = result["risk_level"]

    # Auto-generate tips based on vulnerability types
    tips = []
    for v in vulnerabilities:
        if v["type"] == "XSS":
            tips.append("Sanitize all user inputs to prevent XSS attacks.")
        elif v["type"] == "Missing Headers":
            if "Content-Security-Policy" in v.get("details", []):
                tips.append("Add a Content-Security-Policy header.")
            if "X-Frame-Options" in v.get("details", []):
                tips.append("Include X-Frame-Options to prevent clickjacking.")
        elif v["type"] == "Admin Panel":
            tips.append("Restrict access to admin panels and hide them from public.")

    scan_data = {
        "url": str(body.url),
        "vulnerabilities": vulnerabilities,
        "risk_level": risk_level,
        "tips": tips
    }


    # Save to history
    scan_history.append(scan_data)
    return scan_data

# GET /history endpoint
@app.get("/history")
async def get_scan_history():
    return {"history": scan_history}
