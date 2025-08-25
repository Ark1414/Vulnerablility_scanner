# scanner.py

import httpx
from bs4 import BeautifulSoup

async def scan_website_for_vulnerabilities(url: str):
    vulnerabilities = []
    risk_score = 0

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            response = await client.get(url)
            headers = response.headers
            html = response.text

            # 1. Check for missing security headers
            missing_headers = []
            required_headers = ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]

            for header in required_headers:
                if header not in headers:
                    missing_headers.append(header)

            if missing_headers:
                vulnerabilities.append({
                    "type": "Missing Headers",
                    "count": len(missing_headers),
                    "details": missing_headers
                })
                risk_score += len(missing_headers)

            # 2. Check for input fields (XSS-prone)
            soup = BeautifulSoup(html, "html.parser")
            input_fields = soup.find_all("input")

            if input_fields:
                vulnerabilities.append({
                    "type": "XSS",
                    "count": len(input_fields),
                    "details": ["Potential input fields without sanitization"]
                })
                risk_score += len(input_fields)

            # 3. Check for exposed admin paths (basic)
            if "/admin" in html or "/login" in html:
                vulnerabilities.append({
                    "type": "Exposed Admin/Login URL",
                    "count": 1,
                    "details": ["/admin or /login found in HTML"]
                })
                risk_score += 3

    except Exception as e:
        vulnerabilities.append({
            "type": "Error",
            "count": 1,
            "details": [str(e)]
        })
        risk_score += 5

    # Determine risk level
    if risk_score >= 7:
        risk_level = "High"
    elif risk_score >= 3:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "vulnerabilities": vulnerabilities,
        "risk_level": risk_level
    }
