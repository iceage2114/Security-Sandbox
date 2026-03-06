"""
AbuseIPDB API Integration

Provides tools for checking IP reputation and abuse reports.
API Documentation: https://docs.abuseipdb.com/
"""

import httpx
import os
from typing import Dict, Any


async def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB for IP reputation data and abuse reports.
    
    Returns detailed information about an IP address including abuse confidence score,
    total reports, usage type (ISP, hosting, etc.), and country information.
    
    Args:
        ip: IPv4 or IPv6 address to check (e.g., "8.8.8.8")
    
    Returns:
        Dictionary containing:
        - ip_address: The queried IP address
        - abuse_confidence_score: Score from 0-100 indicating likelihood of malicious activity
        - total_reports: Total number of abuse reports for this IP
        - num_distinct_users: Number of distinct users who reported this IP
        - last_reported_at: Timestamp of the most recent report
        - country_code: Two-letter country code
        - country_name: Full country name
        - usage_type: Type of IP usage (e.g., Data Center, ISP, Corporate)
        - isp: Internet Service Provider name
        - domain: Domain associated with the IP
        - is_whitelisted: Whether the IP is on the whitelist
        - is_public: Whether it's a public IP address
        - recent_reports: Sample of recent abuse reports (last 5)
        - verdict: Human-readable risk assessment
    
    Raises:
        Exception: If API key is missing or API error occurs
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    if not api_key:
        return {
            "error": "AbuseIPDB API key not found. Please set ABUSEIPDB_API_KEY in .env file",
            "hint": "Get a free API key at https://www.abuseipdb.com/account/api"
        }
    
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,  # Check reports from last 90 days
        "verbose": ""  # Include detailed report information
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers, params=params)
            
            if response.status_code == 422:
                return {"error": f"Invalid IP address format: {ip}"}
            
            response.raise_for_status()
            data = response.json()
            
            if "data" not in data:
                return {"error": "Unexpected API response format"}
            
            ip_data = data["data"]
            
            # Extract core information
            abuse_score = ip_data.get("abuseConfidenceScore", 0)
            total_reports = ip_data.get("totalReports", 0)
            num_distinct_users = ip_data.get("numDistinctUsers", 0)
            
            # Extract location and ISP info
            country_code = ip_data.get("countryCode", "Unknown")
            country_name = ip_data.get("countryName", "Unknown")
            usage_type = ip_data.get("usageType", "Unknown")
            isp = ip_data.get("isp", "Unknown")
            domain = ip_data.get("domain", "N/A")
            
            # Extract metadata
            is_whitelisted = ip_data.get("isWhitelisted", False)
            is_public = ip_data.get("isPublic", True)
            last_reported_at = ip_data.get("lastReportedAt", "Never")
            
            # Extract recent reports
            recent_reports = []
            if "reports" in ip_data and ip_data["reports"]:
                for report in ip_data["reports"][:5]:  # Limit to 5 most recent
                    recent_reports.append({
                        "reported_at": report.get("reportedAt", "N/A"),
                        "comment": report.get("comment", "No comment"),
                        "categories": report.get("categories", []),
                        "reporter_country": report.get("reporterCountryCode", "Unknown")
                    })
            
            # Generate verdict based on abuse score
            if abuse_score >= 75:
                verdict = f"🔴 HIGH RISK - Abuse score {abuse_score}/100. Strong evidence of malicious activity."
                risk_level = "HIGH"
            elif abuse_score >= 50:
                verdict = f"🟠 MODERATE RISK - Abuse score {abuse_score}/100. Suspicious activity detected."
                risk_level = "MODERATE"
            elif abuse_score >= 25:
                verdict = f"🟡 LOW RISK - Abuse score {abuse_score}/100. Some reports, use caution."
                risk_level = "LOW"
            elif total_reports > 0:
                verdict = f"🟢 MINIMAL RISK - Abuse score {abuse_score}/100. Few reports."
                risk_level = "MINIMAL"
            else:
                verdict = f"✅ CLEAN - No abuse reports found for this IP."
                risk_level = "CLEAN"
            
            result = {
                "ip_address": ip,
                "abuse_confidence_score": abuse_score,
                "risk_level": risk_level,
                "total_reports": total_reports,
                "num_distinct_users": num_distinct_users,
                "last_reported_at": last_reported_at,
                "country_code": country_code,
                "country_name": country_name,
                "usage_type": usage_type,
                "isp": isp,
                "domain": domain,
                "is_whitelisted": is_whitelisted,
                "is_public": is_public,
                "recent_reports": recent_reports,
                "verdict": verdict,
            }
            
            return result
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return {"error": "Invalid AbuseIPDB API key. Please check your ABUSEIPDB_API_KEY in .env"}
        elif e.response.status_code == 429:
            return {"error": "AbuseIPDB API rate limit exceeded. Free accounts are limited to 1000 requests/day."}
        return {"error": f"HTTP error occurred: {e.response.status_code} - {e.response.text}"}
    except httpx.RequestError as e:
        return {"error": f"Network error occurred: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
