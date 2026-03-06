"""
VirusTotal API Integration

Provides tools for checking Indicators of Compromise (IOCs) against VirusTotal.
Supports IP addresses, domains, URLs, and file hashes.
API Documentation: https://developers.virustotal.com/reference/overview
"""

import httpx
import os
import re
from typing import Dict, Any
from urllib.parse import quote


async def search_ioc(indicator: str) -> Dict[str, Any]:
    """
    Check an Indicator of Compromise (IOC) against VirusTotal.
    
    Supports:
    - IP addresses (e.g., "8.8.8.8")
    - Domains (e.g., "malicious.com")
    - URLs (e.g., "http://example.com/malware.exe")
    - File hashes (MD5, SHA-1, SHA-256)
    
    Args:
        indicator: The IOC to check (IP, domain, URL, or file hash)
    
    Returns:
        Dictionary containing:
        - indicator: The queried indicator
        - type: Type of indicator (ip, domain, url, or hash)
        - malicious: Number of vendors flagging as malicious
        - suspicious: Number of vendors flagging as suspicious
        - harmless: Number of vendors flagging as harmless
        - undetected: Number of vendors with no detection
        - total_vendors: Total number of vendors that scanned
        - reputation_score: Overall reputation score (if available)
        - top_verdicts: List of verdicts from major security vendors
        - last_analysis_date: When the indicator was last analyzed
    
    Raises:
        Exception: If API key is missing or API error occurs
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not api_key:
        return {
            "error": "VirusTotal API key not found. Please set VIRUSTOTAL_API_KEY in .env file",
            "hint": "Get a free API key at https://www.virustotal.com/gui/join-us"
        }
    
    # Detect indicator type
    indicator_type = _detect_indicator_type(indicator)
    
    if indicator_type == "unknown":
        return {"error": f"Unable to determine indicator type for: {indicator}"}
    
    # Build appropriate API endpoint
    if indicator_type == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif indicator_type == "domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    elif indicator_type == "url":
        # URLs need to be base64 encoded (without padding)
        import base64
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif indicator_type == "hash":
        endpoint = f"https://www.virustotal.com/api/v3/files/{indicator}"
    
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(endpoint, headers=headers)
            
            if response.status_code == 404:
                return {
                    "indicator": indicator,
                    "type": indicator_type,
                    "message": "Indicator not found in VirusTotal database",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                }
            
            response.raise_for_status()
            data = response.json()
            
            # Extract analysis stats
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total_vendors = malicious + suspicious + harmless + undetected
            
            # Get reputation score (if available)
            reputation_score = attributes.get("reputation", None)
            
            # Extract top verdicts from major vendors
            results = attributes.get("last_analysis_results", {})
            top_verdicts = []
            major_vendors = ["Kaspersky", "Microsoft", "Sophos", "Fortinet", "ESET", "Avira", "BitDefender", "CrowdStrike"]
            
            for vendor in major_vendors:
                if vendor in results:
                    verdict = results[vendor]
                    if verdict.get("category") in ["malicious", "suspicious"]:
                        top_verdicts.append({
                            "vendor": vendor,
                            "category": verdict.get("category"),
                            "result": verdict.get("result")
                        })
            
            # Get last analysis date
            last_analysis_date = attributes.get("last_analysis_date", "N/A")
            if isinstance(last_analysis_date, int):
                from datetime import datetime
                last_analysis_date = datetime.fromtimestamp(last_analysis_date).strftime("%Y-%m-%d %H:%M:%S")
            
            result = {
                "indicator": indicator,
                "type": indicator_type,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_vendors": total_vendors,
                "reputation_score": reputation_score,
                "top_verdicts": top_verdicts,
                "last_analysis_date": last_analysis_date,
            }
            
            # Add contextual verdict
            if malicious > 0:
                result["verdict"] = f"⚠️ MALICIOUS - {malicious}/{total_vendors} vendors flagged this indicator"
            elif suspicious > 0:
                result["verdict"] = f"⚠️ SUSPICIOUS - {suspicious}/{total_vendors} vendors flagged this indicator"
            elif harmless > 0:
                result["verdict"] = f"✓ CLEAN - {harmless}/{total_vendors} vendors marked as harmless"
            else:
                result["verdict"] = "Unknown - No vendor detections available"
            
            return result
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return {"error": "Invalid VirusTotal API key. Please check your VIRUSTOTAL_API_KEY in .env"}
        elif e.response.status_code == 429:
            return {"error": "VirusTotal API rate limit exceeded. Please wait before retrying."}
        return {"error": f"HTTP error occurred: {e.response.status_code} - {e.response.text}"}
    except httpx.RequestError as e:
        return {"error": f"Network error occurred: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


def _detect_indicator_type(indicator: str) -> str:
    """Detect the type of indicator (IP, domain, URL, or hash)."""
    # Remove whitespace
    indicator = indicator.strip()
    
    # Check if it's a URL
    if indicator.startswith(("http://", "https://", "ftp://")):
        return "url"
    
    # Check if it's an IP address (IPv4)
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, indicator):
        return "ip"
    
    # Check if it's a hash (MD5: 32 hex, SHA-1: 40 hex, SHA-256: 64 hex)
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):  # MD5
        return "hash"
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):  # SHA-1
        return "hash"
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):  # SHA-256
        return "hash"
    
    # Check if it's a domain
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, indicator):
        return "domain"
    
    return "unknown"
