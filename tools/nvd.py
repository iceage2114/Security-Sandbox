"""
NVD (National Vulnerability Database) API Integration

Provides tools for querying CVE information and searching vulnerabilities by product.
API Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

import httpx
import json
from typing import Dict, Any


async def lookup_cve(cve_id: str) -> Dict[str, Any]:
    """
    Query the NVD API for detailed information about a specific CVE.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
    
    Returns:
        Dictionary containing:
        - id: CVE identifier
        - description: Vulnerability description
        - published_date: Publication date
        - last_modified: Last modification date
        - cvss_v3_score: CVSS v3 base score (if available)
        - cvss_v3_severity: Severity rating (if available)
        - cvss_v2_score: CVSS v2 base score (if available)
        - affected_products: List of affected CPE configurations
        - references: List of reference URLs
        - weaknesses: List of CWE identifiers
    
    Raises:
        Exception: If CVE not found or API error occurs
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id.upper()}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            if data.get("totalResults", 0) == 0:
                return {"error": f"CVE {cve_id} not found in NVD database"}
            
            cve = data["vulnerabilities"][0]["cve"]
            
            # Extract CVSS scores
            cvss_v3_score = None
            cvss_v3_severity = None
            cvss_v2_score = None
            
            if "metrics" in cve:
                if "cvssMetricV31" in cve["metrics"] and cve["metrics"]["cvssMetricV31"]:
                    cvss_v3_score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    cvss_v3_severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV30" in cve["metrics"] and cve["metrics"]["cvssMetricV30"]:
                    cvss_v3_score = cve["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    cvss_v3_severity = cve["metrics"]["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                
                if "cvssMetricV2" in cve["metrics"] and cve["metrics"]["cvssMetricV2"]:
                    cvss_v2_score = cve["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
            
            # Extract description
            description = ""
            if "descriptions" in cve:
                for desc in cve["descriptions"]:
                    if desc["lang"] == "en":
                        description = desc["value"]
                        break
            
            # Extract references
            references = []
            if "references" in cve:
                references = [ref["url"] for ref in cve["references"][:10]]  # Limit to first 10
            
            # Extract weaknesses (CWEs)
            weaknesses = []
            if "weaknesses" in cve:
                for weakness in cve["weaknesses"]:
                    for desc in weakness.get("description", []):
                        if desc["lang"] == "en":
                            weaknesses.append(desc["value"])
            
            # Extract affected products (CPEs)
            affected_products = []
            if "configurations" in cve:
                for config in cve["configurations"]:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            if match.get("vulnerable", False):
                                affected_products.append(match["criteria"])
            
            result = {
                "id": cve["id"],
                "description": description,
                "published_date": cve.get("published", "N/A"),
                "last_modified": cve.get("lastModified", "N/A"),
                "cvss_v3_score": cvss_v3_score,
                "cvss_v3_severity": cvss_v3_severity,
                "cvss_v2_score": cvss_v2_score,
                "affected_products": affected_products[:15],  # Limit output
                "references": references,
                "weaknesses": weaknesses,
            }
            
            return result
            
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP error occurred: {e.response.status_code} - {e.response.text}"}
    except httpx.RequestError as e:
        return {"error": f"Network error occurred: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


async def search_nvd(product: str, version: str) -> Dict[str, Any]:
    """
    Search the NVD for CVEs affecting a specific software product and version.
    
    Args:
        product: Product name (e.g., "apache", "log4j", "openssl")
        version: Version number (e.g., "2.14.1", "1.1.1")
    
    Returns:
        Dictionary containing:
        - product: Searched product name
        - version: Searched version
        - total_results: Total number of CVEs found
        - cves: List of CVE summaries, each containing:
            - id: CVE identifier
            - description: Brief description
            - cvss_v3_score: CVSS v3 score (if available)
            - cvss_v3_severity: Severity rating
            - published_date: Publication date
    
    Raises:
        Exception: If API error occurs
    """
    # Construct CPE search string
    # Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    # For simplicity, we'll use keyword search which is more flexible
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Use keywordSearch to find CVEs mentioning the product and version
    params = {
        "keywordSearch": f"{product} {version}",
        "resultsPerPage": 20
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            total_results = data.get("totalResults", 0)
            
            if total_results == 0:
                return {
                    "product": product,
                    "version": version,
                    "total_results": 0,
                    "cves": [],
                    "message": f"No CVEs found for {product} {version}"
                }
            
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln["cve"]
                
                # Extract CVSS score
                cvss_v3_score = None
                cvss_v3_severity = None
                
                if "metrics" in cve:
                    if "cvssMetricV31" in cve["metrics"] and cve["metrics"]["cvssMetricV31"]:
                        cvss_v3_score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        cvss_v3_severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                    elif "cvssMetricV30" in cve["metrics"] and cve["metrics"]["cvssMetricV30"]:
                        cvss_v3_score = cve["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]
                        cvss_v3_severity = cve["metrics"]["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                
                # Extract description
                description = ""
                if "descriptions" in cve:
                    for desc in cve["descriptions"]:
                        if desc["lang"] == "en":
                            description = desc["value"][:200] + "..." if len(desc["value"]) > 200 else desc["value"]
                            break
                
                cves.append({
                    "id": cve["id"],
                    "description": description,
                    "cvss_v3_score": cvss_v3_score,
                    "cvss_v3_severity": cvss_v3_severity,
                    "published_date": cve.get("published", "N/A"),
                })
            
            return {
                "product": product,
                "version": version,
                "total_results": total_results,
                "cves": cves,
            }
            
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP error occurred: {e.response.status_code} - {e.response.text}"}
    except httpx.RequestError as e:
        return {"error": f"Network error occurred: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
