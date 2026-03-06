"""
Shodan API Integration

Provides tools for IP enrichment, including port scanning, service detection,
and vulnerability correlation with NVD.
API Documentation: https://developer.shodan.io/api
"""

import httpx
import os
from typing import Dict, Any, List


async def enrich_ip(ip: str) -> Dict[str, Any]:
    """
    Perform deep enrichment on an IP address using Shodan.
    
    Discovers open ports, running services, technologies, and banner information.
    Cross-references detected services with NVD to identify potential CVEs.
    
    Args:
        ip: IPv4 address to enrich (e.g., "8.8.8.8")
    
    Returns:
        Dictionary containing:
        - ip_address: The queried IP address
        - hostnames: List of hostnames associated with the IP
        - domains: List of domains
        - country: Country where the IP is located
        - city: City location
        - org: Organization that owns the IP
        - isp: Internet Service Provider
        - asn: Autonomous System Number
        - open_ports: List of open ports with service information
        - services: Detailed information about detected services:
            - port: Port number
            - protocol: Transport protocol (tcp/udp)
            - service: Service name (http, ssh, ftp, etc.)
            - product: Software product name
            - version: Software version
            - banner: Service banner
        - vulnerabilities: List of CVEs found for detected services:
            - cve_id: CVE identifier
            - service: Affected service
            - cvss_score: CVSS score
        - os: Operating system information
        - last_update: When Shodan last scanned this IP
    
    Raises:
        Exception: If API key is missing or API error occurs
    """
    api_key = os.getenv("SHODAN_API_KEY")
    
    if not api_key:
        return {
            "error": "Shodan API key not found. Please set SHODAN_API_KEY in .env file",
            "hint": "Get an API key at https://account.shodan.io/register"
        }
    
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": api_key}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, params=params)
            
            if response.status_code == 404:
                return {
                    "ip_address": ip,
                    "message": "IP address not found in Shodan database. It may not have been scanned yet.",
                    "open_ports": [],
                    "services": []
                }
            
            response.raise_for_status()
            data = response.json()
            
            # Extract basic information
            hostnames = data.get("hostnames", [])
            domains = data.get("domains", [])
            country = data.get("country_name", "Unknown")
            city = data.get("city", "Unknown")
            org = data.get("org", "Unknown")
            isp = data.get("isp", "Unknown")
            asn = data.get("asn", "Unknown")
            os_info = data.get("os", "Unknown")
            last_update = data.get("last_update", "Unknown")
            
            # Extract port information
            ports = data.get("ports", [])
            
            # Extract detailed service information
            services = []
            detected_products = []  # For CVE correlation
            
            for item in data.get("data", []):
                service_info = {
                    "port": item.get("port"),
                    "protocol": item.get("transport", "tcp"),
                    "service": item.get("_shodan", {}).get("module", "unknown"),
                    "product": item.get("product", "Unknown"),
                    "version": item.get("version", "Unknown"),
                    "banner": item.get("data", "")[:200] + "..." if len(item.get("data", "")) > 200 else item.get("data", ""),
                }
                services.append(service_info)
                
                # Track products for vulnerability lookup
                if service_info["product"] != "Unknown" and service_info["version"] != "Unknown":
                    detected_products.append({
                        "product": service_info["product"],
                        "version": service_info["version"]
                    })
            
            # Cross-reference with NVD for CVEs (limited to avoid rate limiting)
            vulnerabilities = []
            if detected_products:
                vulnerabilities = await _correlate_cves(detected_products[:3])  # Limit to 3 products
            
            result = {
                "ip_address": ip,
                "hostnames": hostnames,
                "domains": domains,
                "country": country,
                "city": city,
                "org": org,
                "isp": isp,
                "asn": asn,
                "open_ports": ports,
                "services": services,
                "vulnerabilities": vulnerabilities,
                "os": os_info,
                "last_update": last_update,
                "total_open_ports": len(ports),
                "total_services": len(services),
            }
            
            return result
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return {"error": "Invalid Shodan API key. Please check your SHODAN_API_KEY in .env"}
        elif e.response.status_code == 429:
            return {"error": "Shodan API rate limit exceeded. Please wait before retrying."}
        return {"error": f"HTTP error occurred: {e.response.status_code}"}
    except httpx.RequestError as e:
        return {"error": f"Network error occurred: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


async def _correlate_cves(products: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Cross-reference detected products with NVD to find related CVEs.
    
    Args:
        products: List of dicts with 'product' and 'version' keys
    
    Returns:
        List of CVE dictionaries with id, service, and cvss_score
    """
    vulnerabilities = []
    
    # Import the NVD search function
    try:
        from .nvd import search_nvd
    except ImportError:
        return []
    
    for product_info in products:
        product = product_info["product"]
        version = product_info["version"]
        
        try:
            # Query NVD for this product/version
            result = await search_nvd(product, version)
            
            if "error" not in result and result.get("total_results", 0) > 0:
                # Add top 3 CVEs for this product
                for cve in result.get("cves", [])[:3]:
                    vulnerabilities.append({
                        "cve_id": cve["id"],
                        "service": f"{product} {version}",
                        "cvss_score": cve.get("cvss_v3_score"),
                        "severity": cve.get("cvss_v3_severity"),
                        "description": cve.get("description", "")[:150] + "..."
                    })
        except Exception:
            # Silently skip on error to avoid breaking the main enrichment
            continue
    
    return vulnerabilities
