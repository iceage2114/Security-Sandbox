"""
Integration tests for Shodan API tools.
Uses mocked HTTP responses to test IP enrichment functionality.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch
from tools.shodan import enrich_ip


@pytest.mark.asyncio
async def test_enrich_ip_success():
    """Test successful IP enrichment with Shodan."""
    mock_response = {
        "ip_str": "8.8.8.8",
        "hostnames": ["dns.google"],
        "domains": ["google"],
        "country_name": "United States",
        "city": "Mountain View",
        "org": "Google LLC",
        "isp": "Google LLC",
        "asn": "AS15169",
        "os": "Linux",
        "ports": [53, 443, 80],
        "last_update": "2024-02-20T10:00:00.000000",
        "data": [
            {
                "port": 53,
                "transport": "udp",
                "_shodan": {"module": "dns"},
                "product": "BIND",
                "version": "9.16.1",
                "data": "DNS server banner information here"
            },
            {
                "port": 443,
                "transport": "tcp",
                "_shodan": {"module": "https"},
                "product": "nginx",
                "version": "1.18.0",
                "data": "HTTPS server banner"
            }
        ]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"SHODAN_API_KEY": "test_api_key"}), \
         patch("tools.shodan._correlate_cves") as mock_correlate:
        
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        # Mock CVE correlation
        mock_correlate.return_value = [
            {
                "cve_id": "CVE-2021-25216",
                "service": "BIND 9.16.1",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "description": "BIND vulnerability..."
            }
        ]
        
        result = await enrich_ip("8.8.8.8")
        
        assert result["ip_address"] == "8.8.8.8"
        assert "dns.google" in result["hostnames"]
        assert result["country"] == "United States"
        assert result["org"] == "Google LLC"
        assert len(result["open_ports"]) == 3
        assert 53 in result["open_ports"]
        assert len(result["services"]) == 2
        assert result["services"][0]["product"] == "BIND"
        assert result["total_open_ports"] == 3
        assert len(result["vulnerabilities"]) > 0


@pytest.mark.asyncio
async def test_enrich_ip_not_found():
    """Test IP not found in Shodan database."""
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"SHODAN_API_KEY": "test_api_key"}):
        
        mock_response = AsyncMock(status_code=404)
        mock_response.json = lambda: {}
        
        def raise_error():
            raise httpx.HTTPStatusError(
                "404 Not Found",
                request=AsyncMock(),
                response=mock_response
            )
        
        mock_response.raise_for_status = raise_error
        mock_get.return_value = mock_response
        
        result = await enrich_ip("192.168.1.1")
        
        assert result["ip_address"] == "192.168.1.1"
        assert "not found" in result["message"].lower()
        assert result["open_ports"] == []


@pytest.mark.asyncio
async def test_enrich_ip_no_api_key():
    """Test error when API key is missing."""
    with patch.dict("os.environ", {}, clear=True):
        result = await enrich_ip("8.8.8.8")
        
        assert "error" in result
        assert "API key not found" in result["error"]


@pytest.mark.asyncio
async def test_enrich_ip_with_multiple_services():
    """Test IP with multiple services and ports."""
    mock_response = {
        "ip_str": "203.0.113.1",
        "hostnames": [],
        "domains": [],
        "country_name": "Germany",
        "city": "Frankfurt",
        "org": "Hosting Provider",
        "isp": "Example ISP",
        "asn": "AS12345",
        "os": "Windows Server 2019",
        "ports": [21, 22, 80, 443, 3389],
        "last_update": "2024-02-15T12:00:00.000000",
        "data": [
            {
                "port": 22,
                "transport": "tcp",
                "_shodan": {"module": "ssh"},
                "product": "OpenSSH",
                "version": "7.4",
                "data": "SSH-2.0-OpenSSH_7.4"
            },
            {
                "port": 80,
                "transport": "tcp",
                "_shodan": {"module": "http"},
                "product": "Apache",
                "version": "2.4.41",
                "data": "HTTP/1.1 200 OK"
            },
            {
                "port": 3389,
                "transport": "tcp",
                "_shodan": {"module": "rdp"},
                "product": "Microsoft Terminal Services",
                "version": "Unknown",
                "data": "RDP service"
            }
        ]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"SHODAN_API_KEY": "test_api_key"}), \
         patch("tools.shodan._correlate_cves") as mock_correlate:
        
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        mock_correlate.return_value = []
        
        result = await enrich_ip("203.0.113.1")
        
        assert result["total_open_ports"] == 5
        assert result["total_services"] == 3
        assert 22 in result["open_ports"]
        assert 3389 in result["open_ports"]
        assert any(s["product"] == "OpenSSH" for s in result["services"])


@pytest.mark.asyncio
async def test_enrich_ip_rate_limit():
    """Test rate limit error handling."""
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"SHODAN_API_KEY": "test_api_key"}):
        
        mock_response = AsyncMock(status_code=429, text="Rate limit exceeded")
        mock_response.json = lambda: {}
        
        def raise_error():
            raise httpx.HTTPStatusError(
                "429 Too Many Requests",
                request=AsyncMock(),
                response=mock_response
            )
        
        mock_response.raise_for_status = raise_error
        mock_get.return_value = mock_response
        
        result = await enrich_ip("8.8.8.8")
        
        assert "error" in result
        assert "rate limit" in result["error"].lower()
