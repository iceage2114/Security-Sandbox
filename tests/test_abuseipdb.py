"""
Integration tests for AbuseIPDB API tools.
Uses mocked HTTP responses to test IP reputation checks.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch
from tools.abuseipdb import check_ip_reputation


@pytest.mark.asyncio
async def test_check_ip_reputation_high_risk():
    """Test high-risk IP reputation check."""
    mock_response = {
        "data": {
            "ipAddress": "192.0.2.1",
            "abuseConfidenceScore": 95,
            "totalReports": 150,
            "numDistinctUsers": 45,
            "lastReportedAt": "2024-02-15T10:30:00+00:00",
            "countryCode": "CN",
            "countryName": "China",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example Hosting Ltd",
            "domain": "example.com",
            "isWhitelisted": False,
            "isPublic": True,
            "reports": [
                {
                    "reportedAt": "2024-02-15T10:30:00+00:00",
                    "comment": "SSH brute force attack",
                    "categories": [22],
                    "reporterCountryCode": "US"
                },
                {
                    "reportedAt": "2024-02-14T08:15:00+00:00",
                    "comment": "Port scanning",
                    "categories": [14],
                    "reporterCountryCode": "GB"
                }
            ]
        }
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_api_key"}):
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await check_ip_reputation("192.0.2.1")
        
        assert result["ip_address"] == "192.0.2.1"
        assert result["abuse_confidence_score"] == 95
        assert result["risk_level"] == "HIGH"
        assert result["total_reports"] == 150
        assert result["country_code"] == "CN"
        assert "HIGH RISK" in result["verdict"]
        assert len(result["recent_reports"]) == 2


@pytest.mark.asyncio
async def test_check_ip_reputation_clean():
    """Test clean IP with no reports."""
    mock_response = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None,
            "countryCode": "US",
            "countryName": "United States",
            "usageType": "Content Delivery Network",
            "isp": "Google LLC",
            "domain": "google.com",
            "isWhitelisted": True,
            "isPublic": True,
            "reports": []
        }
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_api_key"}):
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await check_ip_reputation("8.8.8.8")
        
        assert result["abuse_confidence_score"] == 0
        assert result["risk_level"] == "CLEAN"
        assert result["total_reports"] == 0
        assert result["is_whitelisted"] is True
        assert "CLEAN" in result["verdict"]


@pytest.mark.asyncio
async def test_check_ip_reputation_moderate_risk():
    """Test moderate risk IP."""
    mock_response = {
        "data": {
            "ipAddress": "198.51.100.1",
            "abuseConfidenceScore": 60,
            "totalReports": 25,
            "numDistinctUsers": 10,
            "lastReportedAt": "2024-02-20T14:00:00+00:00",
            "countryCode": "RU",
            "countryName": "Russia",
            "usageType": "Fixed Line ISP",
            "isp": "Example ISP",
            "domain": "example.ru",
            "isWhitelisted": False,
            "isPublic": True,
            "reports": []
        }
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_api_key"}):
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await check_ip_reputation("198.51.100.1")
        
        assert result["abuse_confidence_score"] == 60
        assert result["risk_level"] == "MODERATE"
        assert "MODERATE RISK" in result["verdict"]


@pytest.mark.asyncio
async def test_check_ip_reputation_invalid_ip():
    """Test invalid IP address format."""
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_api_key"}):
        mock_response = AsyncMock(status_code=422, text="Invalid IP")
        mock_response.json = lambda: {}
        
        def raise_error():
            raise httpx.HTTPStatusError(
                "422 Unprocessable Entity",
                request=AsyncMock(),
                response=mock_response
            )
        
        mock_response.raise_for_status = raise_error
        mock_get.return_value = mock_response
        
        result = await check_ip_reputation("invalid_ip")
        
        assert "error" in result
        assert "Invalid IP address" in result["error"]


@pytest.mark.asyncio
async def test_check_ip_reputation_no_api_key():
    """Test error when API key is missing."""
    with patch.dict("os.environ", {}, clear=True):
        result = await check_ip_reputation("8.8.8.8")
        
        assert "error" in result
        assert "API key not found" in result["error"]


@pytest.mark.asyncio
async def test_check_ip_reputation_rate_limit():
    """Test rate limit error handling."""
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_api_key"}):
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
        
        result = await check_ip_reputation("8.8.8.8")
        
        assert "error" in result
        assert "rate limit" in result["error"].lower()
