"""
Integration tests for NVD API tools.
Uses mocked HTTP responses to test tool functionality without hitting real APIs.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch
from tools.nvd import lookup_cve, search_nvd


@pytest.mark.asyncio
async def test_lookup_cve_success():
    """Test successful CVE lookup."""
    mock_response = {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 remote code execution vulnerability"}
                ],
                "published": "2021-12-10T10:15:09.000",
                "lastModified": "2021-12-14T19:15:00.000",
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL"
                        }
                    }]
                },
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"}
                ],
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-502"}]}
                ],
                "configurations": [
                    {
                        "nodes": [{
                            "cpeMatch": [{
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                            }]
                        }]
                    }
                ]
            }
        }]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await lookup_cve("CVE-2021-44228")
        
        assert result["id"] == "CVE-2021-44228"
        assert result["cvss_v3_score"] == 10.0
        assert result["cvss_v3_severity"] == "CRITICAL"
        assert "Log4j" in result["description"]
        assert len(result["references"]) > 0
        assert len(result["weaknesses"]) > 0


@pytest.mark.asyncio
async def test_lookup_cve_not_found():
    """Test CVE not found scenario."""
    mock_response = {"totalResults": 0, "vulnerabilities": []}
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await lookup_cve("CVE-9999-99999")
        
        assert "error" in result
        assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_lookup_cve_http_error():
    """Test HTTP error handling."""
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_response = AsyncMock(status_code=500, text="Server Error")
        mock_response.json = lambda: {}
        
        def raise_error():
            raise httpx.HTTPStatusError(
                "500 Server Error",
                request=AsyncMock(),
                response=mock_response
            )
        
        mock_response.raise_for_status = raise_error
        mock_get.return_value = mock_response
        
        result = await lookup_cve("CVE-2021-44228")
        
        assert "error" in result
        assert "500" in result["error"]


@pytest.mark.asyncio
async def test_search_nvd_success():
    """Test successful NVD search."""
    mock_response = {
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {"lang": "en", "value": "Log4j RCE vulnerability"}
                    ],
                    "published": "2021-12-10T10:15:09.000",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL"
                            }
                        }]
                    }
                }
            },
            {
                "cve": {
                    "id": "CVE-2021-45046",
                    "descriptions": [
                        {"lang": "en", "value": "Log4j DoS vulnerability"}
                    ],
                    "published": "2021-12-14T20:15:00.000",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.0,
                                "baseSeverity": "CRITICAL"
                            }
                        }]
                    }
                }
            }
        ]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await search_nvd("log4j", "2.14.1")
        
        assert result["product"] == "log4j"
        assert result["version"] == "2.14.1"
        assert result["total_results"] == 2
        assert len(result["cves"]) == 2
        assert result["cves"][0]["id"] == "CVE-2021-44228"
        assert result["cves"][0]["cvss_v3_score"] == 10.0


@pytest.mark.asyncio
async def test_search_nvd_no_results():
    """Test search with no results."""
    mock_response = {"totalResults": 0, "vulnerabilities": []}
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await search_nvd("nonexistent", "1.0.0")
        
        assert result["total_results"] == 0
        assert len(result["cves"]) == 0
        assert "message" in result
