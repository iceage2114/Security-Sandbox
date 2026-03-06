"""
Integration tests for VirusTotal API tools.
Uses mocked HTTP responses to test IOC lookup functionality.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from tools.virustotal import search_ioc, _detect_indicator_type


def test_detect_indicator_type():
    """Test indicator type detection."""
    assert _detect_indicator_type("8.8.8.8") == "ip"
    assert _detect_indicator_type("malicious.com") == "domain"
    assert _detect_indicator_type("http://example.com/malware") == "url"
    assert _detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # MD5
    assert _detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"  # SHA1
    assert _detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"  # SHA256
    assert _detect_indicator_type("invalid!!indicator") == "unknown"


@pytest.mark.asyncio
async def test_search_ioc_malicious_ip():
    """Test IOC lookup for malicious IP."""
    mock_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 15,
                    "suspicious": 2,
                    "harmless": 50,
                    "undetected": 10
                },
                "reputation": -50,
                "last_analysis_date": 1645444800,
                "last_analysis_results": {
                    "Kaspersky": {
                        "category": "malicious",
                        "result": "Malware"
                    },
                    "Microsoft": {
                        "category": "malicious",
                        "result": "Trojan"
                    }
                }
            }
        }
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test_api_key"}):
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await search_ioc("8.8.8.8")
        
        assert result["indicator"] == "8.8.8.8"
        assert result["type"] == "ip"
        assert result["malicious"] == 15
        assert result["suspicious"] == 2
        assert result["total_vendors"] == 77
        assert "MALICIOUS" in result["verdict"]
        assert len(result["top_verdicts"]) > 0


@pytest.mark.asyncio
async def test_search_ioc_clean_domain():
    """Test IOC lookup for clean domain."""
    mock_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5
                },
                "reputation": 100,
                "last_analysis_date": 1645444800,
                "last_analysis_results": {}
            }
        }
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test_api_key"}):
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await search_ioc("google.com")
        
        assert result["type"] == "domain"
        assert result["malicious"] == 0
        assert result["harmless"] == 70
        assert "CLEAN" in result["verdict"]


@pytest.mark.asyncio
async def test_search_ioc_not_found():
    """Test IOC not found in database."""
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test_api_key"}):
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
        
        result = await search_ioc("192.168.1.1")
        
        assert result["type"] == "ip"
        assert "not found" in result["message"].lower()
        assert result["malicious"] == 0


@pytest.mark.asyncio
async def test_search_ioc_no_api_key():
    """Test error when API key is missing."""
    with patch.dict("os.environ", {}, clear=True):
        result = await search_ioc("8.8.8.8")
        
        assert "error" in result
        assert "API key not found" in result["error"]
        assert "hint" in result


@pytest.mark.asyncio
async def test_search_ioc_rate_limit():
    """Test rate limit error handling."""
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test_api_key"}):
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
        
        result = await search_ioc("8.8.8.8")
        
        assert "error" in result
        assert "rate limit" in result["error"].lower()


@pytest.mark.asyncio
async def test_search_ioc_file_hash():
    """Test file hash lookup."""
    mock_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 5,
                    "harmless": 0,
                    "undetected": 10
                },
                "reputation": -100,
                "last_analysis_date": 1645444800,
                "last_analysis_results": {
                    "Kaspersky": {
                        "category": "malicious",
                        "result": "Trojan.Win32.Generic"
                    }
                }
            }
        }
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test_api_key"}):
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await search_ioc("d41d8cd98f00b204e9800998ecf8427e")
        
        assert result["type"] == "hash"
        assert result["malicious"] == 45
        assert "MALICIOUS" in result["verdict"]
