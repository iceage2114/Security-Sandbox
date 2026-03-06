"""
Integration tests for MITRE ATT&CK API tools.
Uses mocked HTTP responses to test attack technique queries.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch
from tools.mitre import get_attack_technique


@pytest.mark.asyncio
async def test_get_attack_technique_success():
    """Test successful ATT&CK technique lookup."""
    mock_response = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution"
                    }
                ],
                "x_mitre_platforms": ["Windows", "Linux", "macOS"],
                "x_mitre_data_sources": ["Process: Process Creation", "Command: Command Execution"],
                "x_mitre_detection": "Command-line and scripting activities can be captured through proper logging.",
                "created": "2019-03-11T14:00:00.000Z",
                "modified": "2023-10-01T09:00:00.000Z",
                "x_mitre_version": "2.3",
                "x_mitre_deprecated": False
            }
        ]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch("tools.mitre._get_mitigations_for_technique") as mock_mitigations:
        
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        mock_mitigations.return_value = [
            "Implement least privilege access controls",
            "Use application whitelisting"
        ]
        
        result = await get_attack_technique("T1059")
        
        assert result["technique_id"] == "T1059"
        assert result["name"] == "Command and Scripting Interpreter"
        assert "command and script interpreters" in result["description"].lower()
        assert "execution" in [t.lower() for t in result["tactics"]]
        assert "Windows" in result["platforms"]
        assert len(result["data_sources"]) > 0
        assert "logging" in result["detection"].lower()
        assert result["deprecated"] is False
        assert len(result["mitigations"]) > 0


@pytest.mark.asyncio
async def test_get_attack_technique_sub_technique():
    """Test sub-technique lookup (e.g., T1059.001)."""
    mock_response = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--970cdb5c-02fb-4c38-b17e-d6327cf3c810",
                "name": "PowerShell",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution"
                    }
                ],
                "x_mitre_platforms": ["Windows"],
                "x_mitre_data_sources": ["Process: Process Creation", "Script: Script Execution"],
                "x_mitre_detection": "Monitor PowerShell execution and script block logging.",
                "created": "2020-03-09T14:00:00.000Z",
                "modified": "2023-09-15T12:00:00.000Z",
                "x_mitre_version": "1.5",
                "x_mitre_deprecated": False
            }
        ]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch("tools.mitre._get_mitigations_for_technique") as mock_mitigations:
        
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        mock_mitigations.return_value = []
        
        result = await get_attack_technique("T1059.001")
        
        assert result["technique_id"] == "T1059.001"
        assert result["name"] == "PowerShell"
        assert "PowerShell" in result["description"]
        assert "Windows" in result["platforms"]
        assert "T1059/001" in result["url"]


@pytest.mark.asyncio
async def test_get_attack_technique_not_found():
    """Test technique not found scenario."""
    mock_response = {
        "objects": [
            # Empty list or objects that don't match
            {
                "type": "malware",
                "name": "Not a technique"
            }
        ]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        
        result = await get_attack_technique("T9999")
        
        assert "error" in result
        assert "not found" in result["error"].lower()
        assert "hint" in result


@pytest.mark.asyncio
async def test_get_attack_technique_multiple_tactics():
    """Test technique with multiple tactics."""
    mock_response = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may exploit vulnerabilities in public-facing applications.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1190"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "initial-access"
                    },
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "persistence"
                    }
                ],
                "x_mitre_platforms": ["Windows", "Linux", "macOS", "Network"],
                "x_mitre_data_sources": ["Application Log: Application Log Content"],
                "x_mitre_detection": "Monitor application logs for exploitation attempts.",
                "created": "2019-04-25T15:00:00.000Z",
                "modified": "2023-08-20T10:00:00.000Z",
                "x_mitre_version": "2.1",
                "x_mitre_deprecated": False
            }
        ]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch("tools.mitre._get_mitigations_for_technique") as mock_mitigations:
        
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        mock_mitigations.return_value = []
        
        result = await get_attack_technique("T1190")
        
        assert result["technique_id"] == "T1190"
        assert len(result["tactics"]) == 2
        assert "Initial Access" in result["tactics"]
        assert "Persistence" in result["tactics"]


@pytest.mark.asyncio
async def test_get_attack_technique_http_error():
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
        
        result = await get_attack_technique("T1059")
        
        assert "error" in result
        assert "500" in result["error"]


@pytest.mark.asyncio
async def test_get_attack_technique_deprecated():
    """Test deprecated technique."""
    mock_response = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Deprecated Technique",
                "description": "This technique is deprecated.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1234"
                    }
                ],
                "kill_chain_phases": [],
                "x_mitre_platforms": ["Windows"],
                "x_mitre_data_sources": [],
                "x_mitre_detection": "N/A",
                "created": "2018-01-01T00:00:00.000Z",
                "modified": "2019-06-01T00:00:00.000Z",
                "x_mitre_version": "1.0",
                "x_mitre_deprecated": True
            }
        ]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch("tools.mitre._get_mitigations_for_technique") as mock_mitigations:
        
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        mock_get.return_value.raise_for_status = lambda: None
        mock_mitigations.return_value = []
        
        result = await get_attack_technique("T1234")
        
        assert result["deprecated"] is True
