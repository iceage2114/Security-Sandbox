"""
Threat Intelligence MCP Server

A cybersecurity-focused MCP server that provides threat intelligence and vulnerability research tools.
Integrates with NVD, VirusTotal, AbuseIPDB, Shodan, and MITRE ATT&CK.

Built with FastMCP for a clean, decorator-based tool registration API.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

# Warn about missing .env or unset API keys at startup so failures are obvious
_ENV_FILE = Path(__file__).parent / ".env"
if not _ENV_FILE.exists():
    print(
        "WARNING: .env file not found. API keys will not be loaded.\n"
        "Copy .env.example to .env and fill in your keys."
    )

_OPTIONAL_KEYS = {
    "VIRUSTOTAL_API_KEY": "search_ioc",
    "ABUSEIPDB_API_KEY": "check_ip_reputation",
    "SHODAN_API_KEY": "enrich_ip",
    "MALWAREBAZAAR_API_KEY": "summarize_malware / search_malware_samples",
    "GITHUB_TOKEN": "summarize_malware (GPT-4o via GitHub Models)",
}
_missing = [f"  {k} (used by: {v})" for k, v in _OPTIONAL_KEYS.items() if not os.getenv(k)]
if _missing:
    print("WARNING: The following API keys are not set — affected tools will return errors:")
    print("\n".join(_missing))

from tools.nvd import lookup_cve as _lookup_cve, search_nvd as _search_nvd
from tools.virustotal import search_ioc as _search_ioc
from tools.abuseipdb import check_ip_reputation as _check_ip_reputation
from tools.shodan import enrich_ip as _enrich_ip
from tools.mitre import get_attack_technique as _get_attack_technique

# Initialize FastMCP server
mcp = FastMCP("threat-intel-mcp", host="127.0.0.1", port=8000, stateless_http=True)


@mcp.tool()
async def lookup_cve(cve_id: str) -> str:
    """Query the NVD (National Vulnerability Database) for detailed information about a specific CVE ID.

    Returns vulnerability details, CVSS scores, affected products, and references.

    Args:
        cve_id: The CVE identifier (e.g., CVE-2021-44228)
    """
    result = await _lookup_cve(cve_id)
    return str(result)


@mcp.tool()
async def search_nvd(product: str, version: str) -> str:
    """Search the NVD for CVEs affecting a specific software product and version.

    Useful for vulnerability assessments and patch management.

    Args:
        product: Product name (e.g., 'apache', 'log4j')
        version: Version number (e.g., '2.14.1')
    """
    result = await _search_nvd(product, version)
    return str(result)


@mcp.tool()
async def search_ioc(indicator: str) -> str:
    """Check an Indicator of Compromise (IOC) against VirusTotal.

    Supports IP addresses, domains, URLs, and file hashes.
    Returns detection stats and vendor verdicts.

    Args:
        indicator: IP address, domain, URL, or file hash (MD5/SHA1/SHA256)
    """
    result = await _search_ioc(indicator)
    return str(result)


@mcp.tool()
async def check_ip_reputation(ip: str) -> str:
    """Query AbuseIPDB for IP reputation data.

    Returns abuse confidence score, total reports, usage type, and country information.

    Args:
        ip: IPv4 or IPv6 address to check
    """
    result = await _check_ip_reputation(ip)

    if "error" in result:
        return f"Error: {result['error']}"

    lines = [
        f"IP Reputation Report: {result['ip_address']}",
        f"{'='*45}",
        f"Verdict:          {result['verdict']}",
        f"Abuse Score:      {result['abuse_confidence_score']}/100",
        f"Risk Level:       {result['risk_level']}",
        f"",
        f"Location:         {result.get('country_name', 'Unknown')} ({result.get('country_code', '?')})",
        f"ISP:              {result.get('isp', 'Unknown')}",
        f"Domain:           {result.get('domain', 'N/A')}",
        f"Usage Type:       {result.get('usage_type', 'Unknown')}",
        f"",
        f"Total Reports:    {result['total_reports']}",
        f"Distinct Users:   {result['num_distinct_users']}",
        f"Last Reported:    {result.get('last_reported_at', 'Never')}",
        f"Whitelisted:      {result.get('is_whitelisted', False)}",
        f"Public IP:        {result.get('is_public', True)}",
    ]

    recent = result.get("recent_reports", [])
    if recent:
        lines.append("")
        lines.append("Recent Reports (up to 5):")
        for i, r in enumerate(recent, 1):
            lines.append(f"  [{i}] {r['reported_at']}  Country: {r['reporter_country']}")
            lines.append(f"      {r['comment'][:120]}")

    return "\n".join(lines)


@mcp.tool()
async def enrich_ip(ip: str) -> str:
    """Perform deep enrichment on an IP address using Shodan.

    Discovers open ports, running services, and technologies,
    then cross-references services with NVD to identify related CVEs.

    Args:
        ip: IPv4 address to enrich
    """
    result = await _enrich_ip(ip)
    return str(result)


@mcp.tool()
async def get_attack_technique(technique_id: str) -> str:
    """Query the MITRE ATT&CK framework for detailed information about an attack technique.

    Returns technique description, tactics, detection methods, and mitigation strategies.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., T1059, T1059.001)
    """
    result = await _get_attack_technique(technique_id)
    return str(result)


@mcp.tool()
async def summarize_malware(hash: str, source: str = "full") -> str:
    """Fetch public malware sandbox data and generate an AI-powered threat profile report.

    Queries MalwareBazaar and/or Hybrid Analysis for an existing sandbox report,
    then uses GPT-4o to produce a structured Markdown threat profile with behavior
    summary, MITRE ATT&CK mapping, IoCs, risk score, and remediation steps.

    Requires GITHUB_TOKEN and MALWAREBAZAAR_API_KEY in the environment.
    Set HYBRID_ANALYSIS_API_KEY and USE_JOE_SANDBOX=true for full behavioral data.

    Args:
        hash: SHA-256 hash of the malware sample
        source: Data source — "bazaar" (MalwareBazaar metadata only),
                "hybrid" (Hybrid Analysis behavioral data only),
                or "full" (both sources merged, recommended)
    """
    import asyncio
    from malware_summarizer.core.pipeline import run_pipeline
    from malware_summarizer.parsers.base import SandboxAPIError

    try:
        report_path = await asyncio.get_running_loop().run_in_executor(
            None, lambda: run_pipeline(source=source, identifier=hash)
        )
        return report_path.read_text(encoding="utf-8")
    except SandboxAPIError as exc:
        return f"Sandbox API error: {exc}"
    except ValueError as exc:
        return f"Invalid input: {exc}"
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
async def search_malware_samples(tag: str, limit: int = 10) -> str:
    """Search MalwareBazaar for malware samples matching a family tag.

    Returns a table of matching samples including SHA-256 hashes, file names,
    malware family signatures, and first-seen dates.

    Requires MALWAREBAZAAR_API_KEY in the environment.

    Args:
        tag: Malware family tag to search for (e.g. "emotet", "ransomware", "cobalt-strike")
        limit: Maximum number of results to return (1-100, default 10)
    """
    import asyncio
    from malware_summarizer.parsers.malwarebazaar import MalwareBazaarParser
    from malware_summarizer.parsers.base import SandboxAPIError

    try:
        parser = MalwareBazaarParser()
        raw = await asyncio.get_running_loop().run_in_executor(
            None, lambda: parser.fetch_by_tag(tag, limit=limit)
        )
        results = parser.parse_tag_search(raw)
    except SandboxAPIError as exc:
        return f"MalwareBazaar API error: {exc}"
    except Exception as exc:
        return f"Error: {exc}"

    if not results:
        return f"No samples found for tag: {tag}"

    lines = [f"MalwareBazaar results for tag: {tag}", "=" * 50]
    for r in results:
        lines.append(f"\nHash:       {r.sample_hash}")
        lines.append(f"File:       {r.file_name or 'Unknown'}")
        lines.append(f"Type:       {r.file_type or 'Unknown'}")
        lines.append(f"First Seen: {r.first_seen or 'Unknown'}")
        sigs = r.raw_signatures[:3] or r.tags[:3]
        if sigs:
            lines.append(f"Signatures: {', '.join(sigs)}")
    return "\n".join(lines)


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "streamable-http")
    mcp.run(transport=transport)
