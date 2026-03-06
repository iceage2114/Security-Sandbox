# Threat Intel MCP Server

A **FastMCP** server providing threat intelligence and vulnerability research tools for Claude. Integrates with NVD, VirusTotal, AbuseIPDB, Shodan, and MITRE ATT&CK.

---

## Tools

| Tool | Source | Description |
|---|---|---|
| `lookup_cve` | NVD | CVE details, CVSS scores, affected products |
| `search_nvd` | NVD | Search CVEs by product and version |
| `search_ioc` | VirusTotal | Check IPs, domains, URLs, or file hashes |
| `check_ip_reputation` | AbuseIPDB | Abuse confidence score and report history |
| `enrich_ip` | Shodan | Open ports, services, and correlated CVEs |
| `get_attack_technique` | MITRE ATT&CK | Technique details, tactics, and mitigations |

---

## Setup

**1. Create and activate a virtual environment:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**2. Install dependencies:**
```powershell
pip install -r requirements.txt
```

**3. Configure API keys** — copy `.env.example` to `.env` and fill in your keys:
```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
```

Free API keys: [VirusTotal](https://www.virustotal.com/gui/join-us) · [AbuseIPDB](https://www.abuseipdb.com/account/api) · [Shodan](https://account.shodan.io/register)

---

## Claude Desktop

Since the server now runs over HTTP, start it first, then configure Claude Desktop to connect via URL.

**1. Start the server** (keep this running):
```powershell
python server.py
```

**2.** Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "threat-intel": {
      "url": "http://127.0.0.1:8000/sse"
    }
  }
}
```

API keys are read from `.env` automatically. Restart Claude Desktop after saving.

---

## MCP Inspector

The server runs over HTTP (SSE) on port 8000. Start it first, then connect the inspector.

**1. Start the server:**
```powershell
python server.py
```

**2. Launch the inspector:**
```powershell
npx @modelcontextprotocol/inspector
```

Open **http://localhost:5173**, set transport to **SSE**, and enter the URL `http://127.0.0.1:8000/sse`.

---

## Adding New Tools

1. Create `tools/newtool.py` with your async function
2. Register it in `server.py`:

```python
from tools.newtool import my_function as _my_function

@mcp.tool()
async def my_tool(param: str) -> str:
    """Tool description shown in Inspector and to the LLM.

    Args:
        param: Parameter description
    """
    return str(await _my_function(param))
```

FastMCP generates the JSON schema automatically from the signature and docstring.

---

## API Rate Limits

| Service | Free Tier |
|---|---|
| VirusTotal | 4 req/min, 500 req/day |
| AbuseIPDB | 1,000 req/day |
| Shodan | 100 results/month |
| NVD | No key required |
| MITRE ATT&CK | No key required |

---

## Troubleshooting

**JSON-RPC / EOF errors** — Don't run `python server.py` directly. Use `mcp dev server.py` or Claude Desktop.

**API key not found** — Ensure `.env` exists in the project root with correctly named variables.

**Rate limit errors** — Wait before retrying, or upgrade to a paid API tier.

---