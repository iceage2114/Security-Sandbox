# CLAUDE MCP USAGE GUIDE

## How to Use Your Threat Intel MCP Server with Claude

Once your MCP server is configured and running, Claude Desktop will automatically detect and load the available tools. Here's how to use them effectively:

---

## 📌 Checking Available Tools

When you open Claude Desktop after configuring the MCP server, the tools should be automatically available. You can verify this by simply asking:

```
"What threat intelligence tools do you have access to?"
```

Claude will list all 6 available tools from your server.

---

## 🎯 Using the Tools

### Natural Language Queries

The best part about MCP is that you can ask Claude questions naturally, and it will automatically choose and invoke the appropriate tools:

#### Example 1: CVE Research
```
User: "Tell me everything about CVE-2021-44228"
```

**What Claude does:**
- Automatically calls `lookup_cve("CVE-2021-44228")`
- Returns detailed vulnerability information including CVSS scores, affected products, and references
- Explains the findings in easy-to-understand language

#### Example 2: Software Vulnerability Check
```
User: "Is Apache Log4j version 2.14.1 vulnerable?"
```

**What Claude does:**
- Calls `search_nvd("log4j", "2.14.1")`
- Returns all known CVEs affecting that version
- Summarizes the severity and recommends actions

#### Example 3: IP Reputation Check
```
User: "Is 45.142.212.61 a malicious IP address?"
```

**What Claude does:**
- Calls `search_ioc("45.142.212.61")` for VirusTotal data
- Calls `check_ip_reputation("45.142.212.61")` for AbuseIPDB data
- Combines both results to give you a comprehensive assessment

#### Example 4: Complete IP Analysis
```
User: "Give me a full security profile for IP 203.0.113.50"
```

**What Claude does:**
- Calls `enrich_ip("203.0.113.50")` to get Shodan data
- May also call `check_ip_reputation()` and `search_ioc()`
- Provides detailed report including:
  - Open ports and services
  - Running software versions
  - Known vulnerabilities (CVEs) for detected services
  - Reputation scores
  - Geographic location and ISP info

#### Example 5: Attack Technique Research
```
User: "Explain MITRE ATT&CK technique T1059.001 and how to detect it"
```

**What Claude does:**
- Calls `get_attack_technique("T1059.001")`
- Returns technique details, tactics, detection methods
- Explains in context with real-world examples

---

## 🔍 Advanced Usage Patterns

### Multi-Tool Investigations

You can ask complex questions that require multiple tools:

```
User: "I found this IP in my logs: 192.0.2.45. Can you:
1. Check if it's malicious
2. See what services are running
3. Find vulnerabilities in those services"
```

Claude will orchestrate multiple tool calls:
- `check_ip_reputation("192.0.2.45")`
- `search_ioc("192.0.2.45")`
- `enrich_ip("192.0.2.45")`
- Correlate the results and provide a comprehensive report

### Batch Queries

```
User: "Check these IPs for malicious activity:
- 8.8.8.8
- 192.0.2.1
- 198.51.100.42"
```

Claude will loop through each IP and check them using the appropriate tools.

### Vulnerability Research Workflow

```
User: "I'm running nginx 1.18.0 on Ubuntu. What should I be worried about?"
```

Claude will:
1. Search for nginx vulnerabilities
2. Explain the severity of each CVE
3. Provide mitigation recommendations

---

## 💡 Best Practices

### 1. Be Specific
Instead of: "Check this IP"
Try: "Check if IP 192.0.2.50 is listed in threat intelligence databases"

### 2. Ask Follow-up Questions
```
User: "What's CVE-2021-44228?"
Claude: [explains Log4Shell]
User: "Which versions of Log4j are affected?"
Claude: [uses the CVE data to answer]
```

### 3. Request Summaries
```
User: "Give me a one-paragraph summary of what CVE-2021-44228 is and why it matters"
```

### 4. Combine with Analysis
```
User: "Look up CVE-2021-44228 and explain how the attack technique maps to MITRE ATT&CK"
```

---

## 🛠️ Tool-Specific Usage

### lookup_cve
**When to use:** Need detailed information about a specific CVE

**Examples:**
- "What's the CVSS score for CVE-2023-12345?"
- "Show me all the references for CVE-2021-44228"
- "When was CVE-2022-1234 published?"

### search_nvd
**When to use:** Checking if specific software versions have known vulnerabilities

**Examples:**
- "Find vulnerabilities in Apache 2.4.49"
- "Are there CVEs for OpenSSL 1.1.1k?"
- "Search for nginx 1.20.1 CVEs"

### search_ioc
**When to use:** Checking if an IP, domain, URL, or file hash is malicious

**Examples:**
- "Is malicious-site.com a threat?"
- "Check this file hash: d41d8cd98f00b204e9800998ecf8427e"
- "Is http://suspicious-url.com/malware.exe safe?"

### check_ip_reputation
**When to use:** Need abuse reports and reputation data for an IP

**Examples:**
- "What's the abuse score for 192.0.2.1?"
- "Has 198.51.100.50 been reported for malicious activity?"
- "Show me recent abuse reports for this IP"

### enrich_ip
**When to use:** Need comprehensive intelligence on an IP (ports, services, CVEs)

**Examples:**
- "What services are running on 203.0.113.100?"
- "Scan 198.51.100.75 and find vulnerabilities"
- "Give me a full security assessment of this IP"

### get_attack_technique
**When to use:** Researching attack methods and TTPs

**Examples:**
- "Explain MITRE technique T1059"
- "What are the detection methods for T1566.001?"
- "Show me tactics related to T1055"

---

## 🔔 Understanding Tool Responses

### Success Responses
When a tool succeeds, Claude will present the data in a human-readable format:

```
User: "Check CVE-2021-44228"

Claude: "CVE-2021-44228 is the infamous Log4Shell vulnerability...
- CVSS Score: 10.0 (CRITICAL)
- Affects: Apache Log4j 2.0-beta9 through 2.14.1
- Published: December 10, 2021
- [continues with details]"
```

### Error Responses

If an API key is missing:
```
Claude: "I tried to check that IP with VirusTotal, but the API key isn't configured..."
```

If rate limited:
```
Claude: "The API rate limit was exceeded. You may need to wait before trying again..."
```

If not found:
```
Claude: "That CVE ID doesn't exist in the NVD database. Double-check the ID format..."
```

---

## 🚨 Testing Your Setup

Try these test queries to ensure everything works:

1. **Test NVD (no API key needed):**
   ```
   "Look up CVE-2021-44228"
   ```

2. **Test VirusTotal (requires API key):**
   ```
   "Check if 8.8.8.8 is malicious using VirusTotal"
   ```

3. **Test AbuseIPDB (requires API key):**
   ```
   "Get abuse reports for 8.8.8.8"
   ```

4. **Test Shodan (requires API key):**
   ```
   "What services are running on 8.8.8.8?"
   ```

5. **Test MITRE (no API key needed):**
   ```
   "Explain MITRE ATT&CK technique T1059"
   ```

---

## 🐛 Troubleshooting

### "I don't see the tools"
- Restart Claude Desktop completely
- Check the MCP server configuration in `claude_desktop_config.json`
- Verify the path to `server.py` is correct
- Check Claude Desktop logs for errors

### "API key errors"
- Verify your `.env` file exists and has the correct keys
- Ensure API keys are also in the Claude Desktop config JSON
- Try regenerating your API keys

### "Tool always times out"
- Check your internet connection
- Some APIs may be temporarily down
- Increase timeout values in tool modules if needed

---

## 📚 Example Conversation Flow

```
User: "I'm investigating a potential breach. The attacker's IP is 203.0.113.42"

Claude: "Let me gather intelligence on that IP address..."
[calls check_ip_reputation, search_ioc, enrich_ip]

Claude: "Here's what I found:
- AbuseIPDB shows an 85% abuse confidence score with 47 reports
- VirusTotal has 12/89 vendors flagging it as malicious
- Shodan reveals:
  - Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
  - Running OpenSSH 7.4 (has known CVEs: CVE-2021-xyz)
  - Located in Russia, ISP: Example Hosting

This IP is highly suspicious..."

User: "What attack technique might they use with SSH?"

Claude: "Let me check MITRE ATT&CK..."
[calls get_attack_technique for relevant SSH techniques]

Claude: "They might use T1021.004 (SSH Remote Services)..."
```

---

## 🎉 You're Ready!

You now have a powerful threat intelligence assistant. Just ask Claude natural questions about:
- CVEs and vulnerabilities
- Suspicious IPs, domains, or files
- Attack techniques and tactics
- Software security posture

Claude will automatically invoke the appropriate tools and provide comprehensive, actionable intelligence.

**Enjoy your cybersecurity research! 🛡️**
