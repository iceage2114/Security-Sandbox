import { useState, useEffect, useCallback } from 'react'
import ToolCard from './components/ToolCard'
import ResultDisplay from './components/ResultDisplay'
import './App.css'

const TOOLS = [
  {
    id: 'lookup_cve',
    name: 'Lookup CVE',
    description: 'Query the NVD for detailed information about a specific CVE ID including CVSS scores and affected products.',
    icon: '🛡️',
    category: 'Vulnerability',
    accentColor: '#ff6b6b',
    inputs: [
      { name: 'cve_id', label: 'CVE ID', placeholder: 'e.g. CVE-2021-44228' },
    ],
  },
  {
    id: 'search_nvd',
    name: 'Search NVD',
    description: 'Search the NVD for CVEs affecting a specific software product and version.',
    icon: '🔍',
    category: 'Vulnerability',
    accentColor: '#ffd93d',
    inputs: [
      { name: 'product', label: 'Product', placeholder: 'e.g. apache, log4j' },
      { name: 'version', label: 'Version', placeholder: 'e.g. 2.14.1' },
    ],
  },
  {
    id: 'search_ioc',
    name: 'VirusTotal IOC',
    description: 'Check an Indicator of Compromise against VirusTotal. Supports IPs, domains, URLs, and hashes.',
    icon: '🦠',
    category: 'Threat Intel',
    accentColor: '#ff4757',
    inputs: [
      { name: 'indicator', label: 'Indicator', placeholder: 'IP, domain, URL, or hash (MD5/SHA1/SHA256)' },
    ],
  },
  {
    id: 'check_ip_reputation',
    name: 'IP Reputation',
    description: 'Query AbuseIPDB for IP reputation data including abuse confidence score and reports.',
    icon: '🌐',
    category: 'Threat Intel',
    accentColor: '#00d4ff',
    inputs: [
      { name: 'ip', label: 'IP Address', placeholder: 'e.g. 1.1.1.1' },
    ],
  },
  {
    id: 'enrich_ip',
    name: 'Shodan Enrich',
    description: 'Deep IP enrichment using Shodan: open ports, running services, and CVE cross-references.',
    icon: '📡',
    category: 'Recon',
    accentColor: '#a29bfe',
    inputs: [
      { name: 'ip', label: 'IP Address', placeholder: 'e.g. 8.8.8.8' },
    ],
  },
  {
    id: 'get_attack_technique',
    name: 'MITRE ATT&CK',
    description: 'Look up MITRE ATT&CK techniques: description, tactics, detection, and mitigations.',
    icon: '🎯',
    category: 'Framework',
    accentColor: '#00ff88',
    inputs: [
      { name: 'technique_id', label: 'Technique ID', placeholder: 'e.g. T1059, T1059.001' },
    ],
  },
]

export default function App() {
  const [status, setStatus] = useState({ connected: false, checking: true })
  const [activeTool, setActiveTool] = useState(null)
  const [toolInputs, setToolInputs] = useState({})
  const [toolResults, setToolResults] = useState({})
  const [connecting, setConnecting] = useState(false)

  const checkStatus = useCallback(async () => {
    setStatus(s => ({ ...s, checking: true }))
    try {
      const res = await fetch('/api/status')
      const data = await res.json()
      setStatus({ connected: data.connected, checking: false })
    } catch {
      setStatus({ connected: false, checking: false })
    }
  }, [])

  useEffect(() => {
    checkStatus()
  }, [checkStatus])

  async function handleConnect() {
    setConnecting(true)
    try {
      const res = await fetch('/api/connect', { method: 'POST' })
      const data = await res.json()
      setStatus({ connected: data.connected, checking: false })
    } catch {
      setStatus({ connected: false, checking: false })
    } finally {
      setConnecting(false)
    }
  }

  function handleToolClick(tool) {
    setActiveTool(prev => prev?.id === tool.id ? null : tool)
  }

  function handleInputChange(toolId, inputName, value) {
    setToolInputs(prev => ({
      ...prev,
      [toolId]: { ...(prev[toolId] || {}), [inputName]: value },
    }))
  }

  async function handleRun(tool) {
    const inputs = toolInputs[tool.id] || {}
    setToolResults(prev => ({
      ...prev,
      [tool.id]: { loading: true, result: null, error: null },
    }))
    try {
      const res = await fetch(`/api/call/${tool.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(inputs),
      })
      const data = await res.json()
      if (!res.ok) {
        setToolResults(prev => ({
          ...prev,
          [tool.id]: { loading: false, result: null, error: data.error || 'Request failed' },
        }))
      } else {
        setToolResults(prev => ({
          ...prev,
          [tool.id]: { loading: false, result: data, error: null },
        }))
      }
    } catch (err) {
      setToolResults(prev => ({
        ...prev,
        [tool.id]: { loading: false, result: null, error: err.message },
      }))
    }
  }

  const activeResult = activeTool ? toolResults[activeTool.id] : null

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <span className="header-logo">⚡</span>
          <div>
            <h1 className="header-title">Threat Intelligence Platform</h1>
            <p className="header-subtitle">Powered by MCP · NVD · VirusTotal · AbuseIPDB · Shodan · MITRE ATT&CK</p>
          </div>
        </div>
        <div className="header-right">
          <div className={`status-badge ${status.checking ? 'checking' : status.connected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot" />
            {status.checking ? 'Checking…' : status.connected ? 'MCP Connected' : 'MCP Disconnected'}
          </div>
          {!status.connected && !status.checking && (
            <button className="btn-connect" onClick={handleConnect} disabled={connecting}>
              {connecting ? 'Connecting…' : 'Connect'}
            </button>
          )}
          {status.connected && (
            <button className="btn-reconnect" onClick={handleConnect} disabled={connecting}>
              ↺ Reconnect
            </button>
          )}
        </div>
      </header>

      {/* Toolbar info */}
      {!status.connected && !status.checking && (
        <div className="alert-bar">
          ⚠️ MCP server is not running. Start it with <code>python server.py</code> from the project root, then click Connect.
        </div>
      )}

      {/* Tool Grid */}
      <main className="main">
        <section className="tools-section">
          <h2 className="section-title">Available Tools</h2>
          <div className="tools-grid">
            {TOOLS.map(tool => (
              <ToolCard
                key={tool.id}
                tool={tool}
                active={activeTool?.id === tool.id}
                result={toolResults[tool.id]}
                onClick={() => handleToolClick(tool)}
              />
            ))}
          </div>
        </section>

        {/* Active Tool Panel */}
        {activeTool && (
          <section className="active-panel" style={{ '--accent': activeTool.accentColor }}>
            <div className="active-panel-header">
              <span className="active-panel-icon">{activeTool.icon}</span>
              <div>
                <h3 className="active-panel-title">{activeTool.name}</h3>
                <p className="active-panel-desc">{activeTool.description}</p>
              </div>
              <button className="btn-close" onClick={() => setActiveTool(null)}>✕</button>
            </div>

            <div className="active-panel-form">
              {activeTool.inputs.map(input => (
                <div className="form-group" key={input.name}>
                  <label className="form-label">{input.label}</label>
                  <input
                    className="form-input"
                    type="text"
                    placeholder={input.placeholder}
                    value={(toolInputs[activeTool.id] || {})[input.name] || ''}
                    onChange={e => handleInputChange(activeTool.id, input.name, e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && status.connected && handleRun(activeTool)}
                  />
                </div>
              ))}
              <button
                className="btn-run"
                onClick={() => handleRun(activeTool)}
                disabled={!status.connected || activeResult?.loading}
                style={{ '--accent': activeTool.accentColor }}
              >
                {activeResult?.loading ? (
                  <><span className="spinner" /> Running…</>
                ) : (
                  <>▶ Run {activeTool.name}</>
                )}
              </button>
            </div>

            {activeResult && (
              <ResultDisplay result={activeResult} accentColor={activeTool.accentColor} />
            )}
          </section>
        )}
      </main>

      <footer className="footer">
        <span>Threat Intel MCP Server · <a href="http://localhost:8000" target="_blank" rel="noreferrer">MCP Server</a> · <a href="http://localhost:5173" target="_blank" rel="noreferrer">Frontend</a></span>
      </footer>
    </div>
  )
}
