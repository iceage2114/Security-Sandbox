function extractText(result) {
  if (!result) return ''
  // MCP callTool returns { content: [{ type: 'text', text: '...' }] }
  if (result.content && Array.isArray(result.content)) {
    return result.content
      .filter(c => c.type === 'text')
      .map(c => c.text)
      .join('\n')
  }
  if (typeof result === 'string') return result
  return JSON.stringify(result, null, 2)
}

export default function ResultDisplay({ result, accentColor }) {
  if (!result) return null

  if (result.loading) {
    return (
      <div className="result-display">
        <div className="result-header">
          <span className="result-label">Output</span>
        </div>
        <div className="result-content" style={{ color: '#4a6080' }}>
          Fetching results…
        </div>
      </div>
    )
  }

  if (result.error) {
    return (
      <div className="result-display">
        <div className="result-header">
          <span className="result-label">Output</span>
          <span className="result-badge error">Error</span>
        </div>
        <div className="result-error">{result.error}</div>
      </div>
    )
  }

  if (result.result) {
    const text = extractText(result.result)
    return (
      <div className="result-display">
        <div className="result-header">
          <span className="result-label">Output</span>
          <span className="result-badge success" style={{ '--accent': accentColor }}>Success</span>
        </div>
        <pre className="result-content">{text}</pre>
      </div>
    )
  }

  return null
}
