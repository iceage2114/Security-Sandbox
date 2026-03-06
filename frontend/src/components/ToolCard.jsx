export default function ToolCard({ tool, active, result, onClick }) {
  const { id, name, description, icon, category, accentColor, inputs } = tool

  const chipState = result?.loading
    ? 'loading'
    : result?.error
    ? 'error'
    : result?.result
    ? 'success'
    : 'idle'

  const chipLabel = result?.loading
    ? 'Running…'
    : result?.error
    ? 'Error'
    : result?.result
    ? 'Done'
    : 'Ready'

  return (
    <div
      className={`tool-card${active ? ' active' : ''}`}
      style={{ '--accent': accentColor }}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && onClick()}
      aria-pressed={active}
    >
      <div className="tool-card-top">
        <span className="tool-icon">{icon}</span>
        <div className="tool-meta">
          <div className="tool-name">{name}</div>
          <span className="tool-category">{category}</span>
          <p className="tool-description">{description}</p>
        </div>
      </div>
      <div className="tool-card-footer">
        <span className="tool-inputs-hint">
          {inputs.map(i => i.label).join(', ')}
        </span>
        <span className={`tool-status-chip ${chipState}`}>{chipLabel}</span>
      </div>
    </div>
  )
}
