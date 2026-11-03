import packageInfo from '../../package.json'

export function ProductDetails() {
  return (
    <section aria-label="About Genyra Snitch" style={{ margin:'14px 0 8px',padding:16,border:'1px solid var(--brand-border)',borderRadius:12,background:'var(--brand-soft)' }}>
      <img className="genyra-wordmark genyra-on-dark" src="./brand/genyra-light.png" alt="Genyra LLC" />
      <img className="genyra-wordmark genyra-on-light" src="./brand/genyra-dark.png" alt="Genyra LLC" />
      <div style={{ display:'flex',alignItems:'baseline',gap:10,marginTop:5 }}>
        <strong style={{ color:'var(--text)',fontSize:16,letterSpacing:-.4 }}>Genyra Snitch</strong>
        <span style={{ color:'var(--text-muted)',fontSize:10 }}>v{packageInfo.version}</span>
      </div>
      <p style={{ fontSize:11,lineHeight:1.65,color:'var(--text-dim)',margin:'9px 0 10px' }}>
        Local network visibility and application controls.<br />
        Open source. Built on Snitch. Maintained by Genyra LLC.
      </p>
      <div style={{ display:'flex',gap:14,fontSize:10,fontWeight:600 }}>
        <a href="https://github.com/GenyraLLC/genyra-snitch" target="_blank" rel="noreferrer">Source &amp; documentation ↗</a>
        <a href="https://genyra.com" target="_blank" rel="noreferrer">Genyra ↗</a>
      </div>
      <p style={{ fontSize:9,lineHeight:1.5,color:'var(--text-muted)',margin:'12px 0 0' }}>
        Based on <a href="https://github.com/aixisstudio/Snitch" target="_blank" rel="noreferrer">Snitch by aiXis Studio</a>. AGPL-3.0.
      </p>
    </section>
  )
}
