import React, { useEffect, useState } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8080'
const REPORTER_BASE = import.meta.env.VITE_REPORTER_BASE || 'http://localhost:8090'

export default function App(){
  const [file, setFile] = useState(null)
  const [url, setUrl] = useState('')
  const [password, setPassword] = useState('')
  const [adapters, setAdapters] = useState('')
  const [jobId, setJobId] = useState('')
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [pw2, setPw2] = useState('')
  const [jobs, setJobs] = useState([])
  const [polling, setPolling] = useState(false)
  const [filterYara, setFilterYara] = useState('')
  const [filterIoc, setFilterIoc] = useState('')
  const [filterTimeline, setFilterTimeline] = useState('')
  const [audit, setAudit] = useState([])

  useEffect(() => {
    // Simple RUM: send navigation timing to backend
    try {
      const nav = performance.getEntriesByType('navigation')[0]
      if (nav) {
        const payload = {
          ttfb: nav.responseStart,
          domContentLoaded: nav.domContentLoadedEventEnd,
          load: nav.loadEventEnd,
          url: location.href,
          ts: Date.now()
        }
        fetch(`${API_BASE}/frontend-rum`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        }).catch(() => {})
      }
    } catch {}

    // Error logging: send to backend and console
    const handler = (e) => {
      try {
        const payload = {
          message: e?.message || 'unknown',
          filename: e?.filename,
          lineno: e?.lineno,
          colno: e?.colno,
          stack: e?.error?.stack,
          url: location.href,
          ts: Date.now()
        }
        fetch(`${API_BASE}/frontend-errors`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        }).catch(() => {})
      } catch {}
      // keep console noise for local debugging
      // eslint-disable-next-line no-console
      console.error('FrontendError', e?.message)
    }
    window.addEventListener('error', handler)
    return () => window.removeEventListener('error', handler)
  }, [])

  async function submitAnalyze(e){
    e.preventDefault()
    setError('')
    const form = new FormData()
    if (file) form.append('file', file)
    if (url) form.append('url', url)
    if (password) form.append('password', password)
    if (adapters) form.append('adapters', adapters)
    try{
      const res = await fetch(`${API_BASE}/analyze`, { method:'POST', body: form })
      const data = await res.json()
      if(!res.ok){
        setError(data.detail || 'Request failed')
        return
      }
      setJobId(data.job_id)
      setStatus(null)
      setReport(null)
    }catch(err){
      setError(err.message)
    }
  }

  async function refreshStatus(){
    if(!jobId) return
    const res = await fetch(`${API_BASE}/result/${jobId}`)
    if (res.ok){
      const js = await res.json()
      setStatus(js)
      // fetch report json if available
      try{
        const jurl = js?.export?.json_url
        if (jurl){
          const r = await fetch(`${REPORTER_BASE}${jurl}`)
          if (r.ok){
            const jr = await r.json()
            setReport(jr)
          }
        }
      }catch{}
    }
  }

  async function refreshJobs(){
    try{
      const r = await fetch(`${API_BASE}/jobs`)
      if (r.ok){
        const d = await r.json()
        setJobs(d.items || [])
      }
    }catch{}
  }

  async function refreshAudit(){
    try{
      const r = await fetch(`${API_BASE}/audit?limit=50`)
      if (r.ok){ const d = await r.json(); setAudit(d.items || []) }
    }catch{}
  }

  // Auto-poll job status while in progress
  useEffect(() => {
    if (!jobId) return
    if (status && (status.state === 'done' || status.state === 'failed')) return
    setPolling(true)
    const t = setInterval(() => { refreshStatus().catch(()=>{}) }, 1000)
    return () => { clearInterval(t); setPolling(false) }
  }, [jobId, status?.state])

  function progressForState(st){
    switch(st){
      case 'queued': return 10
      case 'running': return 40
      case 'enriching': return 70
      case 'reporting': return 90
      case 'done': return 100
      case 'failed': return 100
      default: return 0
    }
  }

  return (
    <div style={{maxWidth: 720, margin: '2rem auto', fontFamily:'sans-serif'}}>
      <h1>ZORBOX UI (MVP)</h1>
      <form onSubmit={submitAnalyze}>
        <div>
          <label>File: <input type="file" onChange={e=>setFile(e.target.files?.[0]||null)} /></label>
        </div>
        <div>
          <label>URL: <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://..." /></label>
        </div>
        <div>
          <label>Archive password: <input value={password} onChange={e=>setPassword(e.target.value)} /></label>
        </div>
        <div>
          <label>Adapters (comma): <input value={adapters} onChange={e=>setAdapters(e.target.value)} placeholder="strace,firejail" /></label>
        </div>
        <button type="submit">Analyze</button>
      </form>
      {error && <p style={{color:'red'}}>Error: {error}</p>}
      {jobId && (
        <div style={{marginTop:'1rem'}}>
          <p>Job ID: <code>{jobId}</code></p>
          <button onClick={refreshStatus}>Refresh status</button>
          {status && (
            <div style={{marginTop:'0.5rem'}}>
              <div style={{height:10, background:'#eee', width:300, position:'relative'}}>
                <div style={{height:10, background:'#4caf50', width:`${progressForState(status.state)}%`}} />
              </div>
              <small>{status.state} {polling ? '(auto)' : ''}</small>
            </div>
          )}
        </div>
      )}
      {status && (
        <div style={{marginTop:'1rem'}}>
          <pre style={{background:'#f5f5f5', padding:'1rem'}}>{JSON.stringify(status, null, 2)}</pre>
          {status.state === 'waiting_password' && (
            <div style={{margin:'0.5rem 0', padding:'0.5rem', background:'#fffbdd'}}>
              <div>Archive is encrypted. Provide password to continue:</div>
              <input value={pw2} onChange={e=>setPw2(e.target.value)} placeholder="password" />
              <button onClick={async()=>{
                if(!jobId || !pw2) return
                try{
                  const r = await fetch(`${API_BASE}/provide-password`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({job_id: jobId, password: pw2})})
                  if(r.ok){ const d = await r.json(); setPw2(''); setJobId(d.job_id || jobId); setStatus(null) }
                }catch{}
              }} style={{marginLeft:'0.5rem'}}>Submit password</button>
            </div>
          )}
          {status.export && (
            <div>
              <h3>Exports</h3>
              {status.export.json_url && (
                <div>
                  <a href={`${REPORTER_BASE}${status.export.json_url}`} target="_blank">JSON</a>
                </div>
              )}
              {status.export.pdf_url && (
                <div>
                  <a href={`${REPORTER_BASE}${status.export.pdf_url}`} target="_blank">PDF</a>
                </div>
              )}
              {status.export.stix_url && (
                <div>
                  <a href={`${REPORTER_BASE}${status.export.stix_url}`} target="_blank">STIX</a>
                </div>
              )}
            </div>
          )}
          {report && (
            <div style={{marginTop:'1rem'}}>
              <h3>Score</h3>
              <pre style={{background:'#eef', padding:'0.5rem'}}>{JSON.stringify({score: report.score || {}, ai: report.ai || {}, final: report.final || {}}, null, 2)}</pre>
              <h3>Sandboxes</h3>
              <pre style={{background:'#eef', padding:'0.5rem'}}>{JSON.stringify(report.sandboxes || [], null, 2)}</pre>
              <h3>YARA Hits</h3>
              <input placeholder="filter YARA" value={filterYara} onChange={e=>setFilterYara(e.target.value)} />
              <ul>
                {(((report.static && report.static.yara_hits) || []).filter(x=>!filterYara || (x||'').toLowerCase().includes(filterYara.toLowerCase()))).map((y,i)=> <li key={i}>{y}</li>)}
              </ul>
              <h3>IOCs</h3>
              <input placeholder="filter IOCs" value={filterIoc} onChange={e=>setFilterIoc(e.target.value)} />
              <pre style={{background:'#eef', padding:'0.5rem'}}>{JSON.stringify(report.iocs || report.ti || {}, null, 2)}</pre>
              <h3>Timeline</h3>
              <input placeholder="filter timeline" value={filterTimeline} onChange={e=>setFilterTimeline(e.target.value)} />
              <div style={{maxHeight:200, overflow:'auto', background:'#f9f9f9', padding:'0.5rem'}}>
                {(report.sandboxes || []).map((s,idx)=>{
                  const adapter = s.adapter || 'adapter'
                  const trace = (((s.artifacts||{}).trace)||'').split('\n').filter(x=>!filterTimeline || x.toLowerCase().includes(filterTimeline.toLowerCase()))
                  return (
                    <div key={idx} style={{marginBottom:'0.5rem'}}>
                      <div style={{fontWeight:'bold'}}>{adapter}</div>
                      <ul>
                        {trace.slice(0,200).map((line,i)=> <li key={i}>{line}</li>)}
                      </ul>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
          <div style={{marginTop:'0.5rem'}}>
            <button onClick={async()=>{
              if(!jobId) return
              await fetch(`${API_BASE}/feedback`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({job_id: jobId, kind:'fp', comment: note})})
              setNote('')
            }}>Mark FP</button>
            <button onClick={async()=>{
              if(!jobId) return
              const res = await fetch(`${API_BASE}/reanalysis`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({job_id: jobId})})
              if(res.ok){ const d = await res.json(); setJobId(d.job_id); setStatus(null) }
            }} style={{marginLeft:'0.5rem'}}>Request reanalysis</button>
            <input placeholder="note" value={note} onChange={e=>setNote(e.target.value)} style={{marginLeft:'0.5rem'}}/>
          </div>
        </div>
      )}
      <div style={{marginTop:'2rem'}}>
        <h2>Jobs</h2>
        <button onClick={refreshJobs}>Refresh jobs</button>
        <pre style={{background:'#f5f5f5', padding:'1rem'}}>{JSON.stringify(jobs, null, 2)}</pre>
      </div>
      <div style={{marginTop:'2rem'}}>
        <h2>Audit</h2>
        <button onClick={refreshAudit}>Refresh audit</button>
        <pre style={{background:'#f5f5f5', padding:'1rem', maxHeight:200, overflow:'auto'}}>{JSON.stringify(audit, null, 2)}</pre>
      </div>
    </div>
  )
}
