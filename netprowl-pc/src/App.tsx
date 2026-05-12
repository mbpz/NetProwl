import { useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import './App.css'

function App() {
  const [ipStart, setIpStart] = useState('192.168.1.1')
  const [ipEnd, setIpEnd] = useState('192.168.1.254')
  const [scanning, setScanning] = useState(false)
  const [devices, setDevices] = useState<any[]>([])

  const handleScan = async () => {
    setScanning(true)
    try {
      const result = await invoke<string>('scan_tcp', {
        ipStart,
        ipEnd,
        ports: [80, 443, 22, 3389, 445, 139, 135],
      })
      const parsed = JSON.parse(result)
      setDevices(parsed.devices || [])
    } catch (e) {
      console.error(e)
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="app">
      <header className="header">
        <h1>NetProwl</h1>
        <p>局域网安全扫描</p>
      </header>

      <div className="form">
        <div className="field">
          <label>IP 范围</label>
          <div className="range">
            <input value={ipStart} onChange={e => setIpStart(e.target.value)} />
            <span> - </span>
            <input value={ipEnd} onChange={e => setIpEnd(e.target.value)} />
          </div>
        </div>
        <button onClick={handleScan} disabled={scanning}>
          {scanning ? '扫描中...' : '开始扫描'}
        </button>
      </div>

      <div className="device-list">
        {devices.map(d => (
          <div key={d.ip} className={`device-card risk-${d.risk}`}>
            <div className="card-ip">{d.ip}</div>
            <div className="card-vendor">{d.vendor || '未知'}</div>
            <div className="card-ports">
              {d.ports?.map((p: any) => (
                <span key={p.number} className="port-tag">
                  <span className="port-num">{p.number}</span>
                  <span className="port-svc">{p.service}</span>
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default App
