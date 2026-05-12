import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'

interface Device {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  ports: { port: number; state: string }[]
  sources: string[]
}

export default function App() {
  const [devices, setDevices] = useState<Device[]>([])
  const [scanning, setScanning] = useState(false)
  const [subnet, setSubnet] = useState('192.168.1.0/24')

  const startScan = async () => {
    setScanning(true)
    try {
      const result = await invoke<Device[]>('start_scan', {
        opts: { subnet, concurrency: 100, timeout_ms: 2000, full_ports: false }
      })
      setDevices(result)
    } catch (e) {
      console.error('Scan failed:', e)
    } finally {
      setScanning(false)
    }
  }

  return (
    <div style={{ padding: '48px', minHeight: '100vh', background: '#0f0f1a', color: '#fff' }}>
      <div style={{ textAlign: 'center', marginBottom: '48px' }}>
        <h1 style={{ fontSize: '48px', color: '#00d4ff', margin: 0 }}>NetProwl</h1>
        <p style={{ color: '#666', marginTop: '12px' }}>网络安全扫描工具</p>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '24px' }}>
        <button
          onClick={startScan}
          disabled={scanning}
          style={{
            width: '240px', height: '80px', fontSize: '20px', fontWeight: 'bold',
            background: scanning ? '#666' : 'linear-gradient(135deg, #00d4ff, #0066ff)',
            color: 'white', border: 'none', borderRadius: '40px', cursor: scanning ? 'not-allowed' : 'pointer'
          }}
        >
          {scanning ? '扫描中...' : '开始扫描'}
        </button>
        <p style={{ fontSize: '24px', color: '#00d4ff' }}>发现设备: {devices.length}</p>
        <div style={{ marginTop: '32px', width: '100%', maxWidth: '800px' }}>
          {devices.map(d => (
            <div key={d.ip} style={{ background: '#1a1a2e', padding: '16px', marginBottom: '12px', borderRadius: '8px' }}>
              <div style={{ color: '#00d4ff', fontSize: '18px', fontWeight: 'bold' }}>{d.ip}</div>
              <div style={{ color: '#999', fontSize: '14px', marginTop: '4px' }}>
                端口: {d.ports.map(p => p.port).join(', ')}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}