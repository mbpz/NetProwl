import { useState } from 'react'
import { invoke } from '@tauri-apps/api/core'

interface Port {
  port: number
  state: string
  service?: string
  banner?: string
}

interface Device {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  ports: Port[]
  sources: string[]
}

export default function App() {
  const [devices, setDevices] = useState<Device[]>([])
  const [scanning, setScanning] = useState(false)
  const [subnet] = useState('192.168.1.0/24')
  const [view, setView] = useState<'list' | 'topo'>('list')
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)

  const startScan = async () => {
    setScanning(true)
    setSelectedDevice(null)
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
    <div style={{ minHeight: '100vh', background: '#0f0f1a', color: '#fff', fontFamily: '-apple-system, BlinkMacSystemFont, sans-serif' }}>
      {/* Header */}
      <header style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '16px 32px', borderBottom: '1px solid #1a1a2e',
        background: '#0f0f1a', position: 'sticky', top: 0, zIndex: 100
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '24px' }}>🔒</span>
          <h1 style={{ fontSize: '20px', color: '#00d4ff', margin: 0, fontWeight: 700 }}>NetProwl</h1>
          <span style={{ fontSize: '12px', color: '#666', background: '#1a1a2e', padding: '2px 8px', borderRadius: '4px' }}>v1.0</span>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => setView('list')}
            style={{
              padding: '8px 16px', border: 'none', borderRadius: '6px', cursor: 'pointer',
              background: view === 'list' ? '#00d4ff' : '#1a1a2e', color: view === 'list' ? '#000' : '#fff',
              fontWeight: 500
            }}
          >
            📋 列表
          </button>
          <button
            onClick={() => setView('topo')}
            style={{
              padding: '8px 16px', border: 'none', borderRadius: '6px', cursor: 'pointer',
              background: view === 'topo' ? '#00d4ff' : '#1a1a2e', color: view === 'topo' ? '#000' : '#fff',
              fontWeight: 500
            }}
          >
            🕸️ 拓扑
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ padding: '32px', maxWidth: '1200px', margin: '0 auto' }}>
        {/* Scan Control */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          background: '#1a1a2e', borderRadius: '16px', padding: '24px 32px', marginBottom: '32px'
        }}>
          <div>
            <div style={{ fontSize: '14px', color: '#666', marginBottom: '4px' }}>目标网段</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#00d4ff' }}>{subnet}</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '36px', fontWeight: 700, color: '#fff' }}>{devices.length}</div>
              <div style={{ fontSize: '13px', color: '#666' }}>发现设备</div>
            </div>
            <button
              onClick={startScan}
              disabled={scanning}
              style={{
                width: '120px', height: '48px', borderRadius: '24px', border: 'none',
                background: scanning ? '#333' : 'linear-gradient(135deg, #00d4ff, #0066ff)',
                color: 'white', fontSize: '15px', fontWeight: 600, cursor: scanning ? 'not-allowed' : 'pointer'
              }}
            >
              {scanning ? '⏳ 扫描中' : '🔍 开始扫描'}
            </button>
          </div>
        </div>

        {/* Device List */}
        {view === 'list' && devices.length > 0 && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '16px' }}>
            {devices.map(d => (
              <div
                key={d.ip}
                onClick={() => setSelectedDevice(d)}
                style={{
                  background: selectedDevice?.ip === d.ip ? '#252540' : '#1a1a2e',
                  borderRadius: '12px', padding: '20px', cursor: 'pointer',
                  border: selectedDevice?.ip === d.ip ? '2px solid #00d4ff' : '2px solid transparent',
                  transition: 'all 0.2s'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <span style={{ fontSize: '20px' }}>📱</span>
                  {d.vendor && (
                    <span style={{ fontSize: '12px', color: '#00d4ff', background: '#0f0f1a', padding: '2px 8px', borderRadius: '4px' }}>
                      {d.vendor}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '18px', fontWeight: 600, color: '#fff', marginBottom: '4px' }}>{d.ip}</div>
                {d.hostname && <div style={{ fontSize: '13px', color: '#999', marginBottom: '4px' }}>{d.hostname}</div>}
                {d.mac && <div style={{ fontSize: '12px', color: '#666', marginBottom: '8px' }}>MAC: {d.mac}</div>}
                <div style={{ fontSize: '12px', color: '#666' }}>
                  {d.ports.length} 个开放端口: {d.ports.slice(0, 5).map(p => p.port).join(', ')}
                  {d.ports.length > 5 ? '...' : ''}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Topology View */}
        {view === 'topo' && devices.length > 0 && (
          <div style={{
            background: '#1a1a2e', borderRadius: '16px', padding: '24px', minHeight: '400px',
            position: 'relative', overflow: 'hidden'
          }}>
            <div style={{ display: 'flex', justifyContent: 'center', paddingTop: '40px' }}>
              {/* Router node */}
              <div style={{
                width: '80px', height: '80px', borderRadius: '50%', background: 'linear-gradient(135deg, #00d4ff, #0066ff)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '32px', boxShadow: '0 4px 20px rgba(0,212,255,0.4)',
                position: 'relative', zIndex: 2
              }}>
                🌐
              </div>
            </div>
            {/* Lines to devices */}
            <div style={{
              display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '-20px', paddingTop: '20px',
              position: 'relative'
            }}>
              {devices.slice(0, 8).map((d, i) => (
                <div key={d.ip} style={{
                  width: '2px', height: '40px', background: '#333', transform: `rotate(${(i - 3.5) * 10}deg)`
                }} />
              ))}
            </div>
            {/* Device nodes */}
            <div style={{
              display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: '16px', marginTop: '16px'
            }}>
              {devices.slice(0, 8).map((d, i) => (
                <div key={d.ip} style={{
                  width: '64px', height: '64px', borderRadius: '12px', background: '#252540',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '24px',
                  border: '2px solid #333', cursor: 'pointer'
                }}
                  onClick={() => setSelectedDevice(d)}
                >
                  📱
                </div>
              ))}
            </div>
            {devices.length > 8 && (
              <div style={{ textAlign: 'center', color: '#666', marginTop: '16px', fontSize: '13px' }}>
                还有 {devices.length - 8} 台设备...
              </div>
            )}
          </div>
        )}

        {/* Empty State */}
        {!scanning && devices.length === 0 && (
          <div style={{ textAlign: 'center', padding: '80px 0', color: '#666' }}>
            <div style={{ fontSize: '64px', marginBottom: '16px' }}>🔍</div>
            <div style={{ fontSize: '18px', marginBottom: '8px' }}>点击开始扫描</div>
            <div style={{ fontSize: '14px' }}>发现局域网内的所有设备</div>
          </div>
        )}
      </main>

      {/* Device Detail Drawer */}
      {selectedDevice && (
        <div
          style={{
            position: 'fixed', top: 0, right: 0, bottom: 0, width: '400px',
            background: '#1a1a2e', borderLeft: '1px solid #252540', padding: '24px',
            overflowY: 'auto', boxShadow: '-4px 0 32px rgba(0,0,0,0.5)'
          }}
          onClick={() => setSelectedDevice(null)}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
            <h2 style={{ fontSize: '18px', color: '#fff', margin: 0 }}>设备详情</h2>
            <button
              onClick={() => setSelectedDevice(null)}
              style={{ background: 'none', border: 'none', color: '#666', fontSize: '20px', cursor: 'pointer' }}
            >
              ✕
            </button>
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#00d4ff', marginBottom: '8px' }}>{selectedDevice.ip}</div>
          {selectedDevice.vendor && <div style={{ fontSize: '14px', color: '#999', marginBottom: '16px' }}>{selectedDevice.vendor}</div>}
          {selectedDevice.mac && <div style={{ fontSize: '13px', color: '#666', marginBottom: '4px' }}>MAC: {selectedDevice.mac}</div>}
          {selectedDevice.hostname && <div style={{ fontSize: '13px', color: '#666', marginBottom: '16px' }}>Hostname: {selectedDevice.hostname}</div>}
          <div style={{ borderTop: '1px solid #252540', paddingTop: '16px', marginTop: '16px' }}>
            <div style={{ fontSize: '14px', fontWeight: 600, color: '#fff', marginBottom: '12px' }}>开放端口</div>
            {selectedDevice.ports.map(p => (
              <div key={p.port} style={{
                display: 'flex', justifyContent: 'space-between', padding: '10px 12px',
                background: '#252540', borderRadius: '8px', marginBottom: '8px', fontSize: '14px'
              }}>
                <span style={{ color: '#00d4ff' }}>{p.port}</span>
                <span style={{ color: '#666' }}>{p.service || 'unknown'}</span>
                <span style={{ color: p.state === 'open' ? '#00c853' : '#ff6b35' }}>{p.state}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}