import { useScanner } from '../hooks/useScanner'
import { TopoCanvas } from '../components/TopoCanvas'
import { useDeviceStore } from '../stores/deviceStore'

export function Home() {
  const { startScan } = useScanner()
  const scanning = useDeviceStore((s) => s.scanning)
  const devices = useDeviceStore((s) => s.devices)

  return (
    <div className="home">
      <h2>网络扫描</h2>
      <button onClick={startScan} disabled={scanning}>
        {scanning ? '扫描中...' : '开始扫描'}
      </button>
      <div className="device-count" style={{ marginTop: '16px', fontSize: '14px', color: '#6b7280' }}>
        发现设备: {devices.length}
      </div>
      <div style={{ marginTop: '16px' }}>
        <TopoCanvas devices={devices} width={800} height={400} layout="grid" />
      </div>
    </div>
  )
}
