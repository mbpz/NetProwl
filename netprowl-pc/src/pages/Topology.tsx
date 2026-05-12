import { TopoCanvas } from '../components/TopoCanvas'
import { useDeviceStore } from '../stores/deviceStore'

export function Topology() {
  const devices = useDeviceStore((s) => s.devices)

  return (
    <div className="topology">
      <h2>网络拓扑</h2>
      <TopoCanvas devices={devices} width={800} height={600} layout="topology" />
    </div>
  )
}
