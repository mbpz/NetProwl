import { useDeviceStore } from '../stores/deviceStore'
import { DeviceCard } from '../components/DeviceCard'

export function Devices() {
  const devices = useDeviceStore((s) => s.devices)

  return (
    <div className="devices">
      <h2>发现设备 ({devices.length})</h2>
      <div className="device-list">
        {devices.map((device) => (
          <DeviceCard key={device.ip} device={device} />
        ))}
      </div>
    </div>
  )
}