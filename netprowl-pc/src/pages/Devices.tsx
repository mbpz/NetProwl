import { useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { useDeviceStore, Device } from '../stores/deviceStore'
import { DeviceCard } from '../components/DeviceCard'

export function Devices() {
  const { devices, setDevices } = useDeviceStore()

  useEffect(() => {
    const loadDevices = async () => {
      try {
        const result = await invoke<Device[]>('get_devices')
        setDevices(result)
      } catch (error) {
        console.error('Failed to get devices:', error)
      }
    }
    loadDevices()
  }, [setDevices])

  return (
    <div className="devices">
      <h2>发现设备 ({devices.length})</h2>
      <div className="device-list" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {devices.map((device) => (
          <DeviceCard key={device.ip} device={device} />
        ))}
      </div>
    </div>
  )
}
