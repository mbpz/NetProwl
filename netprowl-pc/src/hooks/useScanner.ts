import { useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { useDeviceStore, Device } from '../stores/deviceStore'

export function useScanner() {
  const { setDevices, setScanning, devices } = useDeviceStore()

  const startScan = useCallback(async () => {
    setScanning(true)
    try {
      const result = await invoke<Device[]>('start_scan', {
        opts: {
          subnet: '192.168.1.0/24',
          concurrency: 100,
          timeout_ms: 2000,
          full_ports: false
        }
      })
      setDevices(result)
    } catch (error) {
      console.error('Scan failed:', error)
    } finally {
      setScanning(false)
    }
  }, [setDevices, setScanning])

  return { startScan, devices, scanning: useDeviceStore((s) => s.scanning) }
}
