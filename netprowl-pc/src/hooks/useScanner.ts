import { useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { useDeviceStore, Device } from '../stores/deviceStore'

export function useScanner() {
  const { setDevices, setScanning, devices } = useDeviceStore()

  const startScan = useCallback(async () => {
    setScanning(true)
    let sessionId: number | null = null
    try {
      // Start a scan session
      sessionId = await invoke<number>('start_scan_session', { target: '192.168.1.0/24' })

      const result = await invoke<Device[]>('start_scan', {
        opts: {
          subnet: '192.168.1.0/24',
          concurrency: 100,
          timeout_ms: 2000,
          full_ports: false
        }
      })
      setDevices(result)

      // Save devices to history
      if (sessionId !== null && result.length > 0) {
        await invoke('save_scan', { sessionId, devices: result })
      }

      // End the scan session with device count
      if (sessionId !== null) {
        await invoke('end_scan_session', { id: sessionId, count: result.length })
      }
    } catch (error) {
      console.error('Scan failed:', error)
    } finally {
      setScanning(false)
    }
  }, [setDevices, setScanning])

  return { startScan, devices, scanning: useDeviceStore((s) => s.scanning) }
}
