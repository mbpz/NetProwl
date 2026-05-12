import { useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { useDeviceStore } from '../stores/deviceStore'

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

interface ScanOptions {
  subnet: string
  concurrency?: number
  timeout_ms?: number
  full_ports?: boolean
}

export function useScanner() {
  const { setDevices, setScanning, devices } = useDeviceStore()

  const startScan = useCallback(async () => {
    setScanning(true)
    try {
      const result = await invoke<Device[]>('start_scan', {
        opts: { subnet: '192.168.1.0/24', concurrency: 100, timeout_ms: 2000, full_ports: false }
      } as ScanOptions)
      setDevices(result)
    } catch (error) {
      console.error('Scan failed:', error)
    } finally {
      setScanning(false)
    }
  }, [setDevices, setScanning])

  return { startScan, devices, scanning: useDeviceStore((s) => s.scanning) }
}