import { useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { useDeviceStore } from '../stores/deviceStore'

interface Port {
  port: number
  service: string
  state: string
}

interface Device {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  deviceType: string
  os: string
  openPorts: Port[]
}

export function useScanner() {
  const { setDevices, setScanning, devices } = useDeviceStore()

  const startScan = useCallback(async () => {
    setScanning(true)
    try {
      const result = await invoke<Device[]>('scan_network')
      setDevices(result)
    } catch (error) {
      console.error('Scan failed:', error)
    } finally {
      setScanning(false)
    }
  }, [setDevices, setScanning])

  return { startScan, devices, scanning: useDeviceStore((s) => s.scanning) }
}