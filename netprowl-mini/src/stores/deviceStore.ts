import { create } from 'zustand'
import type { Device, Port, ScanSnapshot } from '../types'

interface DeviceStore {
  devices: Device[]
  history: ScanSnapshot[]
  scanning: boolean
  lastScanTime: number | null

  // Actions
  addDevice: (d: Device) => void
  setDevices: (ds: Device[]) => void
  setScanning: (v: boolean) => void
  updateDevicePorts: (ip: string, ports: Port[]) => void
  loadHistory: () => void
  saveSnapshot: (ipRange: string) => void
  clearDevices: () => void
}

export const useDeviceStore = create<DeviceStore>((set, get) => ({
  devices: [],
  history: [],
  scanning: false,
  lastScanTime: null,

  addDevice: (d) => set(s => {
    const existingIdx = s.devices.findIndex(x => x.ip === d.ip)
    if (existingIdx >= 0) {
      // Merge: keep existing, update with new info
      const existing = s.devices[existingIdx]
      const updated: Device = { ...existing, ...d }
      // Merge sources (dedupe)
      updated.sources = [...new Set([...existing.sources, ...d.sources])]
      // Merge ports (dedupe by port number)
      const mergedPorts = [...existing.openPorts]
      d.openPorts.forEach(p => {
        if (!mergedPorts.find(mp => mp.port === p.port)) {
          mergedPorts.push(p)
        }
      })
      updated.openPorts = mergedPorts
      const devices = [...s.devices]
      devices[existingIdx] = updated
      return { devices }
    }
    return { devices: [...s.devices, d] }
  }),

  setDevices: (devices) => set({ devices }),

  setScanning: (scanning) => set({ scanning }),

  updateDevicePorts: (ip, ports) => set(s => ({
    devices: s.devices.map(d =>
      d.ip === ip ? { ...d, openPorts: ports } : d
    )
  })),

  loadHistory: () => {
    try {
      const raw = wx.getStorageSync('netprowl_scan_history')
      if (raw) {
        const history: ScanSnapshot[] = JSON.parse(raw)
        set({ history })
      }
    } catch {
      // ignore parse errors
    }
  },

  saveSnapshot: (ipRange) => set(s => {
    const snapshot: ScanSnapshot = {
      id: `scan_${Date.now()}`,
      timestamp: Date.now(),
      ipRange,
      deviceCount: s.devices.length,
      devices: JSON.parse(JSON.stringify(s.devices)), // deep clone
      summary: { critical: 0, high: 0, medium: 0, low: 0 }
    }
    const history = [snapshot, ...s.history].slice(0, 50)
    try {
      wx.setStorageSync('netprowl_scan_history', JSON.stringify(history))
    } catch {
      // ignore storage errors
    }
    set({ history, lastScanTime: Date.now() })
  }),

  clearDevices: () => set({ devices: [] }),
}))