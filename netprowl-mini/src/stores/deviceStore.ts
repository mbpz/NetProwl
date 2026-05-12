import { create } from 'zustand'

export type DeviceType = 'router' | 'pc' | 'camera' | 'nas' | 'phone' | 'printer' | 'unknown'
export type OSType = 'linux' | 'windows' | 'network' | 'unknown'

export interface Port {
  number: number
  service: string | null
  state: 'open' | 'filtered'
  banner?: string
}

export interface Device {
  id: string
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  deviceType: DeviceType
  os: OSType
  openPorts: Port[]
  discoveredAt: number
  sources: ('mdns' | 'ssdp' | 'tcp')[]
}

export interface ScanSnapshot {
  id: string
  timestamp: number
  ipRange: string
  deviceCount: number
  devices: Device[]
}

interface DeviceStore {
  devices: Device[]
  history: ScanSnapshot[]
  scanning: boolean
  addDevice: (d: Device) => void
  setDevices: (ds: Device[]) => void
  setScanning: (v: boolean) => void
  loadHistory: () => void
}

export const useDeviceStore = create<DeviceStore>((set, get) => ({
  devices: [],
  history: [],
  scanning: false,

  addDevice: (d) => set(s => ({ devices: [...s.devices.filter(x => x.ip !== d.ip), d] })),

  setDevices: (devices) => set({ devices }),

  setScanning: (scanning) => set({ scanning }),

  loadHistory: () => {
    try {
      const raw = wx.getStorageSync('netprowl_scan_history')
      const history = raw ? JSON.parse(raw) : []
      set({ history })
    } catch {
      set({ history: [] })
    }
  },
}))