import { create } from 'zustand'

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

interface DeviceStore {
  devices: Device[]
  scanning: boolean
  setDevices: (devices: Device[]) => void
  setScanning: (scanning: boolean) => void
}

export const useDeviceStore = create<DeviceStore>((set) => ({
  devices: [],
  scanning: false,
  setDevices: (devices) => set({ devices }),
  setScanning: (scanning) => set({ scanning }),
}))