import { create } from 'zustand'

export interface Port {
  port: number
  service: string | null
  state: string
  banner: string | null
}

export interface Device {
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  device_type: string | null
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
