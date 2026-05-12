import { Device } from '../types'

interface DeviceStore {
  devices: Device[]
  setDevices: (devices: Device[]) => void
  addDevice: (device: Device) => void
  clearDevices: () => void
}

export const deviceStore: DeviceStore = {
  devices: [],
  setDevices: (devices: Device[]) => { deviceStore.devices = devices },
  addDevice: (device: Device) => { deviceStore.devices.push(device) },
  clearDevices: () => { deviceStore.devices = [] }
}
