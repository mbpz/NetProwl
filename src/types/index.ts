export type DeviceType = 'router' | 'pc' | 'camera' | 'nas' | 'phone' | 'printer' | 'unknown'

export type OSType = 'linux' | 'windows' | 'network' | 'unknown'

export type DiscoverySource = 'mdns' | 'ssdp' | 'tcp' | 'arp'

export type PortState = 'open' | 'filtered'

export interface Port {
  port: number
  service: string | null
  state: PortState
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
  sources: DiscoverySource[]
}

export interface ScanSnapshot {
  id: string
  timestamp: number
  ipRange: string
  deviceCount: number
  devices: Device[]
  summary: {
    critical: number
    high: number
    medium: number
    low: number
  }
}
