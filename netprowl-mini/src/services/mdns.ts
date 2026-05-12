// mDNS discovery service
import { Device } from '../types'

const SERVICE_TYPES = ['_http._tcp', '_ftp._tcp', '_ssh._tcp', '_smb._tcp', '_airplay._tcp', '_googlecast._tcp', '_ipp._tcp']

export async function discoverMDNS(): Promise<Device[]> {
  // Stub: returns empty array
  // Real: wx.startLocalServiceDiscovery + wx.onLocalServiceFound
  return []
}
