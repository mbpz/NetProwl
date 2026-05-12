// SSDP/UPnP discovery service
import { Device } from '../types'

const SSDP_ADDR = '239.255.255.250'
const SSDP_PORT = 1900

export async function discoverSSDP(): Promise<Device[]> {
  // Stub: returns empty array
  // Real: wx.createUDPSocket + M-SEARCH broadcast
  return []
}
