// TCP port probing service
import { Device } from '../types'

const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]

export async function probeTCPPorts(ip: string): Promise<number[]> {
  // Stub: returns empty array
  // Real: wx.createTCPSocket per port
  return []
}
