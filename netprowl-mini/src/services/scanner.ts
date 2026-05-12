// Scanner service — coordinates mDNS + SSDP + TCP scan
import { Device } from '../types'

export interface ScanResult {
  devices: Device[]
  durationMs: number
  mdnsUnavailable: boolean
}

export async function runScan(): Promise<ScanResult> {
  // Stub: returns empty result
  // Real implementation coordinates mDNS + SSDP + TCP
  return {
    devices: [],
    durationMs: 0,
    mdnsUnavailable: false
  }
}
