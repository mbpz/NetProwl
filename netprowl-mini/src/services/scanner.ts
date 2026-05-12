// src/services/scanner.ts
// Scanner service — coordinates mDNS + SSDP + TCP scan

export interface ScanOptions {
  subnet: string
  whitePortsOnly?: boolean
  concurrency?: number
  timeoutMs?: number
}

export interface DiscoveredDevice {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  ports: number[]
  sources: string[]
  discoveredAt: number
}

const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]

class ScannerService {
  private devices: Map<string, DiscoveredDevice> = new Map()

  async startScan(opts: ScanOptions): Promise<DiscoveredDevice[]> {
    const { subnet } = opts
    const ports = opts.whitePortsOnly !== false ? WHITE_PORTS : opts.ports || WHITE_PORTS

    // TODO: implement mDNS discovery
    // TODO: implement SSDP discovery
    // TODO: implement TCP port scanning

    return Array.from(this.devices.values())
  }

  stopScan(): void {
    this.devices.clear()
  }

  getDevices(): DiscoveredDevice[] {
    return Array.from(this.devices.values())
  }
}

export const scanner = new ScannerService()