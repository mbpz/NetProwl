import { useDeviceStore } from '../stores/deviceStore'
import { discoverMDNS } from './mdns'
import { discoverSSDP } from './udp'
import { probeTCPPorts } from './tcp'
import type { Device, Port } from '../types'

// Well-known ports for quick scan
const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]

// Common gateway IPs
const GATEWAY_CANDIDATES = ['192.168.1.1', '192.168.0.1', '10.0.0.1', '10.0.1.1']

function guessGateway(): string {
  try {
    const info = wx.getNetworkInfoSync()
    if (info && info.hostname) {
      // Try to extract gateway from network info if available
    }
  } catch {
    // fallback
  }
  return GATEWAY_CANDIDATES[0]
}

function guessService(port: number): string | null {
  const map: Record<number, string> = {
    80: 'http',
    443: 'https',
    22: 'ssh',
    21: 'ftp',
    554: 'rtsp',
    5000: 'upnp',
    9000: 'cslistener',
    8080: 'http-alt',
    8443: 'https-alt',
    49152: 'unknown'
  }
  return map[port] || null
}

function makeDeviceFromIP(ip: string, ports: Port[]): Device {
  return {
    id: ip,
    ip,
    mac: null,
    hostname: ip,
    vendor: null,
    deviceType: 'unknown',
    os: 'unknown',
    openPorts: ports,
    discoveredAt: Date.now(),
    sources: ['tcp']
  }
}

// Run full scan: mDNS + SSDP + TCP on discovered devices + gateway
export async function runFullScan(): Promise<Device[]> {
  const store = useDeviceStore.getState()
  store.setScanning(true)

  try {
    // Phase 1: mDNS discovery
    try {
      const mdnsDevices = await discoverMDNS()
      mdnsDevices.forEach(d => store.addDevice(d))
    } catch {
      // mDNS may fail on some platforms
    }

    // Phase 2: SSDP discovery
    try {
      const ssdpDevices = await discoverSSDP()
      ssdpDevices.forEach(d => store.addDevice(d))
    } catch {
      // SSDP may fail
    }

    // Phase 3: TCP scan on discovered devices + gateway
    const discoveredIPs = store.devices.map(d => d.ip)
    const gateway = guessGateway()

    // Include gateway if not already in list
    const targets = discoveredIPs.includes(gateway)
      ? discoveredIPs
      : [...discoveredIPs, gateway]

    // Batch TCP scanning with concurrency limit (respect WeChat frequency limit)
    const results = await scanTargetsTCP(targets)

    results.forEach(({ ip, ports }) => {
      if (ports.length > 0) {
        store.updateDevicePorts(ip, ports)
        // Add device if not already present
        const existing = store.devices.find(d => d.ip === ip)
        if (!existing) {
          store.addDevice(makeDeviceFromIP(ip, ports))
        }
      }
    })

    // Save snapshot
    store.saveSnapshot('local')

  } finally {
    store.setScanning(false)
  }

  return useDeviceStore.getState().devices
}

// Scan multiple targets with concurrency control
async function scanTargetsTCP(ips: string[]): Promise<Array<{ ip: string, ports: Port[] }>> {
  const CONCURRENCY = 5 // respect WeChat TCPSocket frequency limit (20/5min)
  const results: Array<{ ip: string, ports: Port[] }> = []

  for (let i = 0; i < ips.length; i += CONCURRENCY) {
    const batch = ips.slice(i, i + CONCURRENCY)
    const batchResults = await Promise.all(
      batch.map(async (ip) => {
        try {
          const openPorts = await probeTCPPorts(ip)
          return {
            ip,
            ports: openPorts.map(port => ({
              port,
              service: guessService(port),
              state: 'open' as const
            }))
          }
        } catch {
          return { ip, ports: [] }
        }
      })
    )
    results.push(...batchResults)

    // Small delay between batches to respect frequency limit
    if (i + CONCURRENCY < ips.length) {
      await new Promise(r => setTimeout(r, 100))
    }
  }

  return results
}