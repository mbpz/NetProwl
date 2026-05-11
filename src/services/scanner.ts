import { Device, Port } from '../types'
import { getLocalNetworkInfo } from './network'
import { discoverViaMDNS, isMDNSDisabledError } from './mdns'
import { discoverViaSSDP } from './udp'
import { probeIPs } from './tcp'
import { expandSubnet } from '../utils/ip'
import { lookupVendor } from '../utils/oui'
import { saveSnapshot } from './storage'

export interface ScanResult {
  devices: Device[]
  duration: number
  mdnsUnavailable: boolean
}

export async function runScan(): Promise<ScanResult> {
  const start = Date.now()
  const { ip, subnet } = await getLocalNetworkInfo()
  const allIPs = expandSubnet(subnet)

  let mdnsUnavailable = false
  const mdnsDevices: Device[] = []
  const ssdpDevices: Device[] = []
  const tcpDevices: Device[] = []

  // Stage 1: mDNS
  try {
    const results = await discoverViaMDNS()
    mdnsDevices.push(...results)
  } catch (err) {
    if (isMDNSDisabledError(err)) {
      mdnsUnavailable = true
    }
  }

  // Stage 2: SSDP + TCP in parallel
  const ssdpPromise = discoverViaSSDP()
  const tcpPromise = probeIPs(subnet, allIPs)

  const [ssdp, tcp] = await Promise.all([ssdpPromise, tcpPromise])
  ssdpDevices.push(...ssdp)
  tcpDevices.push(...tcp)

  // Merge & deduplicate
  const merged = mergeDevices([...mdnsDevices, ...ssdpDevices, ...tcpDevices])
  merged.forEach((d) => { if (d.vendor === null) d.vendor = d.mac ? lookupVendor(d.mac) : null })

  const duration = Date.now() - start

  // Save snapshot
  await saveSnapshot({
    id: `scan_${Date.now()}`,
    timestamp: Date.now(),
    ipRange: subnet,
    deviceCount: merged.length,
    devices: merged,
    summary: { critical: 0, high: 0, medium: 0, low: 0 },
  })

  return { devices: merged, duration, mdnsUnavailable }
}

function mergeDevices(devices: Device[]): Device[] {
  const map = new Map<string, Device>()
  for (const d of devices) {
    if (map.has(d.ip)) {
      const existing = map.get(d.ip)!
      existing.sources = [...new Set([...existing.sources, ...d.sources])]
      existing.openPorts = dedupPorts([...existing.openPorts, ...d.openPorts])
    } else {
      map.set(d.ip, { ...d })
    }
  }
  return Array.from(map.values())
}

function dedupPorts(ports: Port[]): Port[] {
  const seen = new Set<number>()
  return ports.filter((p) => {
    if (seen.has(p.port)) return false
    seen.add(p.port)
    return true
  })
}