// SSDP/UPnP discovery service
import { Device } from '../types'
import { wasmDiscoverSSDP } from '../wasm/netprowl_core'

export async function discoverSSDP(): Promise<Device[]> {
  try {
    const json = await wasmDiscoverSSDP(3000)
    const devices: any[] = JSON.parse(json)
    return devices.map(d => ({
      id: d.ip || d.id || `ssdp-${d.ip}`,
      ip: d.ip,
      mac: d.mac || null,
      hostname: d.hostname || null,
      vendor: d.vendor || d.server || null,
      deviceType: mapDeviceType(d.device_type),
      os: mapOS(d.os),
      openPorts: (d.open_ports || []).map((p: any) => ({
        port: p.port,
        service: p.service || null,
        state: p.state || 'open',
        banner: p.banner || null,
      })),
      discoveredAt: d.discovered_at ? new Date(d.discovered_at).getTime() : Date.now(),
      sources: d.sources || ['ssdp'],
    }))
  } catch {
    return []
  }
}

function mapDeviceType(t: string | undefined): string {
  const map: Record<string, string> = {
    router: 'router', pc: 'pc', camera: 'camera',
    nas: 'nas', phone: 'phone', printer: 'printer', unknown: 'unknown',
  }
  return map[t || ''] || 'unknown'
}

function mapOS(os: string | undefined): string {
  const map: Record<string, string> = {
    linux: 'linux', windows: 'windows', network: 'network', unknown: 'unknown',
  }
  return map[os || ''] || 'unknown'
}
