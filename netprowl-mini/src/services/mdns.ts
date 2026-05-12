// mDNS discovery service
import { Device } from '../types'
import { wasmDiscoverMDNS } from '../wasm/netprowl_core'

const SERVICE_TYPES = ['_http._tcp', '_ftp._tcp', '_ssh._tcp', '_smb._tcp', '_airplay._tcp', '_googlecast._tcp', '_ipp._tcp']

export async function discoverMDNS(): Promise<Device[]> {
  try {
    const json = await wasmDiscoverMDNS(SERVICE_TYPES, 5000)
    const devices: any[] = JSON.parse(json)
    return devices.map(d => ({
      id: d.ip || d.id || `mdns-${d.ip}`,
      ip: d.ip,
      mac: d.mac || null,
      hostname: d.hostname || null,
      vendor: d.vendor || null,
      deviceType: mapDeviceType(d.device_type),
      os: mapOS(d.os),
      openPorts: (d.open_ports || []).map((p: any) => ({
        port: p.port,
        service: p.service || null,
        state: p.state || 'open',
        banner: p.banner || null,
      })),
      discoveredAt: d.discovered_at ? new Date(d.discovered_at).getTime() : Date.now(),
      sources: d.sources || ['mdns'],
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
