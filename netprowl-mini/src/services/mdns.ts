// mDNS discovery service
import { Device, DeviceType, OSType } from '../types'
import { wasmDiscoverMDNS } from '../wasm/netprowl_core'

const SERVICE_TYPES = ['_http._tcp', '_ftp._tcp', '_ssh._tcp', '_smb._tcp', '_airplay._tcp', '_googlecast._tcp', '_ipp._tcp']
const DISCOVERY_TIMEOUT_MS = 5000

export async function discoverMDNS(): Promise<Device[]> {
  const wxApi = (globalThis as any).wx
  if (wxApi?.startLocalServiceDiscovery) {
    return discoverWithWechatMDNS(wxApi)
  }

  try {
    const json = await wasmDiscoverMDNS(SERVICE_TYPES, DISCOVERY_TIMEOUT_MS)
    const devices: any[] = JSON.parse(json)
    return devices.map(mapWasmDevice)
  } catch {
    return []
  }
}

async function discoverWithWechatMDNS(wxApi: any): Promise<Device[]> {
  const devices = new Map<string, Device>()
  const handlers: Array<(res: any) => void> = []

  for (const serviceType of SERVICE_TYPES) {
    const handler = (res: any) => {
      const ip = res.ip || res.address || res.host
      if (!ip) return

      const port = Number(res.port || defaultPortForService(serviceType))
      const key = `${ip}:${port}`
      devices.set(key, {
        id: `mdns-${key}`,
        ip,
        mac: null,
        hostname: res.hostName || res.serviceName || null,
        vendor: null,
        deviceType: guessDeviceType(serviceType, res.serviceName),
        os: 'unknown',
        openPorts: port ? [{
          port,
          service: serviceName(serviceType),
          state: 'open',
          banner: res.serviceName || undefined,
        }] : [],
        discoveredAt: Date.now(),
        sources: ['mdns'],
      })
    }

    handlers.push(handler)
    wxApi.onLocalServiceFound?.(handler)

    await new Promise<void>((resolve) => {
      wxApi.startLocalServiceDiscovery({
        serviceType,
        success: () => setTimeout(resolve, DISCOVERY_TIMEOUT_MS),
        fail: () => resolve(),
      })
    })

    wxApi.stopLocalServiceDiscovery?.({ serviceType })
    wxApi.offLocalServiceFound?.(handler)
  }

  handlers.forEach(handler => wxApi.offLocalServiceFound?.(handler))
  return Array.from(devices.values())
}

function mapWasmDevice(d: any): Device {
  return {
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
        banner: p.banner || undefined,
      })),
    discoveredAt: d.discovered_at ? new Date(d.discovered_at).getTime() : Date.now(),
    sources: d.sources || ['mdns'],
  }
}

function mapDeviceType(t: string | undefined): DeviceType {
  const map: Record<string, string> = {
    router: 'router', pc: 'pc', camera: 'camera',
    nas: 'nas', phone: 'phone', printer: 'printer', unknown: 'unknown',
  }
  return (map[t || ''] || 'unknown') as DeviceType
}

function mapOS(os: string | undefined): OSType {
  const map: Record<string, string> = {
    linux: 'linux', windows: 'windows', network: 'network', unknown: 'unknown',
  }
  return (map[os || ''] || 'unknown') as OSType
}

function defaultPortForService(serviceType: string): number {
  if (serviceType.includes('_http.')) return 80
  if (serviceType.includes('_https.')) return 443
  if (serviceType.includes('_ssh.')) return 22
  if (serviceType.includes('_ftp.')) return 21
  if (serviceType.includes('_smb.')) return 445
  if (serviceType.includes('_ipp.')) return 631
  return 0
}

function serviceName(serviceType: string): string {
  return serviceType.replace(/^_/, '').split('.')[0]
}

function guessDeviceType(serviceType: string, serviceNameValue?: string): DeviceType {
  const text = `${serviceType} ${serviceNameValue || ''}`.toLowerCase()
  if (text.includes('ipp') || text.includes('printer')) return 'printer'
  if (text.includes('airplay') || text.includes('googlecast')) return 'phone'
  if (text.includes('smb')) return 'nas'
  if (text.includes('rtsp') || text.includes('camera')) return 'camera'
  return 'unknown'
}
