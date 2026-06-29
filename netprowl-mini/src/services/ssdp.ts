// SSDP/UPnP discovery service
import { Device, DeviceType, OSType } from '../types'
import { wasmDiscoverSSDP } from '../wasm/netprowl_core'

const SSDP_ADDR = '239.255.255.250'
const SSDP_PORT = 1900
const SSDP_TIMEOUT_MS = 3000
const M_SEARCH = [
  'M-SEARCH * HTTP/1.1',
  `HOST: ${SSDP_ADDR}:${SSDP_PORT}`,
  'MAN: "ssdp:discover"',
  'MX: 2',
  'ST: ssdp:all',
  '',
  '',
].join('\r\n')

export async function discoverSSDP(): Promise<Device[]> {
  const wxApi = (globalThis as any).wx
  if (wxApi?.createUDPSocket) {
    return discoverWithWechatSSDP(wxApi)
  }

  try {
    const json = await wasmDiscoverSSDP(SSDP_TIMEOUT_MS)
    const devices: any[] = JSON.parse(json)
    return devices.map(mapWasmDevice)
  } catch {
    return []
  }
}

async function discoverWithWechatSSDP(wxApi: any): Promise<Device[]> {
  const socket = wxApi.createUDPSocket()
  const devices = new Map<string, Device>()

  const onMessage = (res: any) => {
    const text = decodeMessage(res.message)
    const headers = parseHeaders(text)
    const ip = res.remoteInfo?.address || parseHost(headers.location)
    if (!ip) return

    const server = headers.server || headers.st || headers.usn || null
    devices.set(ip, {
      id: `ssdp-${ip}`,
      ip,
      mac: null,
      hostname: headers.location || headers.usn || ip,
      vendor: server,
      deviceType: guessDeviceType(text),
      os: 'unknown',
      openPorts: [{
        port: 1900,
        service: 'ssdp',
        state: 'open',
        banner: server || undefined,
      }],
      discoveredAt: Date.now(),
      sources: ['ssdp'],
    })
  }

  socket.onMessage?.(onMessage)
  try {
    socket.bind?.()
    socket.send?.({
      address: SSDP_ADDR,
      port: SSDP_PORT,
      message: M_SEARCH,
    })
    await new Promise(resolve => setTimeout(resolve, SSDP_TIMEOUT_MS))
  } finally {
    socket.offMessage?.(onMessage)
    socket.close?.()
  }

  return Array.from(devices.values())
}

function mapWasmDevice(d: any): Device {
  return {
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
        banner: p.banner || undefined,
      })),
    discoveredAt: d.discovered_at ? new Date(d.discovered_at).getTime() : Date.now(),
    sources: d.sources || ['ssdp'],
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

function decodeMessage(message: unknown): string {
  if (typeof message === 'string') return message
  if (message instanceof ArrayBuffer) return new TextDecoder().decode(message)
  return ''
}

function parseHeaders(response: string): Record<string, string> {
  const headers: Record<string, string> = {}
  response.split(/\r?\n/).forEach((line) => {
    const idx = line.indexOf(':')
    if (idx > 0) {
      headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim()
    }
  })
  return headers
}

function parseHost(location?: string): string | null {
  if (!location) return null
  const match = location.match(/^https?:\/\/([^/:]+)/i)
  return match?.[1] || null
}

function guessDeviceType(text: string): DeviceType {
  const lower = text.toLowerCase()
  if (lower.includes('printer') || lower.includes('ipp')) return 'printer'
  if (lower.includes('camera') || lower.includes('rtsp') || lower.includes('hikvision') || lower.includes('dahua')) return 'camera'
  if (lower.includes('nas') || lower.includes('synology') || lower.includes('qnap')) return 'nas'
  if (lower.includes('router') || lower.includes('gateway')) return 'router'
  return 'unknown'
}
