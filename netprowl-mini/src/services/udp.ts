import type { Device } from '../stores/deviceStore'

const SSDP_ADDR = '239.255.255.250'
const SSDP_PORT = 1900
const M_SEARCH = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'

export async function discoverSSDP(): Promise<Device[]> {
  const devices: Device[] = []
  const seen = new Set<string>()

  const udp = wx.createUDPSocket()
  udp.onMessage((res: any) => {
    const banner = bufToString(res.message)
    if (!banner.includes('HTTP/1.1 200')) return
    const ip = res.remoteInfo.address
    if (seen.has(ip)) return
    seen.add(ip)
    devices.push(makeDevice(ip, banner, 'ssdp'))
  })

  udp.send({ address: SSDP_ADDR, port: SSDP_PORT, message: M_SEARCH })
  await delay(3000)
  udp.close()

  return devices
}

function makeDevice(ip: string, banner: string, source: 'ssdp' | 'tcp'): Device {
  return {
    id: ip,
    ip,
    mac: null,
    hostname: extractHeader(banner, 'SERVER') || ip,
    vendor: null,
    deviceType: inferType(banner),
    os: 'unknown',
    openPorts: [],
    discoveredAt: Date.now(),
    sources: [source],
  }
}

function extractHeader(banner: string, key: string): string | null {
  const m = banner.match(new RegExp(`^${key}:\\s*(.+)$`, 'im'))
  return m ? m[1].trim() : null
}

function inferType(banner: string): Device['deviceType'] {
  const lower = banner.toLowerCase()
  if (/router|gateway|netgear|tp-link|xiaomi|honor|huawei/.test(lower)) return 'router'
  if (/camera|ipcam|hikvision|dahua|ezviz/.test(lower)) return 'camera'
  if (/nas|synology|qnap|群晖/.test(lower)) return 'nas'
  if (/printer|hp|canon|epson/.test(lower)) return 'printer'
  return 'unknown'
}

function bufToString(buf: ArrayBuffer): string {
  const arr = new Uint8Array(buf)
  return String.fromCharCode(...arr)
}

function delay(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
