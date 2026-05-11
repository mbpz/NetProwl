import Taro from '@tarojs/taro'
import { Device, DeviceType } from '../types'

const SSDP_ADDR = '239.255.255.250'
const SSDP_PORT = 1900
const M_SEARCH = [
  'M-SEARCH * HTTP/1.1',
  'HOST: 239.255.255.250:1900',
  'MAN: "ssdp:discover"',
  'MX: 2',
  'ST: ssdp:all',
  '',
  '',
].join('\r\n')

export async function discoverViaSSDP(): Promise<Device[]> {
  const devices: Device[] = []
  const seen = new Set<string>()

  const udp = Taro.createUDPSocket()

  udp.onMessage((res: any) => {
    const banner = arrayBufferToString(res.message)
    const device = parseSSDPResponse(banner, res.remoteInfo.address)
    if (device && !seen.has(device.ip)) {
      seen.add(device.ip)
      devices.push(device)
    }
  })

  udp.onError((err: any) => {
    console.error('UDP SSDP error', err)
    udp.close()
  })

  try {
    udp.send({
      address: SSDP_ADDR,
      port: SSDP_PORT,
      message: M_SEARCH,
    })

    await delay(3000)
  } finally {
    udp.close()
  }

  return devices
}

function parseSSDPResponse(banner: string, ip: string): Device | null {
  if (!banner.includes('HTTP/1.1 200')) return null

  const getHeader = (key: string): string | null => {
    const re = new RegExp(`^${key}:\\s*(.+)$`, 'im')
    const m = banner.match(re)
    return m ? m[1].trim() : null
  }

  const friendlyName = getHeader('SERVER') || getHeader('X-FriendlyName') || ip
  const usn = getHeader('USN') || ip

  return {
    id: usn,
    ip,
    mac: null,
    hostname: friendlyName,
    vendor: null,
    deviceType: inferDeviceType(friendlyName, banner),
    os: 'unknown',
    openPorts: [],
    discoveredAt: Date.now(),
    sources: ['ssdp'],
  }
}

function inferDeviceType(name: string, banner: string): DeviceType {
  const lower = (name + banner).toLowerCase()
  if (/router|gateway|netgear|tp-link|xiaomi|honor|huawei/.test(lower)) return 'router'
  if (/camera|ipcam|hikvision|dahua|ezviz|萤石/.test(lower)) return 'camera'
  if (/nas|synology|qnap|群晖|威联通/.test(lower)) return 'nas'
  if (/printer|hp|canon|epson/.test(lower)) return 'printer'
  if (/iphone|android|手机|mobile/.test(lower)) return 'phone'
  return 'unknown'
}

function arrayBufferToString(buffer: ArrayBuffer): string {
  const arr = new Uint8Array(buffer)
  return String.fromCharCode(...arr)
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}
