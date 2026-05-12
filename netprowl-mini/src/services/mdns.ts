import type { Device } from '../stores/deviceStore'

const SERVICE_TYPES = ['_http._tcp', '_smb._tcp', '_ssh._tcp', '_ftp._tcp', '_airplay._tcp', '_googlecast._tcp']

export async function discoverMDNS(): Promise<Device[]> {
  const found = new Map<string, Device>()

  wx.onLocalServiceFound((res: any) => {
    const key = res.serviceName
    if (!found.has(key)) {
      found.set(key, {
        id: key,
        ip: res.ip,
        mac: null,
        hostname: res.hostName || res.serviceName,
        vendor: null,
        deviceType: 'unknown',
        os: 'unknown',
        openPorts: [],
        discoveredAt: Date.now(),
        sources: ['mdns'],
      })
    }
  })

  for (const st of SERVICE_TYPES) {
    try {
      await wx.startLocalServiceDiscovery({ serviceType: st })
    } catch (e: any) {
      if (e?.errCode === -1) {
        // iOS mDNS disabled — handled at scanner level
      }
    }
  }

  await delay(3000)
  wx.stopLocalServiceDiscovery({})
  return Array.from(found.values())
}

function delay(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
