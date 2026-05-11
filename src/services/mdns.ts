import Taro from '@tarojs/taro'
import { Device } from '../types'

const SERVICE_TYPES = [
  '_http._tcp',
  '_ftp._tcp',
  '_ssh._tcp',
  '_smb._tcp',
  '_airplay._tcp',
  '_googlecast._tcp',
  '_ipp._tcp',
]

export async function discoverViaMDNS(): Promise<Device[]> {
  const devices: Device[] = []
  const foundMap = new Map<string, Device>()

  // Subscribe to found events
  Taro.onLocalServiceFound((res: any) => {
    const key = res.serviceName
    if (!foundMap.has(key)) {
      foundMap.set(key, {
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

  for (const serviceType of SERVICE_TYPES) {
    try {
      await startDiscovery(serviceType)
    } catch {
      // Single failure doesn't stop
    }
  }

  // Wait then stop
  await delay(3000)
  stopDiscovery()

  return Array.from(foundMap.values())
}

function startDiscovery(serviceType: string): Promise<void> {
  return new Promise((resolve, reject) => {
    Taro.startLocalServiceDiscovery({ serviceType })
      .then(() => resolve())
      .catch((err: any) => {
        // iOS 7.0.18+ errCode -1 means disabled
        if (err.errCode === -1) {
          reject(new Error('MDNS_DISABLED'))
        } else {
          reject(err)
        }
      })
  })
}

function stopDiscovery(): void {
  try {
    Taro.stopLocalServiceDiscovery({})
  } catch {
    // Ignore
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

export function isMDNSDisabledError(err: unknown): boolean {
  return err instanceof Error && err.message === 'MDNS_DISABLED'
}