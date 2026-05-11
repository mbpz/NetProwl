import Taro from '@tarojs/taro'
import { Device, Port } from '../types'

const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]
const CONCURRENCY = 20
const TIMEOUT_MS = 2000
const TOTAL_TIMEOUT_MS = 60000

export async function probeTCPPorts(ip: string): Promise<Port[]> {
  const openPorts: Port[] = []
  const chunks = chunkArray(WHITE_PORTS, CONCURRENCY)

  for (const group of chunks) {
    const results = await Promise.all(group.map((port) => probePort(ip, port)))
    results.forEach((p) => { if (p) openPorts.push(p) })
    await delay(50)
  }

  return openPorts
}

async function probePort(ip: string, port: number): Promise<Port | null> {
  return new Promise((resolve) => {
    const socket = Taro.createTCPSocket()
    let settled = false

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true
        socket.close()
        resolve(null)
      }
    }, TIMEOUT_MS)

    socket.onConnect(() => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        socket.close()
        resolve({ port, service: null, state: 'open' })
      }
    })

    socket.onError(() => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        socket.close()
        resolve(null)
      }
    })

    socket.connect({ address: ip, port })
  })
}

export async function probeIPs(ipRange: string, ips: string[]): Promise<Device[]> {
  const devices: Device[] = []
  const start = Date.now()

  for (const ip of ips) {
    if (Date.now() - start > TOTAL_TIMEOUT_MS) break

    const ports = await probeTCPPorts(ip)
    if (ports.length > 0) {
      devices.push({
        id: ip,
        ip,
        mac: null,
        hostname: null,
        vendor: null,
        deviceType: 'unknown',
        os: 'unknown',
        openPorts: ports,
        discoveredAt: Date.now(),
        sources: ['tcp'],
      })
    }
  }

  return devices
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = []
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size))
  }
  return chunks
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}
