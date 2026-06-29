// TCP port probing service
import { Port } from '../types'
import { wasmProbeTCPPorts } from '../wasm/netprowl_core'

const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]
const DEFAULT_TIMEOUT_MS = 2000

export async function probeTCPPorts(ip: string, ports: number[] = WHITE_PORTS): Promise<number[]> {
  const wxApi = (globalThis as any).wx
  if (wxApi?.createTCPSocket) {
    const results = await probeTCPPortsFull(ip, ports)
    return results.map(p => p.port)
  }

  try {
    const json = await wasmProbeTCPPorts(ip, ports, DEFAULT_TIMEOUT_MS)
    const result: any[] = JSON.parse(json)
    return result.map(p => p.port)
  } catch {
    return []
  }
}

export async function probeTCPPortsFull(ip: string, ports: number[] = WHITE_PORTS): Promise<Port[]> {
  const wxApi = (globalThis as any).wx
  if (wxApi?.createTCPSocket) {
    const results = await Promise.all(ports.map(port => probeWechatTCPPort(wxApi, ip, port)))
    return results.filter((p): p is Port => Boolean(p))
  }

  try {
    const json = await wasmProbeTCPPorts(ip, ports, DEFAULT_TIMEOUT_MS)
    const result: any[] = JSON.parse(json)
    return result.map((p: any) => ({
      port: p.port,
      service: p.service || null,
      state: p.state || 'open',
      banner: p.banner || null,
    }))
  } catch {
    return []
  }
}

async function probeWechatTCPPort(wxApi: any, ip: string, port: number): Promise<Port | null> {
  return new Promise((resolve) => {
    const socket = wxApi.createTCPSocket()
    let settled = false

    const done = (result: Port | null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.offConnect?.(onConnect)
      socket.offError?.(onError)
      socket.close?.()
      resolve(result)
    }

    const onConnect = () => done({
      port,
      service: guessService(port),
      state: 'open',
      banner: undefined,
    })
    const onError = () => done(null)
    const timer = setTimeout(() => done(null), DEFAULT_TIMEOUT_MS)

    socket.onConnect?.(onConnect)
    socket.onError?.(onError)
    try {
      socket.connect({ address: ip, port, timeout: DEFAULT_TIMEOUT_MS })
    } catch {
      done(null)
    }
  })
}

function guessService(port: number): string | null {
  const map: Record<number, string> = {
    80: 'http',
    443: 'https',
    554: 'rtsp',
    5000: 'upnp',
    8080: 'http-alt',
    8443: 'https-alt',
    9000: 'cslistener',
    49152: 'upnp',
  }
  return map[port] || null
}
