// TCP port probing service
import { Port } from '../types'
import { wasmProbeTCPPorts } from '../wasm/netprowl_core'

const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]

export async function probeTCPPorts(ip: string, ports: number[] = WHITE_PORTS): Promise<number[]> {
  try {
    const json = await wasmProbeTCPPorts(ip, ports, 2000)
    const result: any[] = JSON.parse(json)
    return result.map(p => p.port)
  } catch {
    return []
  }
}

export async function probeTCPPortsFull(ip: string, ports: number[] = WHITE_PORTS): Promise<Port[]> {
  try {
    const json = await wasmProbeTCPPorts(ip, ports, 2000)
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
