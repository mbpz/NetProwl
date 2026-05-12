/**
 * rs-core WASM loader
 *
 * Build: cd rs-core && wasm-pack build --target web -d ../build
 * Output: build/ (copied to src/wasm_pkg/)
 */
import init, {
  lookup_vendor,
  infer_subnet,
  expand_subnet,
  guess_gateway,
  is_private_ip,
  discover_ssdp,
  discover_mdns,
  probe_tcp_ports,
  grab_banner,
  guess_service,
} from '../wasm_pkg/rs_core'

let initialized = false

async function ensureInit(): Promise<void> {
  if (!initialized) {
    await init()
    initialized = true
  }
}

// ============== OUI / IP utils ==============

export async function wasmLookupVendor(mac: string): Promise<string | null> {
  await ensureInit()
  return lookup_vendor(mac) ?? null
}

export async function wasmInferSubnet(localIP: string): Promise<string | null> {
  await ensureInit()
  return infer_subnet(localIP) ?? null
}

export async function wasmExpandSubnet(subnet: string): Promise<string[]> {
  await ensureInit()
  const json = expand_subnet(subnet)
  try {
    return JSON.parse(json) as string[]
  } catch {
    return []
  }
}

export async function wasmGuessGateway(localIP: string): Promise<string> {
  await ensureInit()
  return guess_gateway(localIP)
}

export async function wasmIsPrivateIP(ip: string): Promise<boolean> {
  await ensureInit()
  return is_private_ip(ip)
}

// ============== Discovery ==============

export async function wasmDiscoverSSDP(timeoutMs: number = 3000): Promise<string> {
  await ensureInit()
  return discover_ssdp(BigInt(timeoutMs))
}

export async function wasmDiscoverMDNS(serviceTypes: string[], timeoutMs: number = 5000): Promise<string> {
  await ensureInit()
  return discover_mdns(serviceTypes, BigInt(timeoutMs))
}

// ============== TCP scanning ==============

export async function wasmProbeTCPPorts(ip: string, ports: number[], timeoutMs: number = 2000): Promise<string> {
  await ensureInit()
  return probe_tcp_ports(ip, new Uint16Array(ports), BigInt(timeoutMs))
}

// ============== Banner ==============

export async function wasmGrabBanner(ip: string, port: number, timeoutMs: number = 3000): Promise<string> {
  await ensureInit()
  return grab_banner(ip, port, BigInt(timeoutMs))
}

// ============== Registry ==============

export async function wasmGuessService(port: number): Promise<string> {
  await ensureInit()
  return guess_service(port)
}
