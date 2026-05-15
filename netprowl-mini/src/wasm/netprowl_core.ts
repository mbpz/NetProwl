/**
 * rs-core WASM loader
 *
 * Build: cd rs-core && wasm-pack build --target web --out-dir pkg
 * Output: rs-core/pkg/ (copied to ../wasm_pkg/ for mini program)
 *
 * NOTE: mDNS/SSDP/TCP networking functions return empty results in WASM.
 * The mini program MUST use WeChat native APIs (wx.startLocalServiceDiscovery,
 * wx.createUDPSocket, wx.createTCPSocket) for actual network discovery.
 * WASM is only used for pure computation: OUI lookup, IP subnet math.
 */
import init, {
  lookup_vendor,
  infer_subnet,
  expand_subnet,
  guess_gateway,
  is_private_ip,
  discover_mdns,
  discover_ssdp,
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

// ============== Discovery (WASM stubs — use WeChat APIs in production) ==============

export async function wasmDiscoverMDNS(serviceTypes: string[], timeoutMs: number): Promise<string> {
  await ensureInit()
  // NOTE: Returns empty on WASM. Replace with wx.startLocalServiceDiscovery in production.
  return discover_mdns(serviceTypes as any, timeoutMs) as string
}

export async function wasmDiscoverSSDP(timeoutMs: number): Promise<string> {
  await ensureInit()
  // NOTE: Returns empty on WASM. Replace with wx.createUDPSocket in production.
  return discover_ssdp(timeoutMs) as string
}

export async function wasmProbeTCPPorts(ip: string, ports: number[], timeoutMs: number): Promise<string> {
  await ensureInit()
  // NOTE: Returns empty on WASM. Replace with wx.createTCPSocket in production.
  return probe_tcp_ports(ip, ports as any, timeoutMs) as string
}

export async function wasmGrabBanner(ip: string, port: number, timeoutMs: number): Promise<string> {
  await ensureInit()
  return grab_banner(ip, port, timeoutMs) as string
}

export async function wasmGuessService(port: number): Promise<string> {
  await ensureInit()
  return guess_service(port) as string
}
