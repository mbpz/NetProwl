/**
 * rs-core WASM loader
 *
 * Build: cd core && wasm-pack build --target web --out-dir pkg
 * Output: core/pkg/ (imported below as relative path)
 */
import init, {
  lookup_vendor,
  infer_subnet,
  expand_subnet,
  discover_mdns,
  discover_ssdp,
  probe_tcp_ports,
  scan_network,
} from '../../core/pkg'

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

// ============== Discovery ==============

export async function wasmDiscoverMDNS(serviceTypes: string[], timeoutMs: number): Promise<string> {
  await ensureInit()
  return discover_mdns(JSON.stringify(serviceTypes), timeoutMs) as any
}

export async function wasmDiscoverSSDP(timeoutMs: number): Promise<string> {
  await ensureInit()
  return discover_ssdp(timeoutMs) as any
}

export async function wasmProbeTCPPorts(ip: string, ports: number[], timeoutMs: number): Promise<string> {
  await ensureInit()
  return probe_tcp_ports(ip, JSON.stringify(ports), timeoutMs) as any
}