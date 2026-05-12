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
