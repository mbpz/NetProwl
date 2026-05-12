// Network service — local IP detection and subnet inference
import { wasmInferSubnet, wasmExpandSubnet } from '../wasm/netprowl_core'

export interface NetworkInfo {
  localIP: string
  gatewayIP: string
  subnet: string
  wifi: boolean
}

// Well-known gateway suffixes
const GATEWAY_SUFFIXES = ['.1', '.254']

export async function getLocalIPAddress(): Promise<string> {
  try {
    const res = wx.getLocalIPAddress({})
    if (res && res.ip) {
      return res.ip
    }
  } catch {
    // fallthrough
  }
  return '0.0.0.0'
}

export async function inferSubnet(localIP: string): Promise<string> {
  const result = await wasmInferSubnet(localIP)
  return result ?? '192.168.1.0/24'
}

export async function expandSubnet(subnet: string): Promise<string[]> {
  return await wasmExpandSubnet(subnet)
}

export function guessGatewayIP(localIP: string): string {
  const parts = localIP.split('.')
  if (parts.length !== 4) return '192.168.1.1'

  const base = `${parts[0]}.${parts[1]}.${parts[2]}`
  return `${base}.1`
}

export async function getNetworkInfo(): Promise<NetworkInfo> {
  const localIP = await getLocalIPAddress()
  const subnet = inferSubnet(localIP)
  const gatewayIP = guessGatewayIP(localIP)

  let wifi = false
  try {
    const info = wx.getNetworkType({})
    wifi = info.networkType === 'wifi'
  } catch {
    // ignore
  }

  return { localIP, gatewayIP, subnet, wifi }
}
