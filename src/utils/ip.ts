import { OSType } from '../types'

/** From local IP infer /24 subnet range */
export function inferSubnet(localIP: string): string {
  const parts = localIP.split('.')
  parts[3] = '0'
  return `${parts.join('.')}/24`
}

/** Generate all IPs in a /24 subnet (1-254) */
export function expandSubnet(subnet: string): string[] {
  const [base, mask] = subnet.split('/')
  const prefix = base.split('.').slice(0, 3).join('.')
  const count = mask === '24' ? 254 : 254
  return Array.from({ length: count }, (_, i) => `${prefix}.${i + 1}`)
}

/** Check if IP is private (RFC 1918) */
export function isPrivateIP(ip: string): boolean {
  const p = ip.split('.').map(Number)
  return (
    (p[0] === 10) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168)
  )
}

/** Normalize MAC to lowercase colon-separated */
export function normalizeMac(mac: string): string {
  return mac.replace(/[-:]/g, ':').toLowerCase()
}

/** Infer OS from TTL value */
export function inferOS(ttl: number): OSType {
  if (ttl <= 64) return 'linux'
  if (ttl <= 128) return 'windows'
  if (ttl >= 255) return 'network'
  return 'unknown'
}