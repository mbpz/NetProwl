// Network service — local IP detection and subnet inference
export async function getLocalIPAddress(): Promise<string> {
  try {
    const res = wx.getLocalIPAddress({})
    return res.ip || '0.0.0.0'
  } catch {
    return '0.0.0.0'
  }
}

export function inferSubnet(localIP: string): string {
  const parts = localIP.split('.')
  if (parts.length !== 4) return '192.168.1.0/24'
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`
}
