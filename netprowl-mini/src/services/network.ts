// src/services/network.ts
// Network awareness — local IP, subnet inference

export interface NetworkInfo {
  localIP: string
  subnet: string
  gateway?: string
}

async function getLocalIPAddress(): Promise<string> {
  // Stub — wx.getLocalIPAddress in real implementation
  return '192.168.1.100'
}

async function inferSubnet(): Promise<string> {
  const localIP = await getLocalIPAddress()
  const parts = localIP.split('.')
  if (parts.length !== 4) return ''
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`
}

export const network = {
  getLocalIPAddress,
  inferSubnet,
}