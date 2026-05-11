import Taro from '@tarojs/taro'
import { inferSubnet } from '../utils/ip'

interface NetworkInfo {
  ip: string
  subnet: string
}

export async function getLocalNetworkInfo(): Promise<NetworkInfo> {
  const ip = await getLocalIPAddress()
  return { ip, subnet: inferSubnet(ip) }
}

export async function getLocalIPAddress(): Promise<string> {
  try {
    const res = Taro.getLocalIPAddress({})
    return res.ip || '0.0.0.0'
  } catch {
    return '0.0.0.0'
  }
}

export async function getNetworkType(): Promise<string> {
  const res = await Taro.getNetworkType()
  return res.networkType
}
