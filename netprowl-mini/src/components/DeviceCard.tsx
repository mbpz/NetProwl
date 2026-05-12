import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { Device, DeviceType } from '../types'

const DEVICE_ICONS: Record<DeviceType, string> = {
  router: '🔰',
  pc: '💻',
  camera: '📹',
  nas: '💾',
  phone: '📱',
  printer: '🖨️',
  unknown: '📟',
}

interface DeviceCardProps {
  device: Device
  onClick?: (device: Device) => void
}

export default class DeviceCard extends Component<DeviceCardProps> {
  render() {
    const { device } = this.props
    const icon = DEVICE_ICONS[device.deviceType] || DEVICE_ICONS.unknown
    const portCount = device.openPorts?.length || 0

    return (
      <View className="device-card" onClick={() => this.props.onClick?.(device)}>
        <View className="card-icon">
          <Text style={{ fontSize: '28px' }}>{icon}</Text>
        </View>
        <View className="card-info">
          <Text className="ip">{device.ip}</Text>
          {device.hostname && <Text className="hostname">{device.hostname}</Text>}
          {device.vendor && <Text className="vendor">{device.vendor}</Text>}
          <Text className="ports">{portCount} 个开放端口</Text>
        </View>
        <View className="card-arrow">
          <Text style={{ color: '#666', fontSize: '20px' }}>›</Text>
        </View>
      </View>
    )
  }
}