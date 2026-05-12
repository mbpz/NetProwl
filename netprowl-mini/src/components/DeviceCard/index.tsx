import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { Device } from '../../types'

const iconMap: Record<string, string> = {
  router: '🛣',
  pc: '💻',
  camera: '📹',
  nas: '💾',
  phone: '📱',
  printer: '🖨',
  unknown: '❓'
}

interface Props {
  device: Device
  onClick: (device: Device) => void
}

export default class DeviceCard extends Component<Props> {
  render() {
    const { device, onClick } = this.props
    return (
      <View className='device-card' onClick={() => onClick(device)}>
        <View className='card-icon'>
          <Text style={{ fontSize: '28px' }}>{iconMap[device.deviceType] || '❓'}</Text>
        </View>
        <View className='card-info'>
          <Text className='card-ip'>{device.ip}</Text>
          <Text className='card-vendor'>{device.vendor || '未知厂商'}</Text>
        </View>
        <Text className='card-ports'>{device.openPorts?.length || 0} 端口</Text>
      </View>
    )
  }
}
