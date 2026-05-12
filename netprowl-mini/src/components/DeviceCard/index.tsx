import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import type { Device } from '../../stores/deviceStore'
import './index.css'

interface Props {
  device: Device
  onClick: (d: Device) => void
}

export default class DeviceCard extends Component<Props> {
  render() {
    const { device, onClick } = this.props
    return (
      <View className='card' onClick={() => onClick(device)}>
        <View className='card-icon'>{this.getIcon(device.deviceType)}</View>
        <View className='card-info'>
          <Text className='ip'>{device.ip}</Text>
          <Text className='vendor'>{device.vendor || '未知厂商'}</Text>
        </View>
        <Text className='port-count'>{device.openPorts.length} 端口</Text>
      </View>
    )
  }

  getIcon(type: Device['deviceType']) {
    return { router: '🛣', pc: '💻', camera: '📹', nas: '💾', phone: '📱', printer: '🖨', unknown: '❓' }[type]
  }
}