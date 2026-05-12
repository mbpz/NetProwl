import { Component } from 'react'
import { View } from '@tarojs/components'
import { Device } from '../../types'

interface Props {
  devices: Device[]
  gatewayIP: string
  onDeviceClick: (device: Device) => void
}

export default class TopoCanvas extends Component<Props> {
  render() {
    // Stub: simple placeholder for topology canvas
    return (
      <View className='topo-placeholder'>
        <View style={{ textAlign: 'center', padding: '40rpx' }}>
          <Text style={{ color: '#666', fontSize: '28rpx' }}>拓扑图 {this.props.devices.length} 台设备</Text>
        </View>
      </View>
    )
  }
}
