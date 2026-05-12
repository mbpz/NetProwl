import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import './index.css'

export default class TopologyPage extends Component {
  store = useDeviceStore()

  render() {
    const ip = (wx as any).getCurrentInstance?.()?.router?.params?.ip || ''
    const device = this.store.devices.find(d => d.ip === ip)
    if (!device) return <View className='topo-page'><Text>未找到设备</Text></View>

    return (
      <View className='topo-page'>
        <View className='device-header'>
          <Text className='ip'>{device.ip}</Text>
          <Text className='vendor'>{device.vendor || '未知厂商'}</Text>
          <Text className='risk'>风险: {device.openPorts.length > 3 ? '高' : device.openPorts.length > 0 ? '中' : '低'}</Text>
        </View>
        <View className='ports'>
          {device.openPorts.map((p: any) => (
            <View key={p.number} className='port-tag'>
              <Text className='port-num'>{p.number}</Text>
              <Text className='port-svc'>{p.service || 'unknown'}</Text>
            </View>
          ))}
        </View>
      </View>
    )
  }
}