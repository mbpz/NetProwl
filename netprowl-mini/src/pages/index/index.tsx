import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import { runFullScan } from '../../services/scanner'
import TopoCanvas from '../../components/TopoCanvas'
import DeviceCard from '../../components/DeviceCard'

const GATEWAY_IP = '192.168.1.1'

export default class Index extends Component {
  handleScan = async () => {
    await runFullScan()
  }

  render() {
    const { devices, scanning } = useDeviceStore()

    return (
      <View className="container">
        <View className="header">
          <Text className="title">NetProwl</Text>
          <Text className="subtitle">局域网安全扫描</Text>
        </View>

        <View className="scan-btn-wrap">
          <View
            className={`scan-btn ${scanning ? 'scanning' : ''}`}
            onClick={scanning ? undefined : this.handleScan}
          >
            <Text>{scanning ? '⏳ 扫描中...' : '🔍 开始扫描'}</Text>
          </View>
        </View>

        <TopoCanvas
          devices={devices}
          gatewayIP={GATEWAY_IP}
          onDeviceClick={() => {}}
        />

        {devices.length > 0 && (
          <View className="device-list">
            <Text className="section-title">发现的设备 ({devices.length})</Text>
            {devices.map(d => (
              <DeviceCard
                key={d.id}
                device={d}
                onClick={() => {}}
              />
            ))}
          </View>
        )}
      </View>
    )
  }
}