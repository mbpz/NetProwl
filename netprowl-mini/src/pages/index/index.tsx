import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import { runFullScan } from '../../services/scanner'
import TopoCanvas from '../../components/TopoCanvas'
import DeviceCard from '../../components/DeviceCard'
import { Device } from '../../types'

export default class Index extends Component {
  state = {
    selectedDevice: null as Device | null,
  }

  handleScan = async () => {
    await runFullScan()
  }

  handleDeviceClick = (device: Device) => {
    this.setState({ selectedDevice: device })
  }

  handleCloseDetail = () => {
    this.setState({ selectedDevice: null })
  }

  render() {
    const { devices, scanning, networkInfo } = useDeviceStore()
    const { selectedDevice } = this.state
    const gatewayIP = networkInfo?.gatewayIP || '192.168.1.1'

    return (
      <View className="container">
        <View className="header">
          <Text className="title">NetProwl</Text>
          <Text className="subtitle">局域网安全扫描</Text>
          {networkInfo && (
            <Text className="network-info">
              {networkInfo.localIP !== '0.0.0.0' ? networkInfo.localIP : '检测中...'} · {networkInfo.subnet}
            </Text>
          )}
        </View>

        <TopoCanvas
          devices={devices}
          gatewayIP={gatewayIP}
          onDeviceClick={this.handleDeviceClick}
        />

        <View className="scan-btn-wrap">
          <View
            className={`scan-btn ${scanning ? 'scanning' : ''}`}
            onClick={scanning ? undefined : this.handleScan}
          >
            <Text>{scanning ? '⏳ 扫描中...' : '🔍 开始扫描'}</Text>
          </View>
        </View>

        {devices.length > 0 && (
          <View className="device-list">
            <Text className="section-title">设备详情 ({devices.length})</Text>
            {devices.map(d => (
              <DeviceCard
                key={d.id}
                device={d}
                onClick={this.handleDeviceClick}
              />
            ))}
          </View>
        )}

        {selectedDevice && (
          <View className="device-detail-modal" onClick={this.handleCloseDetail}>
            <View className="modal-content" onClick={() => {}}>
              <View className="modal-header">
                <Text className="modal-title">{selectedDevice.hostname || selectedDevice.ip}</Text>
                <Text className="modal-close" onClick={this.handleCloseDetail}>✕</Text>
              </View>
              <View className="modal-body">
                <View className="info-row">
                  <Text className="info-label">IP</Text>
                  <Text className="info-value">{selectedDevice.ip}</Text>
                </View>
                {selectedDevice.mac && (
                  <View className="info-row">
                    <Text className="info-label">MAC</Text>
                    <Text className="info-value">{selectedDevice.mac}</Text>
                  </View>
                )}
                {selectedDevice.vendor && (
                  <View className="info-row">
                    <Text className="info-label">厂商</Text>
                    <Text className="info-value">{selectedDevice.vendor}</Text>
                  </View>
                )}
                <View className="info-row">
                  <Text className="info-label">类型</Text>
                  <Text className="info-value">{selectedDevice.deviceType}</Text>
                </View>
                <View className="info-row">
                  <Text className="info-label">来源</Text>
                  <Text className="info-value">{selectedDevice.sources.join(', ')}</Text>
                </View>
                {selectedDevice.openPorts.length > 0 && (
                  <View className="ports-section">
                    <Text className="ports-title">开放端口 ({selectedDevice.openPorts.length})</Text>
                    {selectedDevice.openPorts.map(p => (
                      <View className="port-item" key={p.port}>
                        <Text className="port-num">{p.port}</Text>
                        <Text className="port-service">{p.service || '-'}</Text>
                        <Text className="port-state">{p.state}</Text>
                      </View>
                    ))}
                  </View>
                )}
              </View>
            </View>
          </View>
        )}
      </View>
    )
  }
}