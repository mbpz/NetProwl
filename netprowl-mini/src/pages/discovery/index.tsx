import { Component } from 'react'
import { View, Text, ScrollView } from '@tarojs/components'
import { Device } from '../../types'
import { runScan } from '../../services/scanner'
import { getLocalIPAddress } from '../../services/network'
import TopoCanvas from '../../components/TopoCanvas'
import DeviceCard from '../../components/DeviceCard'
import ScanButton from '../../components/ScanButton'

interface State {
  devices: Device[]
  scanning: boolean
  selectedDevice: Device | null
  mdnsUnavailable: boolean
  lastScanTime: number | null
  summaryText: string
  localIP: string
}

export default class Discovery extends Component<State> {
  state: State = {
    devices: [],
    scanning: false,
    selectedDevice: null,
    mdnsUnavailable: false,
    lastScanTime: null,
    summaryText: '点击下方按钮开始局域网扫描',
    localIP: ''
  }

  async componentDidMount() {
    const ip = await getLocalIPAddress()
    this.setState({ localIP: ip })
  }

  async handleScan() {
    if (this.state.scanning) return
    this.setState({ scanning: true, summaryText: '扫描中...' })

    try {
      const result = await runScan()
      const duration = (result.durationMs / 1000).toFixed(1)
      this.setState({
        devices: result.devices,
        scanning: false,
        lastScanTime: Date.now(),
        mdnsUnavailable: result.mdnsUnavailable,
        summaryText: `发现 ${result.devices.length} 台设备，耗时 ${duration}s`
      })

      if (result.mdnsUnavailable) {
        wx.showToast({ title: 'iOS 环境已降级至 TCP 扫描', icon: 'none', duration: 2000 })
      }
    } catch (err) {
      this.setState({ scanning: false, summaryText: '扫描失败，请重试' })
    }
  }

  handleDeviceClick(device: Device) {
    this.setState({ selectedDevice: device })
  }

  handleDrawerClose() {
    this.setState({ selectedDevice: null })
  }

  render() {
    const { devices, scanning, selectedDevice, summaryText } = this.state
    const gatewayIP = devices.find((d: Device) => d.deviceType === 'router')?.ip || devices[0]?.ip || ''

    return (
      <View className='discovery-page'>
        <View className='summary-bar'>
          <Text className='summary-text'>{summaryText}</Text>
        </View>

        <ScrollView scrollY className='device-scroll'>
          {devices.length === 0 ? (
            <View className='empty-state'>
              <Text className='empty-icon'>🛣</Text>
              <Text className='empty-text'>未发现设备</Text>
              <Text className='empty-hint'>确认在同一 WiFi 下</Text>
            </View>
          ) : (
            <View className='device-list'>
              {devices.map((d: Device) => (
                <DeviceCard key={d.ip} device={d} onClick={this.handleDeviceClick.bind(this)} />
              ))}
            </View>
          )}
        </ScrollView>

        <View className='bottom-area'>
          {devices.length > 0 && gatewayIP && (
            <View className='topo-wrap'>
              <TopoCanvas devices={devices} gatewayIP={gatewayIP} onDeviceClick={this.handleDeviceClick.bind(this)} />
            </View>
          )}
          <ScanButton scanning={scanning} onScan={this.handleScan.bind(this)} />
        </View>

        {selectedDevice && (
          <View className='drawer-overlay' onClick={this.handleDrawerClose.bind(this)}>
            <View className='drawer-panel' onClick={(e) => e.stopPropagation()}>
              <View className='drawer-header'>
                <Text className='drawer-ip'>{selectedDevice.ip}</Text>
                <Text className='drawer-close' onClick={this.handleDrawerClose.bind(this)}>✕</Text>
              </View>
              <View className='drawer-body'>
                <View className='info-row'>
                  <Text className='info-label'>厂商</Text>
                  <Text className='info-value'>{selectedDevice.vendor || '—'}</Text>
                </View>
                <View className='info-row'>
                  <Text className='info-label'>类型</Text>
                  <Text className='info-value'>{selectedDevice.deviceType}</Text>
                </View>
                <View className='info-row'>
                  <Text className='info-label'>端口</Text>
                  <Text className='info-value'>{selectedDevice.openPorts?.length || 0}</Text>
                </View>
              </View>
            </View>
          </View>
        )}
      </View>
    )
  }
}
