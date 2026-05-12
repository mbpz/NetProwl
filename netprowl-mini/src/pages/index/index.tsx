import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import { discoverMDNS } from '../../services/mdns'
import { discoverSSDP } from '../../services/udp'
import TopoCanvas from '../../components/TopoCanvas'
import ScanButton from '../../components/ScanButton'
import './index.css'

export default class IndexPage extends Component {
  store = useDeviceStore()

  componentDidShow() {
    this.store.loadHistory()
  }

  handleScan = async () => {
    if (this.store.scanning) return
    this.store.setScanning(true)

    try {
      const mdnsDevices = await discoverMDNS()
      mdnsDevices.forEach(d => this.store.addDevice(d))

      const ssdpDevices = await discoverSSDP()
      ssdpDevices.forEach(d => this.store.addDevice(d))

      this.store.setScanning(false)
    } catch (e) {
      this.store.setScanning(false)
    }
  }

  handleDeviceClick = (device: any) => {
    wx.navigateTo({ url: `/pages/devices/index?ip=${device.ip}` })
  }

  render() {
    const { devices, scanning } = this.store
    const gatewayIP = devices.find(d => d.deviceType === 'router')?.ip || devices[0]?.ip || ''

    return (
      <View className='index-page'>
        <View className='summary-bar'>
          <Text className='summary'>
            {devices.length === 0 ? '点击下方按钮开始局域网扫描' : `发现 ${devices.length} 台设备`}
          </Text>
        </View>
        <View className='topo-wrap'>
          <TopoCanvas devices={devices} gatewayIP={gatewayIP} onDeviceClick={this.handleDeviceClick} />
        </View>
        <ScanButton scanning={scanning} onScan={this.handleScan} />
      </View>
    )
  }
}