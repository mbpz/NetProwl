import { Component } from 'react'
import { View, Text, ScrollView } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import DeviceCard from '../../components/DeviceCard'
import './index.css'

export default class DevicesPage extends Component {
  store = useDeviceStore()

  handleClick = (device: any) => {
    wx.navigateTo({ url: `/pages/topology/index?ip=${device.ip}` })
  }

  render() {
    return (
      <View className='devices-page'>
        <ScrollView scrollY className='list'>
          {this.store.devices.map(d => (
            <DeviceCard key={d.id} device={d} onClick={this.handleClick} />
          ))}
        </ScrollView>
      </View>
    )
  }
}