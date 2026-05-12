import { Component } from 'react'
import { View, Text, ScrollView } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import './index.css'

export default class HistoryPage extends Component {
  store = useDeviceStore()

  componentDidShow() {
    this.store.loadHistory()
  }

  formatTime(ts: number) {
    const d = new Date(ts)
    return `${d.getMonth()+1}-${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2,'0')}`
  }

  render() {
    const { history } = this.store
    return (
      <View className='history-page'>
        <ScrollView scrollY className='list'>
          {history.length === 0 ? (
            <View className='empty'><Text className='empty-text'>暂无扫描记录</Text></View>
          ) : history.map((snap) => (
            <View key={snap.id} className='snap-item'>
              <View className='snap-dot' />
              <View className='snap-info'>
                <Text className='snap-time'>{this.formatTime(snap.timestamp)}</Text>
                <Text className='snap-range'>{snap.ipRange}</Text>
              </View>
              <Text className='snap-count'>{snap.deviceCount} 台</Text>
            </View>
          ))}
        </ScrollView>
      </View>
    )
  }
}