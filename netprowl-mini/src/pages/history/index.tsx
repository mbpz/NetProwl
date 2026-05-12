import { Component } from 'react'
import { View, Text, ScrollView } from '@tarojs/components'
import { ScanSnapshot } from '../../types'
import { loadHistory } from '../../services/storage'

interface State {
  history: ScanSnapshot[]
  expandedId: string | null
}

export default class History extends Component<State> {
  state: State = {
    history: [],
    expandedId: null
  }

  async componentDidShow() {
    const history = await loadHistory()
    this.setState({ history })
  }

  toggleExpand(id: string) {
    this.setState((s) => ({
      expandedId: s.expandedId === id ? null : id
    }))
  }

  formatTime(ts: number) {
    const d = new Date(ts)
    return `${d.getMonth() + 1}-${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`
  }

  render() {
    const { history, expandedId } = this.state

    return (
      <View className='history-page'>
        <ScrollView scrollY className='history-list'>
          {history.length === 0 ? (
            <View className='empty'>
              <Text className='empty-text'>暂无扫描记录</Text>
            </View>
          ) : (
            history.map((snap) => (
              <View key={snap.id} className='history-item'>
                <View className='item-header' onClick={() => this.toggleExpand(snap.id)}>
                  <View className='item-dot' />
                  <View className='item-info'>
                    <Text className='item-time'>{this.formatTime(snap.timestamp)}</Text>
                    <Text className='item-sub'>{snap.ipRange}</Text>
                  </View>
                  <Text className='item-count'>{snap.deviceCount} 台</Text>
                </View>

                {expandedId === snap.id && (
                  <View className='item-detail'>
                    {snap.devices.map((d) => (
                      <View key={d.ip} className='device-row'>
                        <Text className='device-ip'>{d.ip}</Text>
                        <Text className='device-ports'>{d.openPorts?.length || 0} 端口</Text>
                      </View>
                    ))}
                  </View>
                )}
              </View>
            ))
          )}
        </ScrollView>
      </View>
    )
  }
}
