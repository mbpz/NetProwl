import { Component } from 'react'
import { View, Text, ScrollView } from '@tarojs/components'
import type { ScanSnapshot, Device } from '../../types'
import { loadHistory, compareSnapshots } from '../../services/storage'
import type { SnapshotDiff } from '../../services/storage'

interface State {
  history: ScanSnapshot[]
  expandedId: string | null
  comparingId: string | null
  diff: SnapshotDiff | null
}

export default class History extends Component<{}, State> {
  state: State = {
    history: [],
    expandedId: null,
    comparingId: null,
    diff: null,
  }

  async componentDidShow() {
    const history = await loadHistory()
    this.setState({ history })
  }

  toggleExpand(id: string) {
    this.setState((s) => ({
      expandedId: s.expandedId === id ? null : id,
      comparingId: null,
      diff: null,
    }))
  }

  handleCompare(snap: ScanSnapshot, idx: number) {
    const { history, comparingId } = this.state
    if (comparingId === snap.id) {
      this.setState({ comparingId: null, diff: null })
      return
    }
    // Compare with previous snapshot (next in list = older)
    const prevSnap = history[idx + 1]
    if (!prevSnap) {
      this.setState({ comparingId: snap.id, diff: null })
      return
    }
    const diff = compareSnapshots(prevSnap, snap)
    this.setState({ comparingId: snap.id, diff })
  }

  formatTime(ts: number) {
    const d = new Date(ts)
    return `${d.getMonth() + 1}-${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`
  }

  getDiffSummary(diff: SnapshotDiff) {
    const parts: string[] = []
    if (diff.added.length > 0) parts.push(`+${diff.added.length} 新`)
    if (diff.removed.length > 0) parts.push(`-${diff.removed.length} 消失`)
    if (diff.changed.length > 0) parts.push(`~${diff.changed.length} 变化`)
    return parts.join(' ')
  }

  render() {
    const { history, expandedId, comparingId, diff } = this.state

    return (
      <View className='history-page'>
        <View className='history-header'>
          <Text className='history-title'>扫描历史</Text>
        </View>
        <ScrollView scrollY className='history-list'>
          {history.length === 0 ? (
            <View className='empty'>
              <Text className='empty-text'>暂无扫描记录</Text>
            </View>
          ) : (
            history.map((snap, idx) => (
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
                    {idx < history.length - 1 && (
                      <View
                        className={`compare-btn ${comparingId === snap.id ? 'active' : ''}`}
                        onClick={() => this.handleCompare(snap, idx)}
                      >
                        <Text className='compare-text'>
                          {comparingId === snap.id ? '收起对比' : '对比上次'}
                        </Text>
                      </View>
                    )}

                    {comparingId === snap.id && diff && (
                      <View className='diff-section'>
                        {diff.added.length > 0 && (
                          <View className='diff-group'>
                            <Text className='diff-label added'>新增设备</Text>
                            {diff.added.map(d => (
                              <View key={d.ip} className='diff-row added'>
                                <Text className='diff-ip'>{d.ip}</Text>
                                <Text className='diff-info'>{d.vendor || d.deviceType}</Text>
                              </View>
                            ))}
                          </View>
                        )}
                        {diff.removed.length > 0 && (
                          <View className='diff-group'>
                            <Text className='diff-label removed'>消失设备</Text>
                            {diff.removed.map(d => (
                              <View key={d.ip} className='diff-row removed'>
                                <Text className='diff-ip'>{d.ip}</Text>
                                <Text className='diff-info'>{d.vendor || d.deviceType}</Text>
                              </View>
                            ))}
                          </View>
                        )}
                        {diff.changed.length > 0 && (
                          <View className='diff-group'>
                            <Text className='diff-label changed'>变化设备</Text>
                            {diff.changed.map(({ ip, before, after }) => {
                              const addedPorts = after.openPorts.filter(p => !before.openPorts.find(bp => bp.port === p.port))
                              const removedPorts = before.openPorts.filter(p => !after.openPorts.find(ap => ap.port === p.port))
                              return (
                                <View key={ip} className='diff-row changed'>
                                  <Text className='diff-ip'>{ip}</Text>
                                  <View className='diff-changes'>
                                    {addedPorts.length > 0 && <Text className='port-added'>+{addedPorts.map(p => p.port).join(',')}</Text>}
                                    {removedPorts.length > 0 && <Text className='port-removed'>-{removedPorts.map(p => p.port).join(',')}</Text>}
                                  </View>
                                </View>
                              )
                            })}
                          </View>
                        )}
                        {diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0 && (
                          <Text className='no-changes'>无变化</Text>
                        )}
                      </View>
                    )}

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
