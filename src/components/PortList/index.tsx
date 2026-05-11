import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { Port } from '../../types'

interface Props {
  ports: Port[]
}

export default class PortList extends Component<Props> {
  render() {
    const { ports } = this.props
    if (ports.length === 0) {
      return <Text className='port-empty'>暂未发现开放端口</Text>
    }
    return (
      <View className='port-list'>
        {ports.map((p) => (
          <View className='port-item' key={p.port}>
            <Text className='port-num'>{p.port}</Text>
            <Text className='port-service'>{p.service || 'unknown'}</Text>
          </View>
        ))}
      </View>
    )
  }
}