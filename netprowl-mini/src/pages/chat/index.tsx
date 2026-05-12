import { Component } from 'react'
import { View, Text } from '@tarojs/components'

export default class Chat extends Component {
  render() {
    return (
      <View className='chat-page'>
        <View className='placeholder'>
          <Text className='placeholder-icon'>🤖</Text>
          <Text className='placeholder-text'>AI 问诊</Text>
          <Text className='placeholder-hint'>Phase 2 接入 DeepSeek</Text>
        </View>
      </View>
    )
  }
}
