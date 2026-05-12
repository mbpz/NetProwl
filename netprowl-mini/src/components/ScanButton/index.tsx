import { Component } from 'react'
import { View, Button, Text } from '@tarojs/components'
import './index.css'

interface Props {
  scanning: boolean
  onScan: () => void
}

export default class ScanButton extends Component<Props> {
  render() {
    return (
      <View className='scan-btn-wrap'>
        <Button className={`scan-btn ${this.props.scanning ? 'scanning' : ''}`} onClick={this.props.onScan} disabled={this.props.scanning}>
          {this.props.scanning ? '⏳ 扫描中...' : '🔍 开始扫描'}
        </Button>
      </View>
    )
  }
}