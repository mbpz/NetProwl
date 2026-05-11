import { Component } from 'react'
import { View, Button } from '@tarojs/components'

interface Props {
  scanning: boolean
  onScan: () => void
}

export default class ScanButton extends Component<Props> {
  render() {
    const { scanning, onScan } = this.props
    return (
      <View className='scan-button-wrap'>
        <Button
          className={`scan-btn ${scanning ? 'scanning' : ''}`}
          onClick={onScan}
          disabled={scanning}
        >
          {scanning ? '⏳ 扫描中...' : '🔍 开始扫描'}
        </Button>
      </View>
    )
  }
}
