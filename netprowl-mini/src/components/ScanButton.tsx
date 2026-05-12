import { Component } from 'react'

interface ScanButtonProps {
  status: 'idle' | 'scanning' | 'done' | 'error'
  deviceCount: number
  onClick: () => void
}

export default class ScanButton extends Component<ScanButtonProps> {
  getLabel() {
    switch (this.props.status) {
      case 'scanning': return '扫描中...'
      case 'done': return '重新扫描'
      case 'error': return '重试'
      default: return '开始扫描'
    }
  }

  getIcon() {
    switch (this.props.status) {
      case 'scanning': return '⏳'
      case 'done': return '✓'
      case 'error': return '⚠'
      default: return '🔍'
    }
  }

  render() {
    const { status, deviceCount } = this.props
    const isScanning = status === 'scanning'

    return (
      <view className="scan-button-container">
        <button
          className={`scan-btn ${status}`}
          onClick={this.props.onClick}
          disabled={isScanning}
        >
          <text className="btn-icon">{this.getIcon()}</text>
          <text className="btn-label">{this.getLabel()}</text>
        </button>
        {deviceCount > 0 && (
          <text className="device-count">发现 {deviceCount} 台设备</text>
        )}
      </view>
    )
  }
}