import { Component } from 'react'

interface DeviceCardProps {
  ip: string
  mac?: string
  vendor?: string
  portCount: number
  onClick?: () => void
}

export default class DeviceCard extends Component<DeviceCardProps> {
  render() {
    const { ip, mac, vendor, portCount } = this.props
    return (
      <view className="device-card" onClick={this.props.onClick}>
        <view className="card-icon">
          <text style={{ fontSize: '32px' }}>📱</text>
        </view>
        <view className="card-info">
          <text className="ip">{ip}</text>
          {vendor && <text className="vendor">{vendor}</text>}
          {mac && <text className="mac">{mac}</text>}
          <text className="ports">{portCount} 个开放端口</text>
        </view>
        <view className="card-arrow">
          <text style={{ color: '#666', fontSize: '20px' }}>›</text>
        </view>
      </view>
    )
  }
}