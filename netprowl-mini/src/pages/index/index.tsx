import { Component } from 'react'
import ScanButton from '../../components/ScanButton'
import TopoCanvas from '../../components/TopoCanvas'
import DeviceCard from '../../components/DeviceCard'
import { scanner } from '../../services/scanner'

interface Device {
  ip: string
  mac?: string
  vendor?: string
  ports: number[]
  sources: string[]
}

export default class Index extends Component {
  state = {
    status: 'idle' as 'idle' | 'scanning' | 'done' | 'error',
    devices: [] as Device[],
  }

  handleScan = async () => {
    this.setState({ status: 'scanning' })
    try {
      const devices = await scanner.startScan({ subnet: '192.168.1.0/24' })
      this.setState({ devices, status: 'done' })
    } catch (e) {
      this.setState({ status: 'error' })
    }
  }

  render() {
    const { status, devices } = this.state
    return (
      <view className="container">
        <view className="header">
          <text className="title">NetProwl</text>
          <text className="subtitle">局域网安全扫描</text>
        </view>
        <ScanButton
          status={status}
          deviceCount={devices.length}
          onClick={this.handleScan}
        />
        {devices.length > 0 && (
          <view className="device-list">
            <text className="section-title">发现的设备</text>
            {devices.map(d => (
              <DeviceCard
                key={d.ip}
                ip={d.ip}
                mac={d.mac}
                vendor={d.vendor}
                portCount={d.ports.length}
              />
            ))}
          </view>
        )}
      </view>
    )
  }
}