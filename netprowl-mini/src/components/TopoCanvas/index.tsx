import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import type { Device } from '../../stores/deviceStore'
import './index.css'

interface Props {
  devices: Device[]
  gatewayIP: string
  onDeviceClick: (d: Device) => void
}

export default class TopoCanvas extends Component<Props> {
  componentDidMount() {
    this.render()
  }

  componentDidUpdate() {
    this.render()
  }

  render() {
    const { devices, gatewayIP } = this.props
    if (devices.length === 0) return (
      <View className='topo-empty'>
        <Text className='empty-icon'>🛣</Text>
        <Text className='empty-text'>点击下方按钮开始扫描</Text>
      </View>
    )

    return <canvas id='topo-canvas' className='topo-canvas' onClick={this.handleClick.bind(this)} />
  }

  handleClick(e: any) {
    const { devices, gatewayIP, onDeviceClick } = this.props
    const { x, y } = e.detail
    const w = Taro.getSystemInfoSync().windowWidth
    const h = w * 0.7
    const cx = w / 2, cy = h / 2
    const r = Math.min(w, h) * 0.35
    const gateway = devices.find(d => d.ip === gatewayIP) || devices[0]
    const others = devices.filter(d => d.ip !== gateway?.ip)

    const dx0 = x - cx, dy0 = y - cy
    if (dx0*dx0 + dy0*dy0 < 28*28) { onDeviceClick(gateway); return }

    others.forEach((dev, i) => {
      const angle = (2 * Math.PI * i) / others.length - Math.PI / 2
      const nx = cx + r * Math.cos(angle)
      const ny = cy + r * Math.sin(angle)
      const dx = x - nx, dy = y - ny
      if (dx*dx + dy*dy < 22*22) { onDeviceClick(dev) }
    })
  }

  getIcon(type: Device['deviceType']) {
    return { router: '🛣', pc: '💻', camera: '📹', nas: '💾', phone: '📱', printer: '🖨', unknown: '❓' }[type]
  }
}