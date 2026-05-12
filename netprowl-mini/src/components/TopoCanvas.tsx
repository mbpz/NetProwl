import { Component } from 'react'

interface Device {
  ip: string
  vendor?: string
  x?: number
  y?: number
}

interface TopoCanvasProps {
  devices: Device[]
  localIP: string
}

export default class TopoCanvas extends Component<TopoCanvasProps> {
  canvas: any

  componentDidUpdate(prevProps: TopoCanvasProps) {
    if (prevProps.devices !== this.props.devices) {
      this.draw()
    }
  }

  draw() {
    // Canvas drawing — stub for mini-program
    console.log('[TopoCanvas] Drawing', this.props.devices.length, 'devices')
  }

  render() {
    return (
      <view className="topo-container">
        <canvas
          type="2d"
          className="topo-canvas"
          onTouchStart={() => {}}
        />
        <view className="topo-legend">
          <view className="legend-item">
            <view className="legend-dot router" />
            <text>路由器</text>
          </view>
          <view className="legend-item">
            <view className="legend-dot device" />
            <text>设备</text>
          </view>
          <view className="legend-item">
            <view className="legend-dot camera" />
            <text>摄像头</text>
          </view>
        </view>
      </view>
    )
  }
}