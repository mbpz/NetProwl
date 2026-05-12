import { Component } from 'react'
import { Device, DeviceType } from '../types'

const DEVICE_ICONS: Record<DeviceType, string> = {
  router: '🔰',
  pc: '💻',
  camera: '📹',
  nas: '💾',
  phone: '📱',
  printer: '🖨️',
  unknown: '📟',
}

const DEVICE_COLORS: Record<DeviceType, string> = {
  router: '#3b82f6',
  pc: '#10b981',
  camera: '#ef4444',
  nas: '#f59e0b',
  phone: '#8b5cf6',
  printer: '#06b6d4',
  unknown: '#6b7280',
}

interface TopoCanvasProps {
  devices: Device[]
  localIP?: string
  onDeviceClick?: (device: Device) => void
}

interface LayoutNode {
  device: Device
  x: number
  y: number
}

export default class TopoCanvas extends Component<TopoCanvasProps> {
  canvas: any
  ctx: any
  nodes: LayoutNode[] = []

  componentDidMount() {
    this.draw()
  }

  componentDidUpdate(prevProps: TopoCanvasProps) {
    if (prevProps.devices !== this.props.devices || prevProps.localIP !== this.props.localIP) {
      this.draw()
    }
  }

  computeLayout(devices: Device[], canvasWidth: number, canvasHeight: number): LayoutNode[] {
    if (!devices || devices.length === 0) return []

    const centerX = canvasWidth / 2
    const centerY = canvasHeight / 2
    const nodes: LayoutNode[] = []

    // Find router (gateway) - typically .1 or .254
    const router = devices.find(d => d.deviceType === 'router' || d.ip.endsWith('.1') || d.ip.endsWith('.254'))
    const otherDevices = devices.filter(d => d !== router)
    const radiusStep = Math.min(canvasWidth, canvasHeight) / 2.5 / 3

    // Center node: router
    if (router) {
      nodes.push({ device: router, x: centerX, y: centerY })
    } else if (devices.length > 0) {
      // Use first device as center if no router found
      nodes.push({ device: devices[0], x: centerX, y: centerY })
    }

    // Arrange other devices in concentric circles
    const step = Math.max(1, Math.floor(otherDevices.length / 3))
    let ring = 1
    let angle = 0
    const angleStep = (2 * Math.PI) / Math.max(otherDevices.length, 1)

    otherDevices.forEach((device, idx) => {
      const ringRadius = ring * radiusStep
      const x = centerX + ringRadius * Math.cos(angle)
      const y = centerY + ringRadius * Math.sin(angle)
      nodes.push({ device, x, y })
      angle += angleStep
      if ((idx + 1) % step === 0 && ring < 3) {
        ring++
      }
    })

    return nodes
  }

  draw() {
    const { devices } = this.props
    if (!this.canvas) return

    this.ctx = this.canvas.getContext('2d')
    const dpr = wx.getSystemInfoSync().pixelRatio || 2
    const canvasWidth = this.canvas.width / dpr
    const canvasHeight = this.canvas.height / dpr

    this.ctx.clearRect(0, 0, canvasWidth, canvasHeight)

    // Draw grid background
    this.drawGrid(canvasWidth, canvasHeight)

    // Compute layout
    this.nodes = this.computeLayout(devices, canvasWidth, canvasHeight)
    if (this.nodes.length === 0) {
      this.drawEmptyState(canvasWidth, canvasHeight)
      return
    }

    // Find center node (router or first device)
    const centerNode = this.nodes.find(n => n.device.deviceType === 'router') || this.nodes[0]
    const otherNodes = this.nodes.filter(n => n !== centerNode)

    // Draw connection lines from center to all devices
    otherNodes.forEach(node => {
      this.drawConnection(centerNode.x, centerNode.y, node.x, node.y)
    })

    // Draw all nodes
    this.nodes.forEach(node => {
      const isCenter = node === centerNode
      this.drawNode(node, isCenter)
    })
  }

  drawGrid(width: number, height: number) {
    const ctx = this.ctx
    ctx.strokeStyle = 'rgba(255,255,255,0.05)'
    ctx.lineWidth = 1
    const gridSize = 30
    for (let x = 0; x < width; x += gridSize) {
      ctx.beginPath()
      ctx.moveTo(x, 0)
      ctx.lineTo(x, height)
      ctx.stroke()
    }
    for (let y = 0; y < height; y += gridSize) {
      ctx.beginPath()
      ctx.moveTo(0, y)
      ctx.lineTo(width, y)
      ctx.stroke()
    }
  }

  drawConnection(x1: number, y1: number, x2: number, y2: number) {
    const ctx = this.ctx
    ctx.strokeStyle = 'rgba(99,179,237,0.3)'
    ctx.lineWidth = 2
    ctx.setLineDash([5, 3])
    ctx.beginPath()
    ctx.moveTo(x1, y1)
    ctx.lineTo(x2, y2)
    ctx.stroke()
    ctx.setLineDash([])
  }

  drawNode(node: LayoutNode, isCenter: boolean) {
    const ctx = this.ctx
    const { device, x, y } = node
    const radius = isCenter ? 28 : 22
    const color = DEVICE_COLORS[device.deviceType] || DEVICE_COLORS.unknown

    // Draw glow for center
    if (isCenter) {
      ctx.shadowColor = color
      ctx.shadowBlur = 20
    }

    // Draw circle background
    ctx.fillStyle = color
    ctx.beginPath()
    ctx.arc(x, y, radius, 0, 2 * Math.PI)
    ctx.fill()

    // Draw white border
    ctx.strokeStyle = 'rgba(255,255,255,0.8)'
    ctx.lineWidth = 2
    ctx.stroke()

    ctx.shadowBlur = 0

    // Draw icon text (emoji)
    const icon = DEVICE_ICONS[device.deviceType] || DEVICE_ICONS.unknown
    ctx.font = `${isCenter ? 20 : 16}px Arial`
    ctx.textAlign = 'center'
    ctx.textBaseline = 'middle'
    ctx.fillStyle = '#fff'
    ctx.fillText(icon, x, y)

    // Draw IP label below node
    ctx.font = '10px Arial'
    ctx.fillStyle = 'rgba(255,255,255,0.7)'
    ctx.textBaseline = 'top'
    const label = device.ip.split('.').slice(-1)[0] + '.' + device.ip.split('.')[3]
    ctx.fillText(device.ip, x, y + radius + 4)

    // Draw vendor if available
    if (device.vendor) {
      ctx.font = '9px Arial'
      ctx.fillStyle = 'rgba(255,255,255,0.5)'
      const shortVendor = device.vendor.length > 10 ? device.vendor.substring(0, 10) + '..' : device.vendor
      ctx.fillText(shortVendor, x, y + radius + 16)
    }
  }

  drawEmptyState(width: number, height: number) {
    const ctx = this.ctx
    ctx.font = '14px Arial'
    ctx.fillStyle = 'rgba(255,255,255,0.4)'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'middle'
    ctx.fillText('点击"开始扫描"发现局域网设备', width / 2, height / 2)
  }

  handleCanvasTap(e: any) {
    if (!this.nodes || this.nodes.length === 0) return
    const { x, y } = e.detail || e
    // Simple tap detection - find closest node within radius
    for (const node of this.nodes) {
      const dx = node.x - x
      const dy = node.y - y
      const dist = Math.sqrt(dx * dx + dy * dy)
      if (dist < 30) {
        this.props.onDeviceClick?.(node.device)
        return
      }
    }
  }

  render() {
    return (
      <view className="topo-container">
        <canvas
          type="2d"
          className="topo-canvas"
          style={{ width: '100%', height: '280px' }}
          onTap={this.handleCanvasTap}
        />
        <view className="topo-legend">
          <view className="legend-item">
            <view className="legend-dot" style={{ background: '#3b82f6' }} />
            <text>路由器</text>
          </view>
          <view className="legend-item">
            <view className="legend-dot" style={{ background: '#10b981' }} />
            <text>PC</text>
          </view>
          <view className="legend-item">
            <view className="legend-dot" style={{ background: '#ef4444' }} />
            <text>摄像头</text>
          </view>
          <view className="legend-item">
            <view className="legend-dot" style={{ background: '#f59e0b' }} />
            <text>NAS</text>
          </view>
          <view className="legend-item">
            <view className="legend-dot" style={{ background: '#6b7280' }} />
            <text>其他</text>
          </view>
        </view>
      </view>
    )
  }
}