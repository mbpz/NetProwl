import { useEffect, useRef, useMemo } from 'react'
import { Device } from '../stores/deviceStore'

interface TopoCanvasProps {
  devices: Device[]
  width: number
  height: number
  layout?: 'grid' | 'topology'
}

// Device colors by type
const DEVICE_COLORS: Record<string, string> = {
  router: '#3b82f6',
  pc: '#10b981',
  camera: '#ef4444',
  nas: '#f59e0b',
  phone: '#8b5cf6',
  printer: '#06b6d4',
  unknown: '#6b7280',
}

const DEVICE_ICONS: Record<string, string> = {
  router: 'R',
  pc: 'P',
  camera: 'C',
  nas: 'N',
  phone: 'M',
  printer: 'L',
  unknown: '?',
}

interface NodePosition {
  device: Device
  x: number
  y: number
  radius: number
  color: string
}

function computeTopologyLayout(devices: Device[], width: number, height: number): NodePosition[] {
  if (devices.length === 0) return []

  const centerX = width / 2
  const centerY = height / 2

  // Find router (gateway) - typically .1 or .254 or has "router" device_type
  let routerIndex = devices.findIndex(d =>
    d.device_type === 'router' ||
    d.ip.endsWith('.1') ||
    d.ip.endsWith('.254')
  )
  if (routerIndex === -1) routerIndex = 0

  const router = devices[routerIndex]
  const otherDevices = devices.filter((_, i) => i !== routerIndex)

  const positions: NodePosition[] = []

  // Center node (router) - larger
  positions.push({
    device: router,
    x: centerX,
    y: centerY,
    radius: 28,
    color: DEVICE_COLORS[router.device_type || 'unknown'],
  })

  // Ring layout for other devices
  const ringCount = 3
  const baseRadius = Math.min(width, height) / 4

  otherDevices.forEach((device, index) => {
    const ring = Math.floor(index / 8) + 1
    const ringRadius = baseRadius * ring
    const angleInRing = (index % 8) * (Math.PI * 2 / 8)

    const x = centerX + ringRadius * Math.cos(angleInRing)
    const y = centerY + ringRadius * Math.sin(angleInRing)

    positions.push({
      device,
      x,
      y,
      radius: 22,
      color: DEVICE_COLORS[device.device_type || 'unknown'],
    })
  })

  return positions
}

function computeGridLayout(devices: Device[], width: number, height: number): NodePosition[] {
  if (devices.length === 0) return []

  const cols = Math.ceil(Math.sqrt(devices.length))
  const cellWidth = width / cols
  const cellHeight = height / Math.ceil(devices.length / cols)

  return devices.map((device, index) => {
    const col = index % cols
    const row = Math.floor(index / cols)
    return {
      device,
      x: col * cellWidth + cellWidth / 2,
      y: row * cellHeight + cellHeight / 2,
      radius: 22,
      color: DEVICE_COLORS[device.device_type || 'unknown'],
    }
  })
}

export function TopoCanvas({ devices, width, height, layout = 'grid' }: TopoCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  const positions = useMemo(() => {
    return layout === 'topology'
      ? computeTopologyLayout(devices, width, height)
      : computeGridLayout(devices, width, height)
  }, [devices, width, height, layout])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Clear canvas
    ctx.clearRect(0, 0, width, height)

    // Draw background grid for topology mode
    if (layout === 'topology') {
      ctx.strokeStyle = '#f0f0f0'
      ctx.lineWidth = 1
      const gridSize = 40
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

      // Draw concentric circles
      const centerX = width / 2
      const centerY = height / 2
      const maxRadius = Math.min(width, height) / 2 - 50
      ctx.strokeStyle = '#e0e0e0'
      ctx.setLineDash([5, 5])
      for (let r = 1; r <= 3; r++) {
        ctx.beginPath()
        ctx.arc(centerX, centerY, maxRadius * (r / 3), 0, Math.PI * 2)
        ctx.stroke()
      }
      ctx.setLineDash([])
    }

    if (positions.length === 0) return

    // Draw connection lines from center to each node (topology mode only)
    if (layout === 'topology' && positions.length > 1) {
      const center = positions[0]
      ctx.strokeStyle = '#94a3b8'
      ctx.lineWidth = 1.5
      for (let i = 1; i < positions.length; i++) {
        ctx.beginPath()
        ctx.moveTo(center.x, center.y)
        ctx.lineTo(positions[i].x, positions[i].y)
        ctx.stroke()
      }
    }

    // Draw device nodes
    positions.forEach((pos) => {
      const { device, x, y, radius, color } = pos

      // Draw circle background
      ctx.fillStyle = color
      ctx.beginPath()
      ctx.arc(x, y, radius, 0, Math.PI * 2)
      ctx.fill()

      // Draw border
      ctx.strokeStyle = '#fff'
      ctx.lineWidth = 2
      ctx.stroke()

      // Draw icon/text in center
      const icon = DEVICE_ICONS[device.device_type || 'unknown'] || '?'
      ctx.fillStyle = '#fff'
      ctx.font = `bold ${radius * 0.8}px sans-serif`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(icon, x, y)

      // Draw IP label below
      ctx.fillStyle = '#374151'
      ctx.font = '11px sans-serif'
      ctx.fillText(device.ip, x, y + radius + 12)
    })
  }, [positions, width, height, layout])

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      style={{ border: '1px solid #e5e7eb', borderRadius: '8px', background: '#fff' }}
    />
  )
}
