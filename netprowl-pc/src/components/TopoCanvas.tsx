import { useEffect, useRef } from 'react'

interface Device {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  ports: { port: number; state: string; service?: string; banner?: string }[]
  sources: string[]
  deviceType?: string
}

interface TopoCanvasProps {
  devices: Device[]
  width: number
  height: number
}

const DEVICE_ICONS: Record<string, string> = {
  router: '🖧',
  pc: '💻',
  camera: '📷',
  nas: '💾',
  phone: '📱',
  printer: '🖨️',
  unknown: '❓',
}

export function TopoCanvas({ devices, width, height }: TopoCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Clear canvas
    ctx.clearRect(0, 0, width, height)

    if (devices.length === 0) return

    // Draw devices in a grid layout
    const cols = Math.ceil(Math.sqrt(devices.length))
    const cellWidth = width / cols
    const cellHeight = height / Math.ceil(devices.length / cols)

    devices.forEach((device, index) => {
      const col = index % cols
      const row = Math.floor(index / cols)
      const x = col * cellWidth + cellWidth / 2
      const y = row * cellHeight + cellHeight / 2

      // Draw device icon
      const icon = DEVICE_ICONS[device.deviceType] || DEVICE_ICONS.unknown
      ctx.font = '24px sans-serif'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(icon, x, y - 10)

      // Draw IP label
      ctx.font = '12px sans-serif'
      ctx.fillText(device.ip, x, y + 15)
    })

    // Draw lines between devices (simplified - connect to first device as "gateway")
    if (devices.length > 1) {
      ctx.strokeStyle = '#ccc'
      ctx.beginPath()
      for (let i = 1; i < devices.length; i++) {
        const col = i % cols
        const row = Math.floor(i / cols)
        const x = col * cellWidth + cellWidth / 2
        const y = row * cellHeight + cellHeight / 2
        ctx.moveTo(cellWidth / 2, cellHeight / 2)
        ctx.lineTo(x, y)
      }
      ctx.stroke()
    }
  }, [devices, width, height])

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      style={{ border: '1px solid #ccc' }}
    />
  )
}