import { DeviceType } from '../../types'

interface IconProps {
  type: DeviceType
  size?: number
}

const ICON_MAP: Record<DeviceType, string> = {
  router: '🛣',
  pc: '💻',
  camera: '📹',
  nas: '💾',
  phone: '📱',
  printer: '🖨',
  unknown: '❓',
}

export function DeviceIcon({ type, size = 32 }: IconProps) {
  return (
    <span style={{ fontSize: size }}>
      {ICON_MAP[type]}
    </span>
  )
}
