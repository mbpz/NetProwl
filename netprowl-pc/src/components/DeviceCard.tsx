interface Port {
  port: number
  state: string
  service?: string
  banner?: string
}

interface Device {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  ports: Port[]
  sources: string[]
}

interface DeviceCardProps {
  device: Device
}

export function DeviceCard({ device }: DeviceCardProps) {
  return (
    <div className="device-card">
      <div className="device-header">
        <span className="device-ip">{device.ip}</span>
        <span className="device-vendor">{device.vendor || 'Unknown'}</span>
      </div>
      <div className="device-body">
        {device.hostname && <div>Hostname: {device.hostname}</div>}
        {device.mac && <div>MAC: {device.mac}</div>}
        {device.ports.length > 0 && (
          <div className="ports">
            <span>开放端口: </span>
            {device.ports.map((p) => (
              <span key={p.port} className="port-tag">
                {p.port}/{p.service || 'unknown'}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
