interface Port {
  port: number
  service: string
  state: string
}

interface Device {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  deviceType: string
  os: string
  openPorts: Port[]
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
        <div>Type: {device.deviceType}</div>
        <div>OS: {device.os}</div>
        {device.openPorts.length > 0 && (
          <div className="ports">
            <span>开放端口: </span>
            {device.openPorts.map((p) => (
              <span key={p.port} className="port-tag">
                {p.port}/{p.service}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
