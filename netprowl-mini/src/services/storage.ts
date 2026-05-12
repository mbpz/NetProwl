// Storage service — scan history persistence
import type { ScanSnapshot, Device } from '../types'

const STORAGE_KEY = 'netprowl_scan_history'
const MAX_RECORDS = 50

export async function loadHistory(): Promise<ScanSnapshot[]> {
  try {
    const raw = wx.getStorageSync(STORAGE_KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export async function saveSnapshot(snapshot: ScanSnapshot): Promise<void> {
  const history = await loadHistory()
  history.unshift(snapshot)
  while (history.length > MAX_RECORDS) {
    history.pop()
  }
  const data = JSON.stringify(history)
  if (data.length > 10 * 1024 * 1024) {
    history.splice(0, 3)
  }
  wx.setStorageSync(STORAGE_KEY, JSON.stringify(history))
}

export interface SnapshotDiff {
  added: Device[]
  removed: Device[]
  changed: Array<{ ip: string, before: Device, after: Device }>
}

// Compare two snapshots
export function compareSnapshots(before: ScanSnapshot, after: ScanSnapshot): SnapshotDiff {
  const beforeMap = new Map(before.devices.map(d => [d.ip, d]))
  const afterMap = new Map(after.devices.map(d => [d.ip, d]))

  const added: Device[] = []
  const removed: Device[] = []
  const changed: Array<{ ip: string, before: Device, after: Device }> = []

  for (const [ip, afterDevice] of afterMap) {
    const beforeDevice = beforeMap.get(ip)
    if (!beforeDevice) {
      added.push(afterDevice)
    } else {
      // Check if ports changed
      const beforePorts = new Set(beforeDevice.openPorts.map(p => p.port))
      const afterPorts = new Set(afterDevice.openPorts.map(p => p.port))
      const portsChanged =
        beforeDevice.openPorts.length !== afterDevice.openPorts.length ||
        [...afterPorts].some(p => !beforePorts.has(p)) ||
        [...beforePorts].some(p => !afterPorts.has(p))

      if (portsChanged || beforeDevice.deviceType !== afterDevice.deviceType) {
        changed.push({ ip, before: beforeDevice, after: afterDevice })
      }
    }
  }

  for (const [ip, beforeDevice] of beforeMap) {
    if (!afterMap.has(ip)) {
      removed.push(beforeDevice)
    }
  }

  return { added, removed, changed }
}
