import type { ScanSnapshot } from '../stores/deviceStore'

const KEY = 'netprowl_scan_history'
const MAX = 50

export function loadHistory(): ScanSnapshot[] {
  try {
    const raw = wx.getStorageSync(KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export function saveSnapshot(snap: ScanSnapshot): void {
  const history = loadHistory()
  history.unshift(snap)
  while (history.length > MAX) history.pop()
  const data = JSON.stringify(history)
  if (data.length > 10 * 1024 * 1024) history.splice(0, 3)
  wx.setStorageSync(KEY, JSON.stringify(history))
}

export function clearHistory(): void {
  wx.removeStorageSync(KEY)
}
