// Storage service — scan history persistence
import { ScanSnapshot } from '../types'

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
