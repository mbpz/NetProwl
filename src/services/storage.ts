import Taro from '@tarojs/taro'
import { ScanSnapshot } from '../types'

const STORAGE_KEY = 'netprowl_scan_history'
const MAX_RECORDS = 50

export async function loadHistory(): Promise<ScanSnapshot[]> {
  try {
    const raw = Taro.getStorageSync(STORAGE_KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export async function saveSnapshot(snapshot: ScanSnapshot): Promise<void> {
  const history = await loadHistory()
  history.unshift(snapshot)

  // Trim to max records
  while (history.length > MAX_RECORDS) {
    history.pop()
  }

  // Check size, trim oldest 3 if over 10MB
  const data = JSON.stringify(history)
  if (data.length > 10 * 1024 * 1024) {
    history.splice(0, 3)
  }

  Taro.setStorageSync(STORAGE_KEY, JSON.stringify(history))
}

export async function clearHistory(): Promise<void> {
  Taro.removeStorageSync(STORAGE_KEY)
}
