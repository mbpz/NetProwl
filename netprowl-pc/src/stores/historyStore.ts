import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';

export interface ScanSession {
  id: number;
  target: string;
  started_at: number;
  finished_at?: number;
  result_count: number;
  has_tls_audit: boolean;
}

interface HistoryStore {
  sessions: ScanSession[];
  selectedSession: number | null;
  open: boolean;
  setOpen: (v: boolean) => void;
  loadHistory: () => Promise<void>;
  selectSession: (id: number | null) => void;
  deleteSession: (id: number) => Promise<void>;
  clearAll: () => Promise<void>;
}

export const useHistoryStore = create<HistoryStore>((set) => ({
  sessions: [],
  selectedSession: null,
  open: false,
  setOpen: (open) => set({ open }),
  loadHistory: async () => {
    const sessions = await invoke<ScanSession[]>('get_scan_history', { limit: 50 });
    set({ sessions });
  },
  selectSession: (id) => set({ selectedSession: id }),
  deleteSession: async (id) => {
    await invoke('delete_scan_session', { sessionId: id });
    set((s: HistoryStore) => ({ sessions: s.sessions.filter((x: ScanSession) => x.id !== id), selectedSession: null }));
  },
  clearAll: async () => {
    await invoke('clear_scan_history');
    set({ sessions: [], selectedSession: null });
  },
}));