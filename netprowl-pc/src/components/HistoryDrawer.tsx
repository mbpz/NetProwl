import { useEffect } from 'react';
import { useHistoryStore } from '../stores/historyStore';
import { HistoryListItem } from './HistoryListItem';
import { HistoryDetail } from './HistoryDetail';

export function HistoryDrawer() {
  const { open, setOpen, loadHistory, selectedSession } = useHistoryStore();

  useEffect(() => { if (open) loadHistory(); }, [open]);

  return (
    <div className={`fixed right-0 top-0 h-full w-[400px] bg-white shadow-xl transform transition-transform z-50 ${open ? 'translate-x-0' : 'translate-x-full'}`}>
      <div className="flex items-center justify-between p-4 border-b">
        <h2 className="font-bold">Scan History</h2>
        <div className="flex gap-2">
          <button onClick={() => useHistoryStore.getState().clearAll()} className="text-xs text-red-500 hover:text-red-700">Clear All</button>
          <button onClick={() => setOpen(false)} className="text-gray-500 hover:text-gray-700">✕</button>
        </div>
      </div>
      <div className="overflow-y-auto h-full pb-20">
        {selectedSession ? (
          <HistoryDetail sessionId={selectedSession} />
        ) : (
          <div className="p-2 space-y-1">
            {useHistoryStore.getState().sessions.map((s) => (
              <HistoryListItem key={s.id} session={s} />
            ))}
            {useHistoryStore.getState().sessions.length === 0 && (
              <div className="text-center text-gray-400 mt-8">No scan history</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}