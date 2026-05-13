import { useHistoryStore } from '../stores/historyStore';

export function HistoryListItem({ session }: { session: { id: number; target: string; started_at: number; result_count: number; has_tls_audit: boolean } }) {
  const { selectSession, deleteSession } = useHistoryStore();
  const date = new Date(session.started_at * 1000).toLocaleString();

  return (
    <div className="border rounded p-3 hover:bg-gray-50 cursor-pointer" onClick={() => selectSession(session.id)}>
      <div className="flex justify-between items-start">
        <div>
          <div className="font-mono text-sm font-medium">{session.target}</div>
          <div className="text-xs text-gray-500 mt-1">{date}</div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">{session.result_count}</span>
          {session.has_tls_audit && <span className="text-xs bg-yellow-100 text-yellow-800 px-1 py-0.5 rounded">TLS</span>}
          <button onClick={(e) => { e.stopPropagation(); deleteSession(session.id); }} className="text-red-400 hover:text-red-600 text-xs">✕</button>
        </div>
      </div>
    </div>
  );
}