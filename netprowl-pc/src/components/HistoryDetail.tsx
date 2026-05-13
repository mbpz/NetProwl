import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useHistoryStore } from '../stores/historyStore';

interface SessionDetail {
  session: { id: number; target: string; started_at: number; result_count: number; has_tls_audit: boolean };
  vulnerabilities: Array<{ host: string; port: number; vuln_id: string; name: string; severity: string }>;
}

const SEV_COLORS: Record<string, string> = { critical: 'border-red-500 bg-red-50', high: 'border-orange-500 bg-orange-50', medium: 'border-yellow-500 bg-yellow-50', low: 'border-blue-500 bg-blue-50' };

export function HistoryDetail({ sessionId }: { sessionId: number }) {
  const { selectSession } = useHistoryStore();
  const [detail, setDetail] = useState<SessionDetail | null>(null);

  useEffect(() => {
    invoke<SessionDetail>('get_session_detail', { sessionId }).then(setDetail).catch(console.error);
  }, [sessionId]);

  const handleExport = async (format: 'json' | 'html') => {
    const data = await invoke<string>('export_session_json', { sessionId });
    if (format === 'json') {
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `netprowl-session-${sessionId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const html = `<!DOCTYPE html><html><head><title>NetProwl Session ${sessionId}</title><style>body{font-family:system-ui;padding:40px}pre{white-space:pre-wrap}</style></head><body><h1>NetProwl Session ${sessionId}</h1><pre>${data}</pre></body></html>`;
      const blob = new Blob([html], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `netprowl-session-${sessionId}.html`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  return (
    <div className="p-3">
      <div className="flex gap-2 mb-3">
        <button onClick={() => handleExport('json')} className="text-xs bg-purple-100 text-purple-800 px-2 py-1 rounded">JSON</button>
        <button onClick={() => handleExport('html')} className="text-xs bg-orange-100 text-orange-800 px-2 py-1 rounded">HTML</button>
      </div>
      <button onClick={() => selectSession(null)} className="text-sm text-blue-600 hover:underline mb-3">← Back</button>
      {detail && (
        <>
          <div className="font-mono font-bold text-lg mb-2">{detail.session.target}</div>
          <div className="text-sm text-gray-600 mb-4">{new Date(detail.session.started_at * 1000).toLocaleString()}</div>
          <div className="space-y-1">
            {detail.vulnerabilities.map((v, i) => (
              <div key={i} className={`border-l-2 px-3 py-2 rounded ${SEV_COLORS[v.severity] || ''}`}>
                <div className="text-sm font-medium">[{v.severity.toUpperCase()}] {v.name}</div>
                <div className="text-xs text-gray-600">{v.host}:{v.port} — {v.vuln_id}</div>
              </div>
            ))}
            {detail.vulnerabilities.length === 0 && <div className="text-gray-400 text-sm">No vulnerabilities found</div>}
          </div>
        </>
      )}
    </div>
  );
}