import { usePipelineStore } from '../stores/pipelineStore';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'border-red-500 bg-red-50',
  high: 'border-orange-500 bg-orange-50',
  medium: 'border-yellow-500 bg-yellow-50',
  low: 'border-blue-500 bg-blue-50',
};

export function TLSResultPanel() {
  const { results } = usePipelineStore();
  const tlsResults = results.filter(r => (r as any).type === 'tls');

  if (tlsResults.length === 0) return null;

  return (
    <div className="mt-4">
      <h3 className="text-lg font-bold mb-2">TLS Audit Results</h3>
      {tlsResults.map((r: any, i: number) => (
        <div key={i} className={`border-l-4 p-3 mb-2 rounded ${SEVERITY_COLORS[r.severity as keyof typeof SEVERITY_COLORS] || ''}`}>
          <div className="font-mono text-sm">{r.host}:{r.port} — {r.severity?.toUpperCase()}</div>
          <div className="text-sm mt-1">{r.message}</div>
          {r.cert_cn && <div className="text-xs text-gray-600 mt-1">CN: {r.cert_cn}</div>}
        </div>
      ))}
    </div>
  );
}