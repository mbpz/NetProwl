import { usePipelineStore, type PipelineResult, type ResultType } from '../stores/pipelineStore';
const TAG_COLORS: Record<ResultType, string> = { port: 'bg-blue-100 text-blue-800', service: 'bg-green-100 text-green-800', vuln: 'bg-red-100 text-red-800', fuzz: 'bg-yellow-100 text-yellow-800', tls: 'bg-purple-100 text-purple-800' };
export function UnifiedResultsPanel() {
  const { results } = usePipelineStore();
  return (
    <div>
      <div className="flex gap-2 mb-4">
        {(['port', 'service', 'vuln', 'fuzz', 'tls'] as ResultType[]).map(t => (
          <span key={t} className={`px-2 py-1 rounded text-xs ${TAG_COLORS[t]}`}>{t}: {results.filter(r => r.type === t).length}</span>
        ))}
      </div>
      <div className="space-y-1">
        {results.map((r, i) => (
          <div key={i} className={`px-3 py-2 rounded border-l-2 ${TAG_COLORS[r.type]}`}>
            {r.type === 'port' && <span>Port {r.port} {r.state} ({r.ip})</span>}
            {r.type === 'vuln' && <span>[{r.severity}] {r.template} → {r.matched}</span>}
            {r.type === 'fuzz' && <span>{r.method} {r.url} → {r.status}</span>}
            {r.type === 'tls' && <span>[{r.severity}] {r.host}:{r.port} - {r.message}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}
