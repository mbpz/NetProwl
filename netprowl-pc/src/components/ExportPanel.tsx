import { PrintReport } from './PrintReport';

interface PipelineResult {
  type: 'port' | 'service' | 'vuln' | 'fuzz' | 'tls';
  host?: string;
  ip?: string;
  port?: number;
  severity?: string;
  name?: string;
  template?: string;
  matched?: string;
  [key: string]: any;
}

export function ExportPanel({ results }: { results: PipelineResult[] }) {
  const vulns = results.filter(r => r.type === 'vuln' || r.type === 'tls');

  const printExport = () => {
    window.print();
  };

  return (
    <div>
      {results.length > 0 && <PrintReport results={results} />}
      <div className="flex gap-2 mt-4">
        <button
          onClick={printExport}
          className="text-sm bg-blue-100 text-blue-800 px-3 py-1 rounded hover:bg-blue-200"
        >
          PDF (Quick)
        </button>
        <span className="text-xs text-gray-400 self-center ml-2">
          {results.length} results
        </span>
      </div>
    </div>
  );
}