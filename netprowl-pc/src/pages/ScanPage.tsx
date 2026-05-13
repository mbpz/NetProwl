import { ToolStatusBar } from '../components/ToolStatusBar';
import { PipelinePanel } from '../components/PipelinePanel';
import { UnifiedResultsPanel } from '../components/UnifiedResultsPanel';
import { ExportPanel } from '../components/ExportPanel';
import { TLSResultPanel } from '../components/TLSResultPanel';
import { HistoryDrawer } from '../components/HistoryDrawer';
import { usePipelineStore } from '../stores/pipelineStore';

export function ScanPage() {
  const results = usePipelineStore((s) => s.results);
  return (
    <div className="p-4 space-y-6">
      <h1 className="text-xl font-bold">Network Scan</h1>
      <ToolStatusBar />
      <PipelinePanel />
      <UnifiedResultsPanel />
      {results.length > 0 && <ExportPanel results={results} />}
      <TLSResultPanel />
      <HistoryDrawer />
    </div>
  );
}
