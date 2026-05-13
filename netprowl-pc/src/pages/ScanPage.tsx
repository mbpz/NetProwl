import { ToolStatusBar } from '../components/ToolStatusBar';
import { PipelinePanel } from '../components/PipelinePanel';
import { UnifiedResultsPanel } from '../components/UnifiedResultsPanel';
import { TLSResultPanel } from '../components/TLSResultPanel';
import { HistoryDrawer } from '../components/HistoryDrawer';

export function ScanPage() {
  return (
    <div className="p-4 space-y-6">
      <h1 className="text-xl font-bold">Network Scan</h1>
      <ToolStatusBar />
      <PipelinePanel />
      <UnifiedResultsPanel />
      <TLSResultPanel />
      <HistoryDrawer />
    </div>
  );
}
