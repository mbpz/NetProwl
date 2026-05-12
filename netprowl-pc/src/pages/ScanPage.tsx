import { ToolStatusBar } from '../components/ToolStatusBar';
import { PipelinePanel } from '../components/PipelinePanel';
import { UnifiedResultsPanel } from '../components/UnifiedResultsPanel';

export function ScanPage() {
  return (
    <div className="p-4 space-y-6">
      <h1 className="text-xl font-bold">Network Scan</h1>
      <ToolStatusBar />
      <PipelinePanel />
      <UnifiedResultsPanel />
    </div>
  );
}
