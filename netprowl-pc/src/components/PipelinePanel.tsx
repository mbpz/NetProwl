import { invoke } from '@tauri-apps/api/core';
import { usePipelineStore } from '../stores/pipelineStore';
export function PipelinePanel() {
  const { phase, target, selectedTool, autoNuclei, setPhase, setTarget, setSelectedTool, setAutoNuclei, addResults, clearResults } = usePipelineStore();
  const start = async () => {
    clearResults();
    setPhase('scanning');
    try {
      const results = await invoke('run_pipeline', { opts: { target, scan_tool: selectedTool, auto_nuclei: autoNuclei, auto_ffuf: false, auto_feroxbuster: false } });
      addResults(results as any);
      setPhase('done');
    } catch { setPhase('idle'); }
  };
  return (
    <div className="flex gap-4 items-center">
      <input
        type="text"
        value={target}
        onChange={e => setTarget(e.target.value)}
        placeholder="192.168.1.0/24"
        className="border rounded px-2 py-1"
      />
      <select value={selectedTool} onChange={e => setSelectedTool(e.target.value as any)} className="border rounded px-2 py-1">
        <option value="masscan">masscan (fast)</option><option value="rustscan">rustscan (fast)</option><option value="nmap">nmap (banner)</option>
      </select>
      <label className="flex items-center gap-1"><input type="checkbox" checked={autoNuclei} onChange={e => setAutoNuclei(e.target.checked)} /> nuclei</label>
      <button onClick={start} disabled={phase !== 'idle'} className="bg-blue-600 text-white px-4 py-1 rounded disabled:opacity-50">
        {phase === 'idle' ? 'Start Scan' : phase}
      </button>
    </div>
  );
}
