import { invoke } from '@tauri-apps/api/core';
import { useState } from 'react';
import { usePipelineStore } from '../stores/pipelineStore';
import { useHistoryStore } from '../stores/historyStore';
export function PipelinePanel() {
  const { phase, target, selectedTool, autoNuclei, autoTlsAudit, autoTlsFull, setPhase, setTarget, setSelectedTool, setAutoNuclei, setAutoTlsAudit, setAutoTlsFull, addResults, clearResults } = usePipelineStore();
  const [portRange, setPortRange] = useState('1-1000');
  const [rate, setRate] = useState(1000);
  const [wordlist, setWordlist] = useState('');
  const start = async () => {
    clearResults();
    setPhase('scanning');
    try {
      const results = await invoke('start_pipeline', { opts: { target, scan_tool: selectedTool, auto_nuclei: autoNuclei, auto_ffuf: false, auto_feroxbuster: false, auto_tls_audit: autoTlsAudit, auto_tls_full: autoTlsFull, port_range: portRange, rate, wordlist: wordlist || null }});
      addResults(results as any);
      setPhase('done');
    } catch { setPhase('idle'); }
  };
  const cancel = async () => {
    await invoke('cancel_scan');
    setPhase('idle');
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
      <input type="text" value={portRange} onChange={e => setPortRange(e.target.value)} placeholder="1-1000" className="border rounded px-2 py-1 w-32" />
      {selectedTool === 'masscan' && <input type="number" value={rate} onChange={e => setRate(Number(e.target.value))} placeholder="rate" className="border rounded px-2 py-1 w-24" />}
      <label className="flex items-center gap-1"><input type="checkbox" checked={autoNuclei} onChange={e => setAutoNuclei(e.target.checked)} /> nuclei</label>
      <label className="flex items-center gap-1"><input type="checkbox" checked={autoTlsAudit} onChange={e => setAutoTlsAudit(e.target.checked)} /> TLS Audit</label>
      <label className={autoTlsFull && !autoTlsAudit ? "opacity-50" : ""}><input type="checkbox" checked={autoTlsFull} onChange={e => setAutoTlsFull(e.target.checked)} disabled={!autoTlsAudit} /> + testssl.sh</label>
      <input type="text" value={wordlist} onChange={e => setWordlist(e.target.value)} placeholder="wordlist (optional)" className="border rounded px-2 py-1 w-48" />
      <button onClick={start} disabled={phase !== 'idle'} className="bg-blue-600 text-white px-4 py-1 rounded disabled:opacity-50">
        {phase === 'idle' ? 'Start Scan' : phase}
      </button>
      {phase !== 'idle' && <button onClick={cancel} className="bg-red-600 text-white px-4 py-1 rounded">Cancel</button>}
      <button onClick={() => useHistoryStore.getState().setOpen(true)} className="bg-gray-200 text-gray-700 px-4 py-1 rounded">History</button>
    </div>
  );
}
