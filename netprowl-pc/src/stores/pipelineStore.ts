import { create } from 'zustand';
export type ResultType = 'port' | 'service' | 'vuln' | 'fuzz' | 'tls';
export interface PipelineResult { type: ResultType; ip?: string; port?: number; state?: string; service?: string; banner?: string; template?: string; severity?: string; matched?: string; url?: string; method?: string; status?: number; host?: string; cert_cn?: string; message?: string; vulnerabilities?: any[]; }
interface PipelineStore {
  phase: 'idle' | 'scanning' | 'detecting' | 'fuzzing' | 'done';
  results: PipelineResult[];
  target: string;
  selectedTool: 'masscan' | 'nmap' | 'rustscan';
  autoNuclei: boolean; autoFfuf: boolean; autoFeroxbuster: boolean;
  autoTlsAudit: boolean; autoTlsFull: boolean;
  setPhase: (phase: PipelineStore['phase']) => void;
  addResults: (results: PipelineResult[]) => void;
  clearResults: () => void;
  setTarget: (target: string) => void;
  setSelectedTool: (tool: PipelineStore['selectedTool']) => void;
  setAutoNuclei: (v: boolean) => void;
  setAutoFfuf: (v: boolean) => void;
  setAutoFeroxbuster: (v: boolean) => void;
  setAutoTlsAudit: (v: boolean) => void;
  setAutoTlsFull: (v: boolean) => void;
}
export const usePipelineStore = create<PipelineStore>((set) => ({ phase: 'idle', results: [], target: '192.168.1.0/24', selectedTool: 'masscan', autoNuclei: true, autoFfuf: false, autoFeroxbuster: false, autoTlsAudit: false, autoTlsFull: false, setPhase: (phase: PipelineStore['phase']) => set({ phase }), addResults: (results: PipelineResult[]) => set((s) => ({ results: [...s.results, ...results] })), clearResults: () => set({ results: [] }), setTarget: (target: string) => set({ target }), setSelectedTool: (selectedTool: PipelineStore['selectedTool']) => set({ selectedTool }), setAutoNuclei: (autoNuclei: boolean) => set({ autoNuclei }), setAutoFfuf: (autoFfuf: boolean) => set({ autoFfuf }), setAutoFeroxbuster: (autoFeroxbuster: boolean) => set({ autoFeroxbuster }), setAutoTlsAudit: (autoTlsAudit: boolean) => set({ autoTlsAudit }), setAutoTlsFull: (autoTlsFull: boolean) => set({ autoTlsFull }) }));
