import { invoke } from '@tauri-apps/api/core';
import { useState } from 'react';

interface RiskInfo {
  ip: string;
  port?: number;
  risk_type: string;
  title: string;
  description: string;
  severity: string;
}

interface DeviceInfo {
  ip: string;
  hostname?: string;
  device_type: string;
  open_ports: number[];
  services: string[];
}

interface DiagnosisReport {
  summary: string;
  critical_issues: { ip: string; title: string; description: string; severity: string }[];
  medium_issues: { ip: string; title: string; description: string; severity: string }[];
  recommendations: string[];
}

interface AttackNode {
  id: string;
  finding_id: string;
  title: string;
  description: string;
  risk_level: string;
  prerequisites: string[];
}

interface AttackEdge {
  from: string;
  to: string;
  relationship: string;
}

interface AttackChain {
  nodes: AttackNode[];
  edges: AttackEdge[];
  combined_risk: string;
  fix_priority: { finding_id: string; title: string; action: string; effort: string }[];
}

interface FixSuggestion {
  finding_id: string;
  explanation: string;
  steps: string[];
  verification: string;
  urgency: string;
}

interface DiagnosisResult {
  summary: string;
  risk_level: string;
  immediate_actions: string[];
  technical_details: string;
}

interface Props {
  devices: DeviceInfo[];
  risks: RiskInfo[];
  deepseekApiKey?: string;
}

export function AIResultsPanel({ devices, risks, deepseekApiKey }: Props) {
  const [diagnosis, setDiagnosis] = useState<DiagnosisReport | null>(null);
  const [attackChain, setAttackChain] = useState<AttackChain | null>(null);
  const [fixSuggestion, setFixSuggestion] = useState<FixSuggestion | null>(null);
  const [selectedRisk, setSelectedRisk] = useState<RiskInfo | null>(null);
  const [vulnDiagnosis, setVulnDiagnosis] = useState<DiagnosisResult | null>(null);
  const [vulnId, setVulnId] = useState('');
  const [cvss, setCvss] = useState(7.5);
  const [loading, setLoading] = useState<string | null>(null);

  const runDiagnosis = async () => {
    setLoading('diagnosis');
    try {
      const result = await invoke<DiagnosisReport>('ai_diagnose_network', {
        input: { devices, risks }
      });
      setDiagnosis(result);
    } catch (e) { console.error('AI diagnosis failed:', e); }
    setLoading(null);
  };

  const buildAttackChain = async () => {
    setLoading('attack_chain');
    try {
      const result = await invoke<AttackChain>('ai_build_attack_chain', { risks });
      setAttackChain(result);
    } catch (e) { console.error('Attack chain failed:', e); }
    setLoading(null);
  };

  const generateFix = async (risk: RiskInfo) => {
    setSelectedRisk(risk);
    setLoading('fix');
    try {
      const result = await invoke<FixSuggestion>('ai_generate_fix', { risk });
      setFixSuggestion(result);
    } catch (e) { console.error('Fix suggestion failed:', e); }
    setLoading(null);
  };

  const diagnoseVuln = async () => {
    if (!deepseekApiKey || !vulnId) return;
    setLoading('vuln_diag');
    try {
      const result = await invoke<DiagnosisResult>('ai_diagnose_vulnerability', {
        deviceInfo: devices.map(d => `${d.device_type} ${d.ip}`).join(', '),
        vulnId,
        cvss,
        apiKey: deepseekApiKey,
      });
      setVulnDiagnosis(result);
    } catch (e) { console.error('Vuln diagnosis failed:', e); }
    setLoading(null);
  };

  const severityColor = (s: string) => {
    switch (s.toLowerCase()) {
      case 'critical': case '严重': return 'text-red-400';
      case 'high': case '高危': return 'text-orange-400';
      case 'medium': case '中危': return 'text-yellow-400';
      case 'low': case '低危': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="mt-4 space-y-4">
      {/* Action Buttons */}
      <div className="flex gap-2 flex-wrap">
        <button
          onClick={runDiagnosis}
          disabled={loading !== null || risks.length === 0}
          className="bg-purple-600 text-white px-3 py-1 rounded text-sm disabled:opacity-50"
        >
          {loading === 'diagnosis' ? '诊断中...' : '🩺 AI 网络诊断'}
        </button>
        <button
          onClick={buildAttackChain}
          disabled={loading !== null || risks.length < 2}
          className="bg-red-700 text-white px-3 py-1 rounded text-sm disabled:opacity-50"
        >
          {loading === 'attack_chain' ? '分析中...' : '🔗 攻击链推理'}
        </button>
      </div>

      {/* Diagnosis Report */}
      {diagnosis && (
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <h3 className="text-purple-400 font-bold mb-2">📋 AI 网络诊断报告</h3>
          <p className="text-gray-300 text-sm mb-3">{diagnosis.summary}</p>

          {diagnosis.critical_issues.length > 0 && (
            <div className="mb-3">
              <h4 className="text-red-400 font-semibold text-sm">严重问题</h4>
              {diagnosis.critical_issues.map((issue, i) => (
                <div key={i} className="text-gray-300 text-xs ml-2 mt-1">
                  • <span className="text-red-300">{issue.title}</span> ({issue.ip})
                  <p className="text-gray-500 ml-3">{issue.description}</p>
                </div>
              ))}
            </div>
          )}

          {diagnosis.recommendations.length > 0 && (
            <div>
              <h4 className="text-green-400 font-semibold text-sm">修复建议</h4>
              {diagnosis.recommendations.map((rec, i) => (
                <p key={i} className="text-gray-300 text-xs ml-2 mt-1">• {rec}</p>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Fix Suggestion per Risk */}
      <div className="space-y-2">
        <h4 className="text-gray-400 text-sm font-semibold">逐项修复建议</h4>
        {risks.map((risk, i) => (
          <div key={i} className="flex items-center gap-2">
            <span className={`text-xs font-mono w-24 truncate ${severityColor(risk.severity)}`}>
              [{risk.severity}] {risk.ip}
            </span>
            <span className="text-xs text-gray-400 truncate flex-1">{risk.title}</span>
            <button
              onClick={() => generateFix(risk)}
              disabled={loading !== null}
              className="bg-slate-700 text-gray-300 px-2 py-0.5 rounded text-xs hover:bg-slate-600 disabled:opacity-50"
            >
              修复建议
            </button>
          </div>
        ))}
      </div>

      {fixSuggestion && selectedRisk && (
        <div className="bg-slate-800 rounded-lg p-4 border border-blue-700">
          <h4 className="text-blue-400 font-bold text-sm mb-1">
            🔧 修复: {selectedRisk.title}
            <span className={`ml-2 ${fixSuggestion.urgency === '紧急' ? 'text-red-400' : 'text-yellow-400'}`}>
              [{fixSuggestion.urgency}]
            </span>
          </h4>
          <p className="text-gray-300 text-xs mb-2">{fixSuggestion.explanation}</p>
          <ol className="list-decimal list-inside text-gray-300 text-xs space-y-1">
            {fixSuggestion.steps.map((step, i) => (
              <li key={i}>{step.replace('{}', selectedRisk.ip)}</li>
            ))}
          </ol>
          <p className="text-green-400 text-xs mt-2">验证: {fixSuggestion.verification}</p>
        </div>
      )}

      {/* Attack Chain */}
      {attackChain && (
        <div className="bg-slate-800 rounded-lg p-4 border border-red-800">
          <h3 className="text-red-400 font-bold mb-2">
            🔗 攻击链分析
            <span className={`ml-2 text-sm ${severityColor(attackChain.combined_risk)}`}>
              [{attackChain.combined_risk}]
            </span>
          </h3>
          <div className="space-y-2">
            {attackChain.nodes.map((node, i) => (
              <div key={node.id} className="flex items-start gap-2">
                <span className="text-gray-500 text-xs font-mono mt-0.5">{i + 1}.</span>
                <div>
                  <span className="text-gray-200 text-sm">{node.title}</span>
                  {node.prerequisites.length > 0 && (
                    <span className="text-gray-500 text-xs ml-2">
                      ← 依赖: {node.prerequisites.map(p => attackChain.nodes.find(n => n.id === p)?.title || p).join(', ')}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
          {attackChain.fix_priority.length > 0 && (
            <div className="mt-3 pt-2 border-t border-slate-700">
              <h4 className="text-green-400 text-sm font-semibold">阻断建议（按优先级）:</h4>
              {attackChain.fix_priority.map((fix, i) => (
                <p key={i} className="text-gray-300 text-xs ml-2 mt-1">
                  {i + 1}. {fix.title} — {fix.action} (工作量: {fix.effort})
                </p>
              ))}
            </div>
          )}
        </div>
      )}

      {/* DeepSeek Vulnerability Diagnosis */}
      {deepseekApiKey && (
        <div className="bg-slate-800 rounded-lg p-4 border border-green-800">
          <h3 className="text-green-400 font-bold text-sm mb-2">🤖 DeepSeek 漏洞诊断</h3>
          <div className="flex gap-2 mb-2">
            <input
              type="text"
              value={vulnId}
              onChange={e => setVulnId(e.target.value)}
              placeholder="CVE-2024-..."
              className="bg-slate-900 border border-slate-600 rounded px-2 py-1 text-sm text-gray-200 flex-1"
            />
            <input
              type="number"
              value={cvss}
              onChange={e => setCvss(Number(e.target.value))}
              step={0.1}
              min={0}
              max={10}
              className="bg-slate-900 border border-slate-600 rounded px-2 py-1 text-sm text-gray-200 w-20"
            />
            <button
              onClick={diagnoseVuln}
              disabled={loading !== null || !vulnId}
              className="bg-green-700 text-white px-3 py-1 rounded text-sm disabled:opacity-50"
            >
              {loading === 'vuln_diag' ? '查询中...' : '诊断'}
            </button>
          </div>
          {vulnDiagnosis && (
            <div className="space-y-2">
              <p className="text-gray-200 text-sm">{vulnDiagnosis.summary}</p>
              <span className={`text-xs px-2 py-0.5 rounded ${severityColor(vulnDiagnosis.risk_level)} bg-slate-700`}>
                {vulnDiagnosis.risk_level}
              </span>
              <div>
                <h5 className="text-red-400 text-xs font-semibold">立即措施:</h5>
                {vulnDiagnosis.immediate_actions.map((a, i) => (
                  <p key={i} className="text-gray-300 text-xs ml-2">• {a}</p>
                ))}
              </div>
              <p className="text-gray-400 text-xs">{vulnDiagnosis.technical_details}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
