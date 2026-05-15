import { invoke } from '@tauri-apps/api/core';
import { useState } from 'react';

interface DnsRecon {
  domain: string;
  records: Record<string, { value: string; ttl?: number }[]>;
  subdomains: string[];
  cloud_provider?: string;
  cdn?: string;
}

interface HttpSecurityReport {
  url: string;
  missing: string[];
  weak: string[];
  score: string;
  recommendations: string[];
}

interface PublicAsset {
  ip: string;
  ports: number[];
  services: string[];
  cves: string[];
  asn?: string;
  geo?: string;
  last_updated?: string;
}

interface ThreatIntelResult {
  ip: string;
  is_malicious: boolean;
  threat_actors: string[];
  attack_reports: string[];
  last_seen?: string;
}

interface WafCdn {
  ip: string;
  waf_type: string;
  cdn_provider: string;
  is_behind: boolean;
  evidence: string[];
}

interface WebVulnResult {
  vuln_type: string;
  url: string;
  evidence: string;
  severity: string;
}

interface CombinedReconResult {
  target: string;
  dns?: DnsRecon;
  subdomains: string[];
  http_security?: HttpSecurityReport;
  public_asset?: PublicAsset;
  threat_intel?: ThreatIntelResult;
}

interface Props {
  target?: string;
  shodanApiKey?: string;
}

export function ReconPanel({ target: defaultTarget, shodanApiKey }: Props) {
  const [target, setTarget] = useState(defaultTarget || '');
  const [loading, setLoading] = useState<string | null>(null);
  const [result, setResult] = useState<CombinedReconResult | null>(null);
  const [httpResult, setHttpResult] = useState<HttpSecurityReport | null>(null);
  const [shodanResult, setShodanResult] = useState<PublicAsset | null>(null);
  const [threatResult, setThreatResult] = useState<ThreatIntelResult | null>(null);
  const [webVulns, setWebVulns] = useState<WebVulnResult[]>([]);
  const [wafResult, setWafResult] = useState<WafCdn | null>(null);

  const runFullRecon = async () => {
    if (!target) return;
    setLoading('full');
    try {
      const res = await invoke<CombinedReconResult>('recon_full', {
        input: {
          target,
          shodan_api_key: shodanApiKey || null,
          fofa_api_key: null,
          fofa_email: null,
        }
      });
      setResult(res);
    } catch (e) { console.error('Recon failed:', e); }
    setLoading(null);
  };

  const runDnsOnly = async () => {
    if (!target) return;
    setLoading('dns');
    try {
      const res = await invoke<DnsRecon>('recon_dns_recon', { target });
      setResult(prev => prev ? { ...prev, dns: res } : { target, dns: res, subdomains: [] });
    } catch (e) { console.error('DNS recon failed:', e); }
    setLoading(null);
  };

  const runHttpAudit = async () => {
    const url = target.startsWith('http') ? target : `https://${target}`;
    setLoading('http');
    try {
      const res = await invoke<HttpSecurityReport>('recon_http_audit', { url });
      setHttpResult(res);
    } catch (e) { console.error('HTTP audit failed:', e); }
    setLoading(null);
  };

  const runShodan = async () => {
    if (!target || !shodanApiKey) return;
    setLoading('shodan');
    try {
      const res = await invoke<PublicAsset>('recon_query_shodan', {
        apiKey: shodanApiKey,
        ip: target,
      });
      setShodanResult(res);
    } catch (e) { console.error('Shodan query failed:', e); }
    setLoading(null);
  };

  const runThreatIntel = async () => {
    if (!target) return;
    setLoading('threat');
    try {
      const res = await invoke<ThreatIntelResult>('recon_check_threat_intel', { ip: target });
      setThreatResult(res);
    } catch (e) { console.error('Threat intel failed:', e); }
    setLoading(null);
  };

  const runWebScan = async () => {
    const url = target.startsWith('http') ? target : `https://${target}`;
    setLoading('web');
    try {
      const res = await invoke<WebVulnResult[]>('recon_passive_web_scan', { url });
      setWebVulns(res);
    } catch (e) { console.error('Web scan failed:', e); }
    setLoading(null);
  };

  const scoreColor = (score: string) => {
    switch (score) {
      case 'A': return 'text-green-400';
      case 'B': return 'text-lime-400';
      case 'C': return 'text-yellow-400';
      case 'D': return 'text-orange-400';
      case 'E': case 'F': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const vulnSeverityColor = (s: string) => {
    switch (s) {
      case '高危': return 'text-red-400';
      case '中危': return 'text-yellow-400';
      case '低危': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="mt-4 space-y-4">
      {/* Target Input */}
      <div className="flex gap-2">
        <input
          type="text"
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="IP or domain (e.g. example.com, 8.8.8.8)"
          className="bg-slate-900 border border-slate-600 rounded px-3 py-1.5 text-sm text-gray-200 flex-1"
        />
        <button
          onClick={runFullRecon}
          disabled={loading !== null || !target}
          className="bg-indigo-600 text-white px-4 py-1.5 rounded text-sm disabled:opacity-50"
        >
          {loading === 'full' ? '侦察中...' : '🔍 全面侦察'}
        </button>
      </div>

      {/* Quick Actions */}
      <div className="flex gap-2 flex-wrap">
        <button onClick={runDnsOnly} disabled={loading !== null || !target}
          className="bg-slate-700 text-gray-300 px-2 py-1 rounded text-xs hover:bg-slate-600 disabled:opacity-50">
          DNS
        </button>
        <button onClick={runHttpAudit} disabled={loading !== null || !target}
          className="bg-slate-700 text-gray-300 px-2 py-1 rounded text-xs hover:bg-slate-600 disabled:opacity-50">
          HTTP 审计
        </button>
        <button onClick={runShodan} disabled={loading !== null || !target || !shodanApiKey}
          className="bg-slate-700 text-gray-300 px-2 py-1 rounded text-xs hover:bg-slate-600 disabled:opacity-50">
          Shodan
        </button>
        <button onClick={runThreatIntel} disabled={loading !== null || !target}
          className="bg-slate-700 text-gray-300 px-2 py-1 rounded text-xs hover:bg-slate-600 disabled:opacity-50">
          威胁情报
        </button>
        <button onClick={runWebScan} disabled={loading !== null || !target}
          className="bg-slate-700 text-gray-300 px-2 py-1 rounded text-xs hover:bg-slate-600 disabled:opacity-50">
          Web 扫描
        </button>
      </div>

      {/* DNS Results */}
      {(result?.dns || result?.subdomains?.length) ? (
        <div className="bg-slate-800 rounded-lg p-4 border border-indigo-800">
          <h3 className="text-indigo-400 font-bold text-sm mb-2">🌐 DNS 侦察</h3>
          {result.dns && (
            <div className="space-y-1 mb-2">
              {result.dns.cloud_provider && (
                <p className="text-gray-300 text-xs">☁️ 云: <span className="text-blue-300">{result.dns.cloud_provider}</span></p>
              )}
              {Object.entries(result.dns.records).map(([type, records]) => (
                <p key={type} className="text-gray-400 text-xs">
                  <span className="text-gray-500 font-mono">{type}</span>
                  {': '}
                  {records.slice(0, 3).map(r => r.value).join(', ')}
                  {records.length > 3 && ` +${records.length - 3}`}
                </p>
              ))}
            </div>
          )}
          {result.subdomains.length > 0 && (
            <div>
              <h4 className="text-gray-400 text-xs font-semibold">子域名 ({result.subdomains.length}):</h4>
              <div className="flex flex-wrap gap-1 mt-1">
                {result.subdomains.slice(0, 15).map((s, i) => (
                  <span key={i} className="bg-slate-700 text-gray-300 px-2 py-0.5 rounded text-xs">{s}</span>
                ))}
                {result.subdomains.length > 15 && (
                  <span className="text-gray-500 text-xs">+{result.subdomains.length - 15} 更多</span>
                )}
              </div>
            </div>
          )}
        </div>
      ) : null}

      {/* HTTP Security */}
      {httpResult && (
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <h3 className="text-gray-200 font-bold text-sm mb-2">
            🔒 HTTP 安全头审计
            <span className={`ml-2 text-lg font-bold ${scoreColor(httpResult.score)}`}>{httpResult.score}</span>
          </h3>
          {httpResult.missing.length > 0 && (
            <div className="mb-2">
              <h4 className="text-red-400 text-xs font-semibold">缺失:</h4>
              {httpResult.missing.map((h, i) => (
                <span key={i} className="text-red-300 text-xs mr-2 bg-red-900/30 px-1.5 py-0.5 rounded">{h}</span>
              ))}
            </div>
          )}
          {httpResult.weak.length > 0 && (
            <div className="mb-2">
              <h4 className="text-yellow-400 text-xs font-semibold">弱配置:</h4>
              {httpResult.weak.map((h, i) => (
                <p key={i} className="text-yellow-300 text-xs ml-2">• {h}</p>
              ))}
            </div>
          )}
          {httpResult.recommendations.map((r, i) => (
            <p key={i} className="text-gray-400 text-xs ml-2">💡 {r}</p>
          ))}
        </div>
      )}

      {/* Shodan */}
      {shodanResult && (
        <div className="bg-slate-800 rounded-lg p-4 border border-orange-800">
          <h3 className="text-orange-400 font-bold text-sm mb-2">🌍 Shodan 公网资产</h3>
          <p className="text-gray-300 text-xs">IP: {shodanResult.ip}</p>
          {shodanResult.asn && <p className="text-gray-400 text-xs">ASN: {shodanResult.asn}</p>}
          {shodanResult.geo && <p className="text-gray-400 text-xs">位置: {shodanResult.geo}</p>}
          <div className="flex flex-wrap gap-1 mt-1">
            {shodanResult.ports.map(p => (
              <span key={p} className="bg-slate-700 text-orange-300 px-1.5 py-0.5 rounded text-xs">{p}</span>
            ))}
          </div>
          <div className="flex flex-wrap gap-1 mt-1">
            {shodanResult.services.map((s, i) => (
              <span key={i} className="text-gray-400 text-xs">{s}{i < shodanResult.services.length - 1 ? ',' : ''}</span>
            ))}
          </div>
          {shodanResult.cves.length > 0 && (
            <div className="mt-2">
              <h4 className="text-red-400 text-xs font-semibold">CVE:</h4>
              {shodanResult.cves.map((c, i) => (
                <span key={i} className="text-red-300 text-xs mr-2">{c}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Threat Intelligence */}
      {threatResult && (
        <div className={`bg-slate-800 rounded-lg p-4 border ${threatResult.is_malicious ? 'border-red-700' : 'border-green-700'}`}>
          <h3 className="font-bold text-sm mb-2">
            {threatResult.is_malicious ? '⚠️ ' : '✅ '}
            <span className={threatResult.is_malicious ? 'text-red-400' : 'text-green-400'}>
              威胁情报: {threatResult.ip}
            </span>
          </h3>
          {threatResult.is_malicious && (
            <p className="text-red-300 text-xs">标记为恶意 IP</p>
          )}
          {threatResult.threat_actors.length > 0 && (
            <p className="text-gray-300 text-xs mt-1">
              威胁方: {threatResult.threat_actors.join(', ')}
            </p>
          )}
          {threatResult.attack_reports.map((r, i) => (
            <p key={i} className="text-gray-400 text-xs ml-2">• {r}</p>
          ))}
        </div>
      )}

      {/* Web Vulnerabilities */}
      {webVulns.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4 border border-red-800">
          <h3 className="text-red-400 font-bold text-sm mb-2">🕷️ Web 漏洞扫描</h3>
          {webVulns.map((v, i) => (
            <div key={i} className="text-xs mb-2 pb-2 border-b border-slate-700 last:border-0">
              <span className={`font-semibold ${vulnSeverityColor(v.severity)}`}>
                [{v.severity}] {v.vuln_type}
              </span>
              <p className="text-gray-400">{v.url}</p>
              <p className="text-gray-500">{v.evidence}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
