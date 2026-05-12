import { invoke } from '@tauri-apps/api/core';
import { useEffect, useState } from 'react';
interface ToolStatus { name: string; installed: boolean; version?: string; }
export function ToolStatusBar() {
  const [tools, setTools] = useState<ToolStatus[]>([]);
  useEffect(() => { invoke<ToolStatus[]>('check_tool_status').then(setTools); }, []);
  return (
    <div className="flex gap-2 text-sm">
      {tools.map((t) => (
        <span key={t.name} className={t.installed ? 'text-green-600' : 'text-red-600'}>
          {t.installed ? '✔' : '✘'} {t.name}
        </span>
      ))}
    </div>
  );
}
