import React, { useEffect, useState } from 'react';
import { HardDrive, Cpu } from 'lucide-react';
import { api } from '../api/client';
import { Badge } from '../components/common/Badge';

export const SettingsView: React.FC = () => {
  const [health, setHealth] = useState<{ status: string; service: string; version?: string } | null>(null);

  useEffect(() => {
    api.getHealth().then(setHealth).catch(() => setHealth({ status: 'offline', service: 'ulpf-api' }));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '800px' }}>
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <h3 style={{ fontSize: '15px', fontWeight: 600 }}>System Configuration & Architecture</h3>
        <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
          ULPF is designed as a local-first, zero-cloud dependency telemetry normalization platform. All deterministic parsers, local GGUF models, and raw file stores operate strictly within host/container boundaries.
        </p>

        {/* Status Pills */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px' }}>
          <div style={{ backgroundColor: 'var(--bg-subtle)', padding: '12px', borderRadius: 'var(--radius-md)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Backend Service</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
              <Badge variant={health?.status === 'ok' ? 'success' : 'danger'}>
                {health?.status === 'ok' ? 'FastAPI Operational' : 'Offline'}
              </Badge>
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-subtle)', padding: '12px', borderRadius: 'var(--radius-md)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Database Layer</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
              <Badge variant="success">PostgreSQL 16</Badge>
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-subtle)', padding: '12px', borderRadius: 'var(--radius-md)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Local AI Subsystem</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
              <Badge variant="purple">llama.cpp / Qwen 2.5 (Lazy Loaded)</Badge>
            </div>
          </div>
        </div>
      </div>

      {/* Raw Storage Info */}
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <HardDrive size={16} color="var(--info-text)" />
          <h4 style={{ fontSize: '13.5px', fontWeight: 600 }}>Raw Log File Storage</h4>
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          Original uploaded log files are preserved in the mounted Docker volume (<code style={{ color: 'var(--accent-text)' }}>/data/raw</code> in containers or <code style={{ color: 'var(--accent-text)' }}>./storage/raw</code> locally).
        </p>
        <div style={{ backgroundColor: 'var(--bg-subtle)', padding: '10px 12px', borderRadius: 'var(--radius-md)', fontSize: '11.5px', fontFamily: 'var(--font-mono)' }}>
          <div>Volume mount: <span style={{ color: 'var(--text-primary)' }}>ulpf-raw-storage:/data/raw</span></div>
          <div>Deduplication: <span style={{ color: 'var(--text-primary)' }}>SHA-256 Content-Addressed Storage</span></div>
          <div>Integrity: <span style={{ color: 'var(--text-primary)' }}>Deterministic Merkle Tree Batch Roots</span></div>
        </div>
      </div>

      {/* Local AI Settings */}
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Cpu size={16} color="var(--accent-text)" />
          <h4 style={{ fontSize: '13.5px', fontWeight: 600 }}>Local AI Assistive Schema Engine</h4>
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          Local AI operates as an <em>assistive subsystem</em>. Deterministic parsing and schema heuristics run first and complete in sub-millisecond time. Local AI is only invoked for unmapped formats where heuristic confidence falls below 60%.
        </p>
        <div style={{ backgroundColor: 'var(--bg-subtle)', padding: '10px 12px', borderRadius: 'var(--radius-md)', fontSize: '11.5px', fontFamily: 'var(--font-mono)' }}>
          <div>Model: <span style={{ color: 'var(--text-primary)' }}>qwen2.5-3b-instruct-q4_k_m.gguf</span></div>
          <div>Inference: <span style={{ color: 'var(--text-primary)' }}>llama.cpp via Python C-bindings (CPU/GPU)</span></div>
          <div>Pipeline Delay: <span style={{ color: 'var(--success-text)' }}>0ms for known formats (Non-blocking)</span></div>
        </div>
      </div>
    </div>
  );
};
