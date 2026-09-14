import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileText,
  CheckCircle2,
  AlertCircle,
  Sparkles,
  ChevronRight,
} from 'lucide-react';
import { api, type IngestionResponse } from '../api/client';
import { Badge } from '../components/common/Badge';

export const IngestView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'upload' | 'paste' | 'samples'>('upload');
  const [rawText, setRawText] = useState('');
  const [filename, setFilename] = useState('manual_input.log');
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentStage, setCurrentStage] = useState<string>('');
  const [result, setResult] = useState<IngestionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const supportedFormats = [
    'JSON', 'NDJSON', 'Syslog', 'CEF', 'CSV', 'Key-Value', 'YAML',
    'Firewall', 'IDS/IPS', 'VPN', 'Router', 'Switch',
  ];

  const sampleLogs = [
    {
      name: 'AcmeGuard Firewall',
      filename: 'acmeguard.log',
      content: '2026-09-06T10:00:00Z FW01 ALLOW SRC=10.10.10.25 DST=172.16.1.20 SP=49152 DP=443 PROTO=TCP RULE=ALLOW_WEB USER=alice',
    },
    {
      name: 'Suricata IDS Alert (JSON)',
      filename: 'suricata.json',
      content: JSON.stringify({
        timestamp: "2026-09-06T10:40:00Z",
        event_type: "alert",
        src_ip: "192.168.1.50",
        src_port: 54321,
        dest_ip: "10.0.0.10",
        dest_port: 443,
        proto: "TCP",
        alert: {
          signature: "Possible malicious traffic",
          severity: 2,
          category: "Attempted Admin"
        }
      }, null, 2),
    },
    {
      name: 'ArcSight CEF Event',
      filename: 'arcsight.cef',
      content: 'CEF:0|SecurityCorp|NextGenFirewall|4.5|1002|Traffic Permitted|3|src=192.168.10.50 dst=203.0.113.80 spt=54321 dpt=443 proto=TCP act=ALLOW msg="Egress session permitted"',
    },
    {
      name: 'Network Perimeter CSV',
      filename: 'perimeter.csv',
      content: '2026-09-14T10:00:00Z, 192.168.1.100, 10.0.0.1, 443, TCP, ALLOW\n2026-09-14T10:01:00Z, 10.0.0.50, 172.16.0.5, 22, TCP, BLOCK',
    },
    {
      name: 'Generic Unknown Gateway (Inference)',
      filename: 'gateway_unknown.log',
      content: 'vendor=SecureEdge dev=CloudGateway action=DENY srcaddr=198.51.100.44 dstaddr=10.0.4.1 sport=50212 dport=22 threat_name=SSHBruteForce custom_severity=CRITICAL user=root',
    },
  ];

  const handleFileUpload = async (file: File) => {
    setIsProcessing(true);
    setError(null);
    setResult(null);

    setCurrentStage('Uploading raw payload...');
    await new Promise((r) => setTimeout(r, 100));
    setCurrentStage('Detecting format & computing SHA-256...');
    await new Promise((r) => setTimeout(r, 100));
    setCurrentStage('Parsing deterministically & normalizing canonical schema...');

    try {
      const resp = await api.uploadFileMultipart(file);
      setCurrentStage('Validated & tamper-evident Merkle root generated');
      setResult(resp);
    } catch (err: any) {
      setError(err.message || 'File ingestion failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!rawText.trim()) return;
    setIsProcessing(true);
    setError(null);
    setResult(null);

    setCurrentStage('Processing payload & preserving raw storage...');
    try {
      const resp = await api.uploadFilePayload(filename, rawText);
      setResult(resp);
    } catch (err: any) {
      setError(err.message || 'Ingestion failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const loadSample = (s: { name: string; filename: string; content: string }) => {
    setFilename(s.filename);
    setRawText(s.content);
    setActiveTab('paste');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Tab Selector */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
        <button
          onClick={() => setActiveTab('upload')}
          className={`btn ${activeTab === 'upload' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <UploadCloud size={14} />
          Upload Log Files
        </button>
        <button
          onClick={() => setActiveTab('paste')}
          className={`btn ${activeTab === 'paste' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <FileText size={14} />
          Paste Raw Text
        </button>
        <button
          onClick={() => setActiveTab('samples')}
          className={`btn ${activeTab === 'samples' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Sparkles size={14} />
          Sample Logs
        </button>
      </div>

      {/* Tab Content: Upload File */}
      {activeTab === 'upload' && (
        <div
          style={{
            border: '2px dashed var(--border-color)',
            borderRadius: 'var(--radius-xl)',
            padding: '48px 24px',
            textAlign: 'center',
            backgroundColor: 'var(--bg-surface)',
            cursor: 'pointer',
            transition: 'border-color 0.15s ease',
          }}
          onClick={() => fileInputRef.current?.click()}
          onDragOver={(e) => {
            e.preventDefault();
            e.currentTarget.style.borderColor = 'var(--accent)';
          }}
          onDragLeave={(e) => {
            e.preventDefault();
            e.currentTarget.style.borderColor = 'var(--border-color)';
          }}
          onDrop={(e) => {
            e.preventDefault();
            e.currentTarget.style.borderColor = 'var(--border-color)';
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
              handleFileUpload(e.dataTransfer.files[0]);
            }
          }}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".log,.txt,.json,.jsonl,.csv,.yaml,.yml"
            style={{ display: 'none' }}
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFileUpload(e.target.files[0]);
              }
            }}
          />
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              backgroundColor: 'var(--accent-subtle)',
              color: 'var(--accent-text)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 16px',
            }}
          >
            <UploadCloud size={24} />
          </div>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
            Drop logs here or Choose Files
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '20px' }}>
            Supports raw log streams, single events, or line-delimited files up to 100MB
          </p>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={(e) => {
              e.stopPropagation();
              fileInputRef.current?.click();
            }}
          >
            Select File from Disk
          </button>

          <div style={{ marginTop: '28px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '8px' }}>
              Supported Formats (Deterministic & Schema Inference):
            </span>
            <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: '6px' }}>
              {supportedFormats.map((fmt) => (
                <span
                  key={fmt}
                  style={{
                    fontSize: '11px',
                    color: 'var(--text-secondary)',
                    backgroundColor: 'var(--bg-subtle)',
                    padding: '2px 8px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  {fmt}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab Content: Paste Text */}
      {activeTab === 'paste' && (
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <label style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Virtual Filename:</label>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              style={{ width: '220px' }}
            />
          </div>
          <textarea
            rows={8}
            placeholder="Paste raw log lines or JSON telemetry here..."
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: '12px' }}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
            <button
              onClick={() => setRawText('')}
              className="btn btn-secondary"
              disabled={!rawText || isProcessing}
            >
              Clear
            </button>
            <button
              onClick={handlePasteSubmit}
              className="btn btn-primary"
              disabled={!rawText.trim() || isProcessing}
            >
              {isProcessing ? 'Processing...' : 'Process & Normalize'}
            </button>
          </div>
        </div>
      )}

      {/* Tab Content: Samples */}
      {activeTab === 'samples' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
          {sampleLogs.map((s) => (
            <div
              key={s.name}
              className="card"
              style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '12px' }}
            >
              <div>
                <h4 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>{s.name}</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                  {s.filename}
                </p>
                <div
                  style={{
                    backgroundColor: 'var(--bg-app)',
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-secondary)',
                    marginTop: '8px',
                    maxHeight: '70px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {s.content}
                </div>
              </div>
              <button onClick={() => loadSample(s)} className="btn btn-secondary btn-sm" style={{ width: '100%' }}>
                Load Sample Log
                <ChevronRight size={13} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* 6-Stage Real Pipeline Tracker */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 16px',
          backgroundColor: 'var(--bg-subtle)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-color)',
          overflowX: 'auto',
          gap: '8px',
        }}
      >
        {[
          { label: 'Uploading', active: isProcessing && currentStage.includes('Uploading'), done: !!result },
          { label: 'Detecting Format', active: isProcessing && currentStage.includes('Detecting'), done: !!result },
          { label: 'Parsing', active: isProcessing && currentStage.includes('Parsing'), done: !!result },
          { label: 'Normalizing', active: isProcessing && currentStage.includes('normalizing'), done: !!result },
          { label: 'Validating', active: isProcessing && currentStage.includes('Validated'), done: !!result },
          { label: 'Complete', active: false, done: !!result && !error },
        ].map((step, idx, arr) => (
          <React.Fragment key={step.label}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}>
              <div
                style={{
                  width: '20px',
                  height: '20px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '10.5px',
                  fontWeight: 600,
                  backgroundColor: step.done ? 'var(--success-bg)' : step.active ? 'var(--accent-subtle)' : 'var(--bg-app)',
                  color: step.done ? 'var(--success-text)' : step.active ? 'var(--accent-text)' : 'var(--text-muted)',
                  border: step.done ? '1px solid var(--success-border)' : step.active ? '1px solid var(--accent)' : '1px solid var(--border-subtle)',
                }}
              >
                {step.done ? '✓' : idx + 1}
              </div>
              <span
                style={{
                  fontSize: '11.5px',
                  fontWeight: step.done || step.active ? 600 : 400,
                  color: step.done ? 'var(--success-text)' : step.active ? 'var(--accent-text)' : 'var(--text-muted)',
                }}
              >
                {step.label}
              </span>
            </div>
            {idx < arr.length - 1 && <span style={{ color: 'var(--border-subtle)', fontSize: '11px' }}>→</span>}
          </React.Fragment>
        ))}
      </div>

      {/* Processing Pipeline Stages Banner */}
      {isProcessing && (
        <div
          className="card"
          style={{
            backgroundColor: 'var(--bg-subtle)',
            borderColor: 'var(--accent)',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
          }}
        >
          <div style={{ width: '18px', height: '18px', border: '2px solid var(--accent)', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
          <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--accent-text)' }}>
            {currentStage || 'Processing telemetry deterministically...'}
          </span>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div
          style={{
            backgroundColor: 'var(--danger-bg)',
            border: '1px solid var(--danger-border)',
            color: 'var(--danger-text)',
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '12.5px',
          }}
        >
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Ingestion Results Summary */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div
            className="card"
            style={{
              backgroundColor: 'var(--bg-surface)',
              borderLeft: '4px solid var(--success)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={18} color="var(--success-text)" />
                <h4 style={{ fontSize: '14px', fontWeight: 600 }}>Ingestion Completed Successfully</h4>
              </div>
              <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                Latency: <strong style={{ color: 'var(--text-primary)' }}>{result.processing_time_ms}ms</strong>
              </span>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                gap: '10px',
                backgroundColor: 'var(--bg-subtle)',
                padding: '12px',
                borderRadius: 'var(--radius-md)',
                marginBottom: '12px',
              }}
            >
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Detected Format</div>
                <div style={{ fontSize: '13px', fontWeight: 600 }}>{result.detected_format}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Parser Used</div>
                <div style={{ fontSize: '13px', fontWeight: 600 }}>{result.parser_used}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Total Events</div>
                <div style={{ fontSize: '13px', fontWeight: 600 }}>{result.total_events}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Valid Canonical</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--success-text)' }}>{result.valid_count}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Invalid / Fallback</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: result.invalid_count > 0 ? 'var(--danger-text)' : 'var(--text-muted)' }}>
                  {result.invalid_count}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              <div>
                <span style={{ color: 'var(--text-secondary)' }}>File SHA-256: </span>
                {result.sha256_hash}
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)' }}>Merkle Batch Root: </span>
                {result.batch_merkle_root}
              </div>
            </div>
          </div>

          {/* Itemized Table */}
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Raw Log Preview</th>
                  <th>Parser</th>
                  <th>Mode</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {result.items.map((item) => (
                  <tr key={item.index}>
                    <td style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{item.index}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-primary)' }}>
                      {item.preview}
                    </td>
                    <td>
                      <Badge variant="outline" size="sm">
                        {item.parser || 'generic'}
                      </Badge>
                    </td>
                    <td>
                      <Badge variant={item.mode === 'deterministic' ? 'info' : 'purple'} size="sm">
                        {item.mode}
                      </Badge>
                    </td>
                    <td>
                      <Badge variant={item.valid ? 'success' : 'danger'} size="sm">
                        {item.valid ? 'Valid' : 'Validation Error'}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
