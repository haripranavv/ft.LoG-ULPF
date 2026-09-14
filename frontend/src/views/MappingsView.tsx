import React, { useEffect, useState } from 'react';
import {
  Sparkles,
  ArrowRight,
} from 'lucide-react';
import { api, type MappingDefinitionItem } from '../api/client';
import { Badge } from '../components/common/Badge';

export const MappingsView: React.FC = () => {
  const [mappings, setMappings] = useState<MappingDefinitionItem[]>([]);
  const [selectedMapping, setSelectedMapping] = useState<MappingDefinitionItem | null>(null);
  const [loading, setLoading] = useState(false);
  const [sampleText, setSampleText] = useState(
    'vendor=AcmeCloud dev=Gateway action=DENY srcaddr=192.168.1.1 dstaddr=10.0.0.5 sport=49152 dport=80 user=admin custom_severity=CRITICAL'
  );
  const [testResult, setTestResult] = useState<any>(null);
  const [isTesting, setIsTesting] = useState(false);

  useEffect(() => {
    loadMappings();
  }, []);

  const loadMappings = async () => {
    setLoading(true);
    try {
      const data = await api.listMappings();
      setMappings(data);
      if (data.length > 0 && !selectedMapping) {
        setSelectedMapping(data[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleTestInference = async () => {
    if (!sampleText.trim()) return;
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await api.uploadFilePayload('test_mapping.log', sampleText);
      setTestResult(res);
    } catch (e: any) {
      alert(`Test failed: ${e.message}`);
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header Info */}
      <div
        className="card"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: 'var(--bg-subtle)',
        }}
      >
        <div>
          <h3 style={{ fontSize: '14px', fontWeight: 600 }}>Schema Mapping Registry</h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Deterministic rule maps & AI-assisted candidate proposals for unknown structured logs.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <Badge variant="success">{mappings.length} Registered Mappings</Badge>
          <Badge variant="purple">AI Schema Assistant Ready</Badge>
        </div>
      </div>

      {/* Two Column Layout: Mappings List vs Detail / Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '16px' }}>
        {/* Left: Mapping List */}
        <div className="card" style={{ padding: '0', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border-color)', backgroundColor: 'var(--bg-subtle)', fontSize: '12px', fontWeight: 600 }}>
            Registered Sources & Formats
          </div>
          <div style={{ overflowY: 'auto', maxHeight: '520px', padding: '6px' }}>
            {loading ? (
              <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                Loading mappings...
              </div>
            ) : (
              mappings.map((m) => {
                const isSelected = selectedMapping?.mapping_id === m.mapping_id;
                return (
                  <div
                    key={m.mapping_id}
                    onClick={() => setSelectedMapping(m)}
                    style={{
                      padding: '10px 12px',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: isSelected ? 'var(--accent-subtle)' : 'transparent',
                      border: `1px solid ${isSelected ? 'var(--border-focus)' : 'transparent'}`,
                      cursor: 'pointer',
                      marginBottom: '4px',
                      transition: 'all 0.12s ease',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontWeight: 600, fontSize: '12.5px', color: isSelected ? 'var(--accent-text)' : 'var(--text-primary)' }}>
                        {m.mapping_id}
                      </span>
                      <Badge variant="outline" size="sm">
                        v{m.version}
                      </Badge>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Format: <span style={{ color: 'var(--text-secondary)' }}>{m.source_format}</span>
                      {m.vendor && ` • Vendor: ${m.vendor}`}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Selected Mapping Details / Field Table */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {selectedMapping ? (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <h4 style={{ fontSize: '14px', fontWeight: 600 }}>{selectedMapping.mapping_id}</h4>
                  <p style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                    Deterministic mapping for {selectedMapping.vendor || 'generic'} ({selectedMapping.source_format})
                  </p>
                </div>
                <Badge variant="success">Deterministic Production Active</Badge>
              </div>

              {/* Fields Table */}
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Source Log Field</th>
                      <th></th>
                      <th>Canonical Target Field</th>
                      <th>Confidence</th>
                      <th>Required</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedMapping.fields.map((f, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-primary)' }}>
                          {f.source_field}
                        </td>
                        <td style={{ width: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          <ArrowRight size={13} />
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-text)', fontWeight: 500 }}>
                          {f.target_field}
                        </td>
                        <td>
                          <Badge variant={f.confidence >= 0.9 ? 'success' : 'warning'} size="sm">
                            {Math.round(f.confidence * 100)}%
                          </Badge>
                        </td>
                        <td>
                          <span style={{ fontSize: '11px', color: f.required ? 'var(--danger-text)' : 'var(--text-muted)' }}>
                            {f.required ? 'Required' : 'Optional'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="card" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
              Select a mapping from the left list to view field definitions.
            </div>
          )}

          {/* Interactive Schema Inference Tester */}
          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <h4 style={{ fontSize: '13px', fontWeight: 600 }}>Test Unknown Log Schema Inference</h4>
                <p style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                  Evaluates unmapped log fields deterministically with optional local AI schema assistance.
                </p>
              </div>
              <button
                onClick={handleTestInference}
                className="btn btn-primary btn-sm"
                disabled={isTesting || !sampleText.trim()}
              >
                <Sparkles size={13} />
                {isTesting ? 'Analyzing...' : 'Run Inference Test'}
              </button>
            </div>

            <textarea
              rows={3}
              value={sampleText}
              onChange={(e) => setSampleText(e.target.value)}
              style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', width: '100%' }}
            />

            {testResult && testResult.items && testResult.items[0] && (
              <div
                style={{
                  backgroundColor: 'var(--bg-subtle)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-md)',
                  padding: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '12px', fontWeight: 600 }}>Inference Result:</span>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <Badge variant={testResult.items[0].mode === 'deterministic' ? 'info' : 'purple'} size="sm">
                      {testResult.items[0].mode === 'deterministic' ? 'Deterministic Resolver' : 'AI Assisted'}
                    </Badge>
                    <Badge variant={testResult.items[0].valid ? 'success' : 'warning'} size="sm">
                      {testResult.items[0].valid ? 'Valid Canonical' : 'Provisional'}
                    </Badge>
                  </div>
                </div>

                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Mapping ID: <strong style={{ color: 'var(--text-primary)' }}>{testResult.items[0].mapping_id || 'dynamic'}</strong>
                  {testResult.items[0].latency_ms && ` • Processed in ${testResult.items[0].latency_ms}ms`}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
