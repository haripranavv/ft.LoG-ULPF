import React, { useEffect, useState } from 'react';
import { Download, Send, Database } from 'lucide-react';
import { api, type ExportJob } from '../api/client';
import { Badge } from '../components/common/Badge';

export const ExportsView: React.FC = () => {
  const [exports, setExports] = useState<ExportJob[]>([]);
  const [, setLoading] = useState(false);
  const [limit, setLimit] = useState(500);

  // Webhook form state
  const [webhookUrl, setWebhookUrl] = useState('https://webhook.site/test-endpoint');
  const [webhookStatus, setWebhookStatus] = useState<string | null>(null);
  const [isSendingWebhook, setIsSendingWebhook] = useState(false);

  // Elasticsearch form state
  const [esEndpoint, setEsEndpoint] = useState('http://localhost:9200');
  const [esIndex, setEsIndex] = useState('ulpf-events');
  const [esStatus, setEsStatus] = useState<string | null>(null);
  const [isSendingEs, setIsSendingEs] = useState(false);

  useEffect(() => {
    loadExports();
  }, []);

  const loadExports = async () => {
    setLoading(true);
    try {
      const res = await api.listExports();
      setExports(res.exports || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadJsonl = () => {
    window.open(api.getDownloadJsonlUrl(limit), '_blank');
  };

  const handleSendWebhook = async () => {
    if (!webhookUrl.trim()) return;
    setIsSendingWebhook(true);
    setWebhookStatus(null);
    try {
      const res = await api.triggerExport({
        target_type: 'webhook',
        limit,
        config: { url: webhookUrl },
      });
      setWebhookStatus(`Exported ${res.event_count} events to webhook (HTTP ${res.http_status})`);
      loadExports();
    } catch (e: any) {
      setWebhookStatus(`Webhook push failed: ${e.message}`);
    } finally {
      setIsSendingWebhook(false);
    }
  };

  const handleSendElasticsearch = async () => {
    if (!esEndpoint.trim()) return;
    setIsSendingEs(true);
    setEsStatus(null);
    try {
      const res = await api.triggerExport({
        target_type: 'elasticsearch',
        limit,
        config: { endpoint: esEndpoint, index_name: esIndex },
      });
      setEsStatus(`Successfully bulk pushed ${res.event_count} events to index '${res.index}'`);
      loadExports();
    } catch (e: any) {
      setEsStatus(`Elasticsearch export failed: ${e.message}`);
    } finally {
      setIsSendingEs(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Overview Banner */}
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
          <h3 style={{ fontSize: '14px', fontWeight: 600 }}>Telemetry Export Connectors</h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Push normalized canonical events to SIEMs, data lakes, and webhook receivers.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <label style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Batch Size:</label>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            style={{ width: '100px' }}
          >
            <option value={100}>100 events</option>
            <option value={500}>500 events</option>
            <option value={1000}>1,000 events</option>
            <option value={5000}>5,000 events</option>
          </select>
        </div>
      </div>

      {/* 3 Main Export Destination Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
        {/* Destination 1: JSON Lines */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <div style={{ width: '28px', height: '28px', borderRadius: 'var(--radius-sm)', backgroundColor: 'var(--accent-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-text)' }}>
                <Download size={16} />
              </div>
              <div>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600 }}>JSON Lines (NDJSON)</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>SIEM & Data Lake Ingestion Format</p>
              </div>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
              Exports events formatted as newline-delimited JSON with full schema preserved. Suitable for Splunk, Datadog, Snowflake, or local archiving.
            </p>
          </div>

          <button onClick={handleDownloadJsonl} className="btn btn-primary" style={{ width: '100%' }}>
            <Download size={14} />
            Download .jsonl File
          </button>
        </div>

        {/* Destination 2: HTTP Webhook */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <div style={{ width: '28px', height: '28px', borderRadius: 'var(--radius-sm)', backgroundColor: 'var(--info-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--info-text)' }}>
                <Send size={16} />
              </div>
              <div>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600 }}>HTTP Webhook</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>REST Telemetry Dispatcher</p>
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Target Webhook URL:</label>
              <input
                type="text"
                placeholder="https://siem-collector.internal/webhook"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                style={{ width: '100%', fontSize: '12px', fontFamily: 'var(--font-mono)' }}
              />
            </div>
            {webhookStatus && (
              <div style={{ fontSize: '11px', color: webhookStatus.includes('failed') ? 'var(--danger-text)' : 'var(--success-text)', marginTop: '6px' }}>
                {webhookStatus}
              </div>
            )}
          </div>

          <button
            onClick={handleSendWebhook}
            className="btn btn-secondary"
            disabled={isSendingWebhook || !webhookUrl.trim()}
            style={{ width: '100%' }}
          >
            <Send size={14} />
            {isSendingWebhook ? 'Dispatching...' : 'Dispatch Webhook Push'}
          </button>
        </div>

        {/* Destination 3: Elasticsearch / OpenSearch */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <div style={{ width: '28px', height: '28px', borderRadius: 'var(--radius-sm)', backgroundColor: 'var(--warning-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--warning-text)' }}>
                <Database size={16} />
              </div>
              <div>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600 }}>Elasticsearch / OpenSearch</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Bulk API Indexing Connector</p>
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div>
                <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Cluster Endpoint:</label>
                <input
                  type="text"
                  value={esEndpoint}
                  onChange={(e) => setEsEndpoint(e.target.value)}
                  style={{ width: '100%', fontSize: '12px', fontFamily: 'var(--font-mono)' }}
                />
              </div>
              <div>
                <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Target Index Name:</label>
                <input
                  type="text"
                  value={esIndex}
                  onChange={(e) => setEsIndex(e.target.value)}
                  style={{ width: '100%', fontSize: '12px', fontFamily: 'var(--font-mono)' }}
                />
              </div>
            </div>
            {esStatus && (
              <div style={{ fontSize: '11px', color: esStatus.includes('failed') ? 'var(--danger-text)' : 'var(--success-text)', marginTop: '6px' }}>
                {esStatus}
              </div>
            )}
          </div>

          <button
            onClick={handleSendElasticsearch}
            className="btn btn-secondary"
            disabled={isSendingEs || !esEndpoint.trim()}
            style={{ width: '100%' }}
          >
            <Database size={14} />
            {isSendingEs ? 'Indexing...' : 'Execute Bulk Push'}
          </button>
        </div>
      </div>

      {/* Export Jobs History Table */}
      <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
        <div
          style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--border-color)',
            backgroundColor: 'var(--bg-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <h4 style={{ fontSize: '13px', fontWeight: 600 }}>Export Execution History</h4>
          <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
            Tracked in PostgreSQL
          </span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Target Type</th>
                <th>Destination</th>
                <th>Event Count</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {exports.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                    No export jobs recorded yet. Execute an export above.
                  </td>
                </tr>
              ) : (
                exports.map((job) => (
                  <tr key={job.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                      {job.created_at ? new Date(job.created_at).toLocaleString() : 'N/A'}
                    </td>
                    <td>
                      <Badge variant="outline" size="sm">
                        {job.target_type}
                      </Badge>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                      {job.destination || 'local'}
                    </td>
                    <td>{job.event_count}</td>
                    <td>
                      <Badge variant={job.status === 'completed' ? 'success' : 'danger'} size="sm">
                        {job.status}
                      </Badge>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
