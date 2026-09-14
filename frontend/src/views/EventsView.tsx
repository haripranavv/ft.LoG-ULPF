import React, { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { api, type NormalizedEventRecord } from '../api/client';
import { Badge } from '../components/common/Badge';
import { Drawer } from '../components/common/Modal';
import { JsonViewer } from '../components/common/JsonViewer';

export const EventsView: React.FC = () => {
  const [events, setEvents] = useState<NormalizedEventRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [sourceFormat, setSourceFormat] = useState('');
  const [validFilter, setValidFilter] = useState<string>('all');
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEventRecord | null>(null);
  const [detailTab, setDetailTab] = useState<'summary' | 'normalized' | 'raw' | 'provenance'>('summary');

  useEffect(() => {
    loadEvents();
  }, [sourceFormat, validFilter]);

  const loadEvents = async () => {
    setLoading(true);
    try {
      const res = await api.listEvents({
        limit: 50,
        search: search.trim() || undefined,
        source_format: sourceFormat || undefined,
        valid: validFilter === 'all' ? undefined : validFilter === 'valid',
      });
      setEvents(res.events || []);
      setTotal(res.total || 0);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadEvents();
  };

  const getSeverityBadge = (sev: number | null) => {
    if (sev === null || sev === undefined) return <Badge size="sm">N/A</Badge>;
    if (sev >= 8) return <Badge variant="danger" size="sm">Sev {sev}</Badge>;
    if (sev >= 5) return <Badge variant="warning" size="sm">Sev {sev}</Badge>;
    if (sev >= 3) return <Badge variant="info" size="sm">Sev {sev}</Badge>;
    return <Badge variant="success" size="sm">Sev {sev}</Badge>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Search & Filter Bar */}
      <div
        className="card"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '8px', flex: 1, minWidth: '260px' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '9px', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search raw payload, action, or event type..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: '30px', width: '100%' }}
            />
          </div>
          <button type="submit" className="btn btn-secondary">
            Search
          </button>
        </form>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <select
            value={sourceFormat}
            onChange={(e) => setSourceFormat(e.target.value)}
            style={{ width: '140px' }}
          >
            <option value="">All Formats</option>
            <option value="cef">CEF</option>
            <option value="syslog">Syslog</option>
            <option value="json">JSON</option>
            <option value="csv">CSV</option>
            <option value="key_value">Key-Value</option>
            <option value="yaml">YAML</option>
            <option value="acmeguard">AcmeGuard</option>
            <option value="openvpn">OpenVPN</option>
            <option value="cisco_ios">Cisco IOS</option>
            <option value="suricata">Suricata</option>
            <option value="discovery">Discovery</option>
          </select>

          <select
            value={validFilter}
            onChange={(e) => setValidFilter(e.target.value)}
            style={{ width: '110px' }}
          >
            <option value="all">All Status</option>
            <option value="valid">Valid</option>
            <option value="invalid">Invalid</option>
          </select>

          <span style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginLeft: '4px' }}>
            Total: <strong style={{ color: 'var(--text-primary)' }}>{total}</strong>
          </span>
        </div>
      </div>

      {/* Events Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Type / Format</th>
              <th>Action</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '28px', color: 'var(--text-muted)' }}>
                  Loading canonical events...
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  No events found matching your search. Ingest logs to view events.
                </td>
              </tr>
            ) : (
              events.map((ev) => (
                <tr
                  key={ev.id}
                  onClick={() => {
                    setSelectedEvent(ev);
                    setDetailTab('summary');
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'N/A'}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                    {ev.source?.ip ? `${ev.source.ip}${ev.source.port ? `:${ev.source.port}` : ''}` : '—'}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                    {ev.destination?.ip ? `${ev.destination.ip}${ev.destination.port ? `:${ev.destination.port}` : ''}` : '—'}
                  </td>
                  <td>
                    <Badge variant="outline" size="sm">
                      {ev.source_format || ev.event_type || 'generic'}
                    </Badge>
                  </td>
                  <td>
                    <span style={{ fontWeight: 500 }}>{ev.action || 'EVENT'}</span>
                  </td>
                  <td>{getSeverityBadge(ev.severity)}</td>
                  <td>
                    <Badge variant={ev.valid ? 'success' : 'warning'} size="sm">
                      {ev.valid ? 'Valid' : 'Validation Error'}
                    </Badge>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Slide-over Event Inspector Drawer with Tabs */}
      <Drawer
        isOpen={!!selectedEvent}
        onClose={() => setSelectedEvent(null)}
        title="Event Inspector"
        subtitle={selectedEvent ? `ID: ${selectedEvent.id}` : ''}
        width="680px"
      >
        {selectedEvent && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', gap: '6px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
              {(['summary', 'normalized', 'raw', 'provenance'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setDetailTab(tab)}
                  className={`btn btn-sm ${detailTab === tab ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ textTransform: 'capitalize' }}
                >
                  {tab === 'summary' && 'Summary'}
                  {tab === 'normalized' && 'Normalized Event'}
                  {tab === 'raw' && 'Raw Data'}
                  {tab === 'provenance' && 'Provenance'}
                </button>
              ))}
            </div>

            {/* Tab 1: Summary */}
            {detailTab === 'summary' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '10px',
                    backgroundColor: 'var(--bg-subtle)',
                    padding: '12px',
                    borderRadius: 'var(--radius-md)',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Timestamp</div>
                    <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                      {selectedEvent.timestamp ? new Date(selectedEvent.timestamp).toISOString() : 'N/A'}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Severity / Action</div>
                    <div style={{ fontSize: '12px', fontWeight: 600 }}>
                      {selectedEvent.action || 'EVENT'} ({selectedEvent.severity ?? 'N/A'})
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Source Endpoint</div>
                    <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                      {selectedEvent.source?.ip || 'None'} {selectedEvent.source?.port ? `:${selectedEvent.source.port}` : ''}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Destination Endpoint</div>
                    <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                      {selectedEvent.destination?.ip || 'None'} {selectedEvent.destination?.port ? `:${selectedEvent.destination.port}` : ''}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Parser & Version</div>
                    <div style={{ fontSize: '12px' }}>
                      {selectedEvent.parser?.name || 'generic'} ({selectedEvent.parser?.version || '1.0.0'})
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Mapping ID</div>
                    <div style={{ fontSize: '12px' }}>
                      {selectedEvent.mapping?.id || 'provisional'}
                    </div>
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '6px' }}>Canonical Event Tree</div>
                  <JsonViewer data={selectedEvent.normalized_event} maxHeight="300px" />
                </div>
              </div>
            )}

            {/* Tab 2: Normalized Event */}
            {detailTab === 'normalized' && (
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  Complete validated canonical ULPF schema event:
                </div>
                <JsonViewer data={selectedEvent.normalized_event} maxHeight="500px" />
              </div>
            )}

            {/* Tab 3: Raw Data */}
            {detailTab === 'raw' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Original unaltered log payload preserved at ingestion:
                </div>
                <div
                  style={{
                    backgroundColor: 'var(--bg-app)',
                    border: '1px solid var(--border-color)',
                    padding: '14px',
                    borderRadius: 'var(--radius-md)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    lineHeight: '1.6',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    color: '#e5e7eb',
                  }}
                >
                  {selectedEvent.raw_payload}
                </div>
              </div>
            )}

            {/* Tab 4: Provenance */}
            {detailTab === 'provenance' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div
                  style={{
                    backgroundColor: 'var(--bg-subtle)',
                    padding: '14px',
                    borderRadius: 'var(--radius-md)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '11px' }}>Raw Payload SHA-256 Hash</span>
                    <span style={{ color: 'var(--accent-text)', wordBreak: 'break-all' }}>
                      {selectedEvent.raw_event_hash || 'SHA-256 computed on ingest'}
                    </span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '11px' }}>Provenance Trace ID</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedEvent.trace_id}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '11px' }}>Collector Identifier</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedEvent.collector_id || 'ulpf-collector-01'}</span>
                  </div>
                </div>
                <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
                  Cryptographic tamper evidence guarantees that the original raw telemetry payload has not been modified since initial receipt.
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
};
