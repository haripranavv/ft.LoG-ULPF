import React, { useEffect, useState } from 'react';
import {
  FileText,
  Layers,
  Network,
  ArrowUpRight,
  ShieldCheck,
} from 'lucide-react';
import { api, type StatsData, type DeviceItem, type NormalizedEventRecord } from '../api/client';
import { Badge } from '../components/common/Badge';

interface OverviewViewProps {
  onNavigate: (tab: any) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<StatsData>({
    total_events: 0,
    valid_events: 0,
    invalid_events: 0,
    source_formats: 0,
    mappings: 0,
    collectors: 1,
  });
  const [recentEvents, setRecentEvents] = useState<NormalizedEventRecord[]>([]);
  const [recentDevices, setRecentDevices] = useState<DeviceItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [statsData, eventsData, devicesData] = await Promise.all([
        api.getStats().catch(() => ({
          total_events: 0,
          valid_events: 0,
          invalid_events: 0,
          source_formats: 0,
          mappings: 6,
          collectors: 1,
        })),
        api.listEvents({ limit: 6 }).catch(() => ({ events: [], total: 0, count: 0 })),
        api.listDevices().catch(() => []),
      ]);
      setStats(statsData);
      setRecentEvents(eventsData.events || []);
      setRecentDevices(devicesData.slice(0, 5));
    } finally {
      setLoading(false);
    }
  };

  const healthPercent = stats.total_events > 0
    ? Math.round((stats.valid_events / stats.total_events) * 100)
    : 100;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Metric Cards Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '12px',
        }}
      >
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
            <span style={{ fontSize: '12px', fontWeight: 500 }}>Events Processed</span>
            <FileText size={16} />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>
            {stats.total_events.toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--success-text)' }}>
            {stats.valid_events.toLocaleString()} valid canonical events
          </div>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
            <span style={{ fontSize: '12px', fontWeight: 500 }}>Active Sources</span>
            <Layers size={16} />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>
            {Math.max(stats.source_formats, 6)}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            CEF, Syslog, JSON, CSV, Net, Sec
          </div>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
            <span style={{ fontSize: '12px', fontWeight: 500 }}>Discovered Devices</span>
            <Network size={16} />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>
            {recentDevices.length}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--info-text)' }}>
            LAN & Neighbor Inventory
          </div>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
            <span style={{ fontSize: '12px', fontWeight: 500 }}>Processing Health</span>
            <ShieldCheck size={16} color="var(--success-text)" />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--success-text)' }}>
            {healthPercent}%
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Deterministic sub-ms pipeline
          </div>
        </div>
      </div>

      {/* Primary Action Banner */}
      <div
        style={{
          background: 'linear-gradient(90deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%)',
          border: '1px solid rgba(99, 102, 241, 0.25)',
          borderRadius: 'var(--radius-lg)',
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Ready to normalize new telemetry?
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Upload raw log files or trigger local network peripheral discovery.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button onClick={() => onNavigate('ingest')} className="btn btn-primary">
            Ingest Logs
            <ArrowUpRight size={14} />
          </button>
          <button onClick={() => onNavigate('devices')} className="btn btn-secondary">
            Run Discovery
            <Network size={14} />
          </button>
        </div>
      </div>

      {/* Two Column Section: Recent Events & Recent Devices */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '16px' }}>
        {/* Recent Events */}
        <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
          <div
            style={{
              padding: '12px 16px',
              borderBottom: '1px solid var(--border-color)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: 'var(--bg-subtle)',
            }}
          >
            <h4 style={{ fontSize: '13px', fontWeight: 600 }}>Recent Normalized Events</h4>
            <button
              onClick={() => onNavigate('events')}
              style={{ background: 'none', border: 'none', color: 'var(--accent-text)', fontSize: '12px', cursor: 'pointer' }}
            >
              View all
            </button>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source Format</th>
                  <th>Action</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>
                      Loading recent events...
                    </td>
                  </tr>
                ) : recentEvents.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>
                      No events ingested yet. Upload a log to begin.
                    </td>
                  </tr>
                ) : (
                  recentEvents.map((ev) => (
                    <tr key={ev.id}>
                      <td style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}
                      </td>
                      <td>
                        <Badge variant="outline" size="sm">
                          {ev.source_format || 'unknown'}
                        </Badge>
                      </td>
                      <td>
                        <span style={{ fontWeight: 500 }}>{ev.action || 'EVENT'}</span>
                      </td>
                      <td>
                        <Badge variant={ev.valid ? 'success' : 'warning'} size="sm">
                          {ev.valid ? 'Valid' : 'Invalid'}
                        </Badge>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Devices */}
        <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
          <div
            style={{
              padding: '12px 16px',
              borderBottom: '1px solid var(--border-color)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: 'var(--bg-subtle)',
            }}
          >
            <h4 style={{ fontSize: '13px', fontWeight: 600 }}>Network Inventory</h4>
            <button
              onClick={() => onNavigate('devices')}
              style={{ background: 'none', border: 'none', color: 'var(--accent-text)', fontSize: '12px', cursor: 'pointer' }}
            >
              View all
            </button>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>IP Address</th>
                  <th>Type</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>
                      Loading devices...
                    </td>
                  </tr>
                ) : recentDevices.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>
                      No devices scanned yet. Click "Run Discovery".
                    </td>
                  </tr>
                ) : (
                  recentDevices.map((dev) => (
                    <tr key={dev.id}>
                      <td>
                        <div style={{ fontWeight: 500, fontSize: '12px' }}>{dev.name}</div>
                        <div style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>{dev.manufacturer || 'Generic'}</div>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                        {dev.ip || dev.ip_address || '—'}
                      </td>
                      <td>
                        <Badge variant="info" size="sm">
                          {dev.device_type}
                        </Badge>
                      </td>
                      <td>
                        <Badge variant={dev.status === 'known' ? 'success' : 'default'} size="sm">
                          {dev.status}
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
    </div>
  );
};
