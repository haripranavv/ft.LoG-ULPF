import React, { useEffect, useState } from 'react';
import {
  Network,
  Play,
  CheckCircle2,
  Laptop,
  Smartphone,
  Printer,
  Camera,
  Server,
  HelpCircle,
} from 'lucide-react';
import { api, type DeviceItem } from '../api/client';
import { Badge } from '../components/common/Badge';
import { Drawer } from '../components/common/Modal';
import { JsonViewer } from '../components/common/JsonViewer';

export const DevicesView: React.FC = () => {
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<DeviceItem | null>(null);
  const [scanLan, setScanLan] = useState(true);
  const [scanWifi, setScanWifi] = useState(true);
  const [scanSummary, setScanSummary] = useState<string | null>(null);

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    setLoading(true);
    try {
      const data = await api.listDevices();
      setDevices(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleRunDiscovery = async () => {
    setIsScanning(true);
    setScanSummary(null);
    try {
      const res = await api.runDiscovery({
        scan_lan: scanLan,
        scan_wifi: scanWifi,
        scan_bluetooth: false,
      });
      setDevices(res.devices || []);
      const sum = res.summary || {};
      setScanSummary(
        `Scanned in ${sum.scan_duration_ms}ms: found ${sum.discovered_this_scan} devices (${sum.new_devices} new, ${sum.updated_devices} updated). Generated ${sum.ulpf_events_generated} canonical discovery events.`
      );
    } catch (e: any) {
      alert(`Discovery failed: ${e.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleStatusChange = async (device: DeviceItem, newStatus: string) => {
    try {
      const updated = await api.updateDeviceStatus(device.id, newStatus);
      setDevices((prev) => prev.map((d) => (d.id === device.id ? updated : d)));
      if (selectedDevice?.id === device.id) {
        setSelectedDevice(updated);
      }
    } catch (e: any) {
      alert(`Failed to update status: ${e.message}`);
    }
  };

  const getDeviceIcon = (type: string) => {
    const t = (type || '').toLowerCase();
    if (t.includes('printer')) return <Printer size={15} />;
    if (t.includes('camera')) return <Camera size={15} />;
    if (t.includes('mobile') || t.includes('phone')) return <Smartphone size={15} />;
    if (t.includes('router') || t.includes('gateway') || t.includes('switch') || t.includes('access_point')) return <Network size={15} />;
    if (t.includes('server')) return <Server size={15} />;
    if (t.includes('workstation') || t.includes('pc') || t.includes('laptop')) return <Laptop size={15} />;
    return <HelpCircle size={15} />;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Top Action Bar */}
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={handleRunDiscovery}
            className="btn btn-primary"
            disabled={isScanning}
          >
            <Play size={14} className={isScanning ? 'spin-anim' : ''} />
            {isScanning ? 'Scanning Network...' : 'Run Discovery'}
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '12px', color: 'var(--text-secondary)' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={scanLan}
                onChange={(e) => setScanLan(e.target.checked)}
              />
              LAN ARP
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={scanWifi}
                onChange={(e) => setScanWifi(e.target.checked)}
              />
              Wi-Fi APs
            </label>
          </div>
        </div>

        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
          Devices Found:{' '}
          <span style={{ color: 'var(--accent-text)', fontFamily: 'var(--font-mono)' }}>
            {devices.length}
          </span>
        </div>
      </div>

      {/* Discovery Summary Notice */}
      {scanSummary && (
        <div
          style={{
            backgroundColor: 'var(--success-bg)',
            border: '1px solid var(--success-border)',
            color: 'var(--success-text)',
            padding: '10px 14px',
            borderRadius: 'var(--radius-md)',
            fontSize: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <CheckCircle2 size={16} />
          <span>{scanSummary}</span>
        </div>
      )}

      {/* Devices Data Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Device Name</th>
              <th>IP Address</th>
              <th>MAC Address</th>
              <th>Peripheral Type</th>
              <th>Manufacturer</th>
              <th>Last Seen</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '28px', color: 'var(--text-muted)' }}>
                  Loading network inventory...
                </td>
              </tr>
            ) : devices.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  No devices discovered yet. Click <strong>[ Run Discovery ]</strong> above to inspect the local network.
                </td>
              </tr>
            ) : (
              devices.map((d) => (
                <tr
                  key={d.id}
                  onClick={() => setSelectedDevice(d)}
                  style={{ cursor: 'pointer' }}
                >
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 500 }}>
                      <span style={{ color: 'var(--text-muted)' }}>{getDeviceIcon(d.device_type)}</span>
                      <span>{d.name}</span>
                    </div>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                    {d.ip || d.ip_address || '—'}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                    {d.mac_address || d.hardware_id || '—'}
                  </td>
                  <td>
                    <Badge variant="info" size="sm">
                      {d.device_type}
                    </Badge>
                  </td>
                  <td>
                    <span style={{ color: 'var(--text-secondary)' }}>{d.manufacturer || d.vendor || 'Generic'}</span>
                  </td>
                  <td style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                    {d.last_seen ? new Date(d.last_seen).toLocaleTimeString() : 'N/A'}
                  </td>
                  <td>
                    <Badge
                      variant={d.status === 'known' ? 'success' : d.status === 'new' ? 'warning' : 'default'}
                      size="sm"
                    >
                      {d.status}
                    </Badge>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Device Details Drawer */}
      <Drawer
        isOpen={!!selectedDevice}
        onClose={() => setSelectedDevice(null)}
        title={selectedDevice?.name || 'Device Details'}
        subtitle={selectedDevice ? `ID: ${selectedDevice.id}` : ''}
      >
        {selectedDevice && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
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
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>IP Address</div>
                <div style={{ fontSize: '12.5px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                  {selectedDevice.ip || selectedDevice.ip_address || 'None'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>MAC Address</div>
                <div style={{ fontSize: '12.5px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                  {selectedDevice.mac_address || selectedDevice.hardware_id || 'None'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Manufacturer / OUI</div>
                <div style={{ fontSize: '12.5px', fontWeight: 500 }}>
                  {selectedDevice.manufacturer || selectedDevice.vendor || 'Generic'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Peripheral Type</div>
                <div style={{ fontSize: '12.5px', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  {selectedDevice.device_type}
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    ({Math.round(selectedDevice.device_type_confidence * 100)}% conf)
                  </span>
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Discovery Method</div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  {selectedDevice.discovery_method || 'Authorized inspection'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>First Seen</div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  {selectedDevice.first_seen ? new Date(selectedDevice.first_seen).toLocaleString() : 'N/A'}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ fontSize: '12.5px', fontWeight: 500 }}>Inventory Status</span>
              <select
                value={selectedDevice.status}
                onChange={(e) => handleStatusChange(selectedDevice, e.target.value)}
                style={{ width: '130px' }}
              >
                <option value="known">Known</option>
                <option value="new">New</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>

            {selectedDevice.event_id && (
              <div
                style={{
                  backgroundColor: 'var(--bg-app)',
                  padding: '10px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '11.5px',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-muted)',
                }}
              >
                <div>Associated Canonical Event ID: {selectedDevice.event_id}</div>
                {selectedDevice.trace_id && <div>Provenance Trace ID: {selectedDevice.trace_id}</div>}
              </div>
            )}

            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '6px' }}>Device Record Metadata</div>
              <JsonViewer data={selectedDevice} maxHeight="240px" />
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};
