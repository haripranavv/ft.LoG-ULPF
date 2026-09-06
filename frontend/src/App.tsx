import { useEffect, useState, useRef } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  CheckCircle2,
  ChevronRight,
  Database,
  FileJson,
  Fingerprint,
  Gauge,
  Layers3,
  Network,
  RefreshCw,
  Server,
  ShieldCheck,
  Terminal,
  Wifi,
  X,
  XCircle,
  Zap,
  Upload,
  Radio,
  Bluetooth,
  Clock,
  Lock,
  Play,
  FileText,
  Search,
  Check,
} from 'lucide-react'
import './App.css'

type Stats = {
  total_events: number
  valid_events: number
  invalid_events: number
  source_formats: number
  mappings: number
  collectors: number
}

type Event = {
  id: string
  timestamp: string | null
  event_type: string | null
  action: string | null
  severity: number | null
  source: {
    ip: string | null
    port: number | null
  } | null
  destination: {
    ip: string | null
    port: number | null
  } | null
  protocol: string | null
  source_format: string | null
  parser: {
    name: string | null
    version: string | null
  } | null
  mapping: {
    id: string | null
    version: string | null
  } | null
  processing_mode: string | null
  normalization_status: string | null
  valid: boolean
  raw_event_hash: string | null
  trace_id: string | null
  collector_id: string | null
  raw_payload: string
  normalized_event: Record<string, unknown>
}

type SampleLog = {
  id: string
  name: string
  category: string
  log: string
}

type DiscoveredDevice = {
  id: string
  name: string
  ip: string | null
  hardware_id: string | null
  discovery_type: 'lan' | 'wifi' | 'bluetooth'
  first_seen: string
  last_seen: string
  status: 'known' | 'new' | 'unknown'
  event_id?: string
  trace_id?: string
}

type ScannerCapabilities = {
  os: string
  os_release: string
  lan: {
    supported: boolean
    method: string
    details: string
  }
  wifi: {
    supported: boolean
    adapter?: string
    method?: string
    details?: string
    reason?: string
  }
  bluetooth: {
    supported: boolean
    method?: string
    details?: string
    reason?: string
  }
}

const API = 'http://localhost:8000'

function App() {
  const [activeTab, setActiveTab] = useState<'control_plane' | 'timeline' | 'scanner'>('control_plane')

  // Dashboard state
  const [stats, setStats] = useState<Stats | null>(null)
  const [events, setEvents] = useState<Event[]>([])
  const [loading, setLoading] = useState(true)
  const [apiOnline, setApiOnline] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(new Date())
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)

  // Upload modal state
  const [uploadModalOpen, setUploadModalOpen] = useState(false)
  const [uploadTab, setUploadTab] = useState<'file' | 'paste'>('file')
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadText, setUploadText] = useState('')
  const [uploadLoading, setUploadLoading] = useState(false)
  const [uploadResult, setUploadResult] = useState<any | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // AI Mapping Timeline state
  const [sampleLogs, setSampleLogs] = useState<SampleLog[]>([])
  const [selectedSampleId, setSelectedSampleId] = useState<string>('')
  const [timelineInput, setTimelineInput] = useState('')
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [timelineData, setTimelineData] = useState<any | null>(null)
  const [approvalLoading, setApprovalLoading] = useState(false)
  const [customMappingId, setCustomMappingId] = useState('')

  // Active Scanner state
  const [scannerCaps, setScannerCaps] = useState<ScannerCapabilities | null>(null)
  const [scannerDevices, setScannerDevices] = useState<DiscoveredDevice[]>([])
  const [scannerLoading, setScannerLoading] = useState(false)
  const [scanLan, setScanLan] = useState(true)
  const [scanWifi, setScanWifi] = useState(true)
  const [scanBluetooth, setScanBluetooth] = useState(true)
  const [ingestToUlpf, setIngestToUlpf] = useState(true)
  const [scanSummary, setScanSummary] = useState<any | null>(null)

  async function loadDashboard() {
    try {
      setLoading(true)

      const [statsResponse, eventsResponse] = await Promise.all([
        fetch(`${API}/api/stats`),
        fetch(`${API}/api/events?limit=8&offset=0`),
      ])

      if (!statsResponse.ok || !eventsResponse.ok) {
        throw new Error('API request failed')
      }

      const statsData = await statsResponse.json()
      const eventsData = await eventsResponse.json()

      setStats(statsData)
      setEvents(eventsData.events ?? [])
      setApiOnline(true)
      setLastUpdated(new Date())
    } catch {
      setApiOnline(false)
    } finally {
      setLoading(false)
    }
  }

  async function loadScannerData() {
    try {
      const [capsRes, devsRes] = await Promise.all([
        fetch(`${API}/api/scanner/capabilities`),
        fetch(`${API}/api/scanner/devices`),
      ])
      if (capsRes.ok) {
        const caps = await capsRes.json()
        setScannerCaps(caps)
      }
      if (devsRes.ok) {
        const devs = await devsRes.json()
        setScannerDevices(devs)
      }
    } catch {
      // Ignored if API offline
    }
  }

  async function loadSampleLogs() {
    try {
      const res = await fetch(`${API}/api/mappings/samples`)
      if (res.ok) {
        const data = await res.json()
        setSampleLogs(data)
        if (data.length > 0 && !timelineInput) {
          setSelectedSampleId(data[0].id)
          setTimelineInput(data[0].log)
        }
      }
    } catch {
      // Ignored if API offline
    }
  }

  useEffect(() => {
    loadDashboard()
    loadScannerData()
    loadSampleLogs()

    const interval = window.setInterval(() => {
      loadDashboard()
    }, 5000)

    return () => window.clearInterval(interval)
  }, [])

  // Handle Log Upload
  async function handleProcessUpload() {
    let contentToSubmit = ''
    let filenameToSubmit = 'log_input.log'

    if (uploadTab === 'file') {
      if (!uploadFile) return
      contentToSubmit = await uploadFile.text()
      filenameToSubmit = uploadFile.name
    } else {
      if (!uploadText.trim()) return
      contentToSubmit = uploadText.trim()
      filenameToSubmit = contentToSubmit.startsWith('{') ? 'payload.json' : 'manual_entry.log'
    }

    try {
      setUploadLoading(true)
      const res = await fetch(`${API}/api/process/upload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: filenameToSubmit,
          content: contentToSubmit,
        }),
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || 'Upload failed')
      }

      const data = await res.json()
      setUploadResult(data)
      await loadDashboard()
    } catch (err: any) {
      alert(`Ingestion error: ${err.message}`)
    } finally {
      setUploadLoading(false)
    }
  }

  // Handle AI Timeline Analysis
  async function handleRunTimelineAnalysis(payloadToAnalyze?: string) {
    const payload = payloadToAnalyze ?? timelineInput
    if (!payload.trim()) return

    try {
      setTimelineLoading(true)
      const res = await fetch(`${API}/api/mappings/timeline`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_payload: payload.trim() }),
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || 'Timeline analysis failed')
      }

      const data = await res.json()
      setTimelineData(data)
      const stage6 = data.stages?.find((s: any) => s.stage === 6)
      if (stage6?.details?.approval_payload?.mapping_id) {
        setCustomMappingId(stage6.details.approval_payload.mapping_id)
      }
    } catch (err: any) {
      alert(`Timeline error: ${err.message}`)
    } finally {
      setTimelineLoading(false)
    }
  }

  // Handle Human Approval of Mapping
  async function handleApproveMapping() {
    const stage6 = timelineData?.stages?.find((s: any) => s.stage === 6)
    const basePayload = stage6?.details?.approval_payload
    if (!basePayload) return

    const approvalPayload = {
      ...basePayload,
      mapping_id: customMappingId.trim() || basePayload.mapping_id,
    }

    try {
      setApprovalLoading(true)
      const res = await fetch(`${API}/api/mappings/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(approvalPayload),
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || 'Approval failed')
      }

      // Re-run timeline analysis to verify newly activated deterministic processing
      await handleRunTimelineAnalysis(timelineInput)
      await loadDashboard()
    } catch (err: any) {
      alert(`Approval error: ${err.message}`)
    } finally {
      setApprovalLoading(false)
    }
  }

  // Handle Active Scanner Run
  async function handleRunScan() {
    try {
      setScannerLoading(true)
      const res = await fetch(`${API}/api/scanner/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_lan: scanLan,
          scan_wifi: scanWifi,
          scan_bluetooth: scanBluetooth,
          ingest_to_ulpf: ingestToUlpf,
        }),
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || 'Scanner execution failed')
      }

      const data = await res.json()
      setScannerDevices(data.devices ?? [])
      setScanSummary(data.summary)
      await loadDashboard()
    } catch (err: any) {
      alert(`Discovery scan error: ${err.message}`)
    } finally {
      setScannerLoading(false)
    }
  }

  // Handle Update Device Status
  async function handleUpdateDeviceStatus(deviceId: string, status: string) {
    try {
      const res = await fetch(`${API}/api/scanner/devices/${deviceId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      })
      if (res.ok) {
        const updated = await res.json()
        setScannerDevices((prev) =>
          prev.map((d) => (d.id === deviceId ? { ...d, status: updated.status } : d))
        )
      }
    } catch {
      // Ignored
    }
  }

  // Open single event in inspector
  async function inspectEventById(eventId: string) {
    try {
      const res = await fetch(`${API}/api/events/${eventId}`)
      if (res.ok) {
        const eventData = await res.json()
        // Map raw event to Event state structure
        const mappedEvent: Event = {
          id: eventId,
          timestamp: eventData.timestamp ?? null,
          event_type: eventData.event?.type ?? null,
          action: eventData.event?.action ?? null,
          severity: eventData.event?.severity ?? null,
          source: eventData.source ?? null,
          destination: eventData.destination ?? null,
          protocol: eventData.network?.protocol ?? null,
          source_format: eventData.ulpf?.source_format ?? null,
          parser: {
            name: eventData.ulpf?.parser_name ?? null,
            version: eventData.ulpf?.parser_version ?? null,
          },
          mapping: {
            id: eventData.ulpf?.mapping_id ?? null,
            version: eventData.ulpf?.mapping_version ?? null,
          },
          processing_mode: eventData.ulpf?.processing_mode ?? null,
          normalization_status: eventData.ulpf?.normalization_status ?? null,
          valid: eventData.processing?.valid ?? true,
          raw_event_hash: eventData.provenance?.raw_event_hash ?? null,
          trace_id: eventData.provenance?.trace_id ?? null,
          collector_id: eventData.provenance?.collector_id ?? null,
          raw_payload: eventData.raw?.payload ?? '',
          normalized_event: eventData,
        }
        setSelectedEvent(mappedEvent)
      }
    } catch {
      // Fallback
    }
  }

  const total = stats?.total_events ?? 0
  const valid = stats?.valid_events ?? 0
  const invalid = stats?.invalid_events ?? 0
  const validationRate = total > 0 ? ((valid / total) * 100).toFixed(1) : '0.0'

  return (
    <div className="app-shell">
      {/* TOPBAR */}
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={23} />
          </div>

          <div>
            <div className="brand-name">ULPF</div>
            <div className="brand-subtitle">Universal Log Pre-processing Framework</div>
          </div>
        </div>

        {/* TOPBAR NAVIGATION TABS */}
        <nav className="topbar-nav" aria-label="Dashboard views">
          <button
            className={`nav-tab ${activeTab === 'control_plane' ? 'active' : ''}`}
            onClick={() => setActiveTab('control_plane')}
          >
            <Gauge size={14} />
            CONTROL PLANE
          </button>

          <button
            className={`nav-tab ${activeTab === 'timeline' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('timeline')
              if (!timelineData && timelineInput) {
                handleRunTimelineAnalysis(timelineInput)
              }
            }}
          >
            <Layers3 size={14} />
            AI MAPPING TIMELINE
          </button>

          <button
            className={`nav-tab ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            <Radio size={14} />
            ACTIVE SCANNER
          </button>
        </nav>

        <div className="topbar-right">
          <button
            className="btn-upload-topbar"
            onClick={() => {
              setUploadModalOpen(true)
              setUploadResult(null)
            }}
          >
            <Upload size={14} />
            UPLOAD LOG
          </button>

          <div className="airgap-pill" title="Host-local air-gapped processing guaranteed">
            <span className="status-dot green" />
            AIR-GAPPED MODE
          </div>

          <div className="api-status">
            <span className={`status-dot ${apiOnline ? 'green' : 'red'}`} />
            {apiOnline ? 'SYSTEM ONLINE' : 'API OFFLINE'}
          </div>

          <button
            className="refresh-button"
            onClick={() => {
              loadDashboard()
              loadScannerData()
            }}
            title="Refresh state"
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </header>

      {/* MAIN DASHBOARD CONTENT CONTAINER */}
      <main className="dashboard">
        {/* VIEW 1: CONTROL PLANE (THE COMPLETE EXISTING DASHBOARD) */}
        {activeTab === 'control_plane' && (
          <>
            <section className="hero-row">
              <div>
                <div className="eyebrow">
                  <Activity size={14} />
                  OPERATIONS CENTER
                </div>

                <h1>Log Processing Control Plane</h1>

                <p>
                  Unified ingestion, deterministic normalization, validation and forensic provenance across
                  heterogeneous perimeter logs.
                </p>
              </div>

              <div className="last-updated">
                <span>LAST SYNCHRONIZED</span>
                <strong>{lastUpdated.toLocaleTimeString()}</strong>
              </div>
            </section>

            <section className="metric-grid">
              <MetricCard
                icon={<Database size={19} />}
                label="EVENTS PROCESSED"
                value={loading ? '—' : total.toLocaleString()}
                detail="Normalized events"
                accent="blue"
              />

              <MetricCard
                icon={<CheckCircle2 size={19} />}
                label="VALID EVENTS"
                value={loading ? '—' : valid.toLocaleString()}
                detail={`${validationRate}% validation rate`}
                accent="green"
              />

              <MetricCard
                icon={<XCircle size={19} />}
                label="INVALID EVENTS"
                value={loading ? '—' : invalid.toLocaleString()}
                detail="Requires review"
                accent="red"
              />

              <MetricCard
                icon={<Layers3 size={19} />}
                label="ACTIVE MAPPINGS"
                value={loading ? '—' : stats?.mappings ?? 0}
                detail="Versioned schemas"
                accent="purple"
              />

              <MetricCard
                icon={<Network size={19} />}
                label="SOURCE FORMATS"
                value={loading ? '—' : stats?.source_formats ?? 0}
                detail="Detected formats"
                accent="orange"
              />

              <MetricCard
                icon={<Wifi size={19} />}
                label="COLLECTORS"
                value={loading ? '—' : stats?.collectors ?? 0}
                detail="Active ingestion nodes"
                accent="cyan"
              />
            </section>

            <section className="content-grid">
              <div className="panel pipeline-panel">
                <PanelHeader icon={<Zap size={18} />} title="PROCESSING PIPELINE" action="LIVE" />

                <div className="pipeline">
                  <PipelineNode
                    icon={<Terminal size={18} />}
                    title="COLLECT"
                    subtitle="Syslog / File / REST"
                    status="healthy"
                  />

                  <PipelineArrow />

                  <PipelineNode
                    icon={<ArrowDownToLine size={18} />}
                    title="KAFKA"
                    subtitle="ulpf.raw.events"
                    status="healthy"
                  />

                  <PipelineArrow />

                  <PipelineNode
                    icon={<Gauge size={18} />}
                    title="FLINK"
                    subtitle="Deterministic processing"
                    status="healthy"
                  />

                  <PipelineArrow />

                  <PipelineNode
                    icon={<FileJson size={18} />}
                    title="NORMALIZE"
                    subtitle="Canonical schema"
                    status="healthy"
                  />

                  <PipelineArrow />

                  <PipelineNode
                    icon={<Database size={18} />}
                    title="STORE"
                    subtitle="PostgreSQL / MinIO"
                    status="healthy"
                  />
                </div>
              </div>

              <div className="panel system-panel">
                <PanelHeader icon={<Server size={18} />} title="SYSTEM HEALTH" action="6 COMPONENTS" />

                <div className="health-list">
                  <HealthRow name="ULPF API" value="ONLINE" />
                  <HealthRow name="Kafka Broker" value="ONLINE" />
                  <HealthRow name="Flink Engine" value="RUNNING" />
                  <HealthRow name="PostgreSQL" value="ONLINE" />
                  <HealthRow name="MinIO Object Store" value="ONLINE" />
                  <HealthRow name="Offline AI Engine" value="READY" />
                </div>
              </div>
            </section>

            <section className="panel events-panel">
              <PanelHeader
                icon={<Terminal size={18} />}
                title="RECENT NORMALIZED EVENTS"
                action={`${events.length} SHOWN`}
              />

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>EVENT</th>
                      <th>SOURCE</th>
                      <th>ACTION</th>
                      <th>NETWORK FLOW</th>
                      <th>PARSER</th>
                      <th>MAPPING</th>
                      <th>MODE</th>
                      <th>VALID</th>
                    </tr>
                  </thead>

                  <tbody>
                    {events.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="empty-state">
                          {apiOnline
                            ? 'No normalized events available.'
                            : 'Waiting for ULPF API connection...'}
                        </td>
                      </tr>
                    ) : (
                      events.map((event) => (
                        <tr
                          key={event.id}
                          className="event-row"
                          onClick={() => setSelectedEvent(event)}
                        >
                          <td>
                            <div className="event-id">
                              <Fingerprint size={14} />
                              {event.id.slice(0, 8)}
                            </div>
                          </td>

                          <td>
                            <span className="source-badge">{event.source_format ?? 'unknown'}</span>
                          </td>

                          <td>
                            <span
                              className={`action-badge ${
                                event.action?.toLowerCase() === 'allow' ? 'allow' : 'other'
                              }`}
                            >
                              {event.action ?? '—'}
                            </span>
                          </td>

                          <td>
                            <div className="flow">
                              <span>{event.source?.ip ?? '—'}</span>
                              <ChevronRight size={13} />
                              <span>{event.destination?.ip ?? '—'}</span>
                            </div>
                          </td>

                          <td>
                            <div className="cell-main">{event.parser?.name ?? '—'}</div>
                            <div className="cell-sub">v{event.parser?.version ?? '—'}</div>
                          </td>

                          <td>
                            <div className="cell-main">{event.mapping?.id ?? '—'}</div>
                            <div className="cell-sub">v{event.mapping?.version ?? '—'}</div>
                          </td>

                          <td>
                            <span className="mode-badge">{event.processing_mode ?? '—'}</span>
                          </td>

                          <td>
                            {event.valid ? (
                              <span className="valid">
                                <CheckCircle2 size={15} />
                                PASS
                              </span>
                            ) : (
                              <span className="invalid">
                                <AlertTriangle size={15} />
                                FAIL
                              </span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="bottom-grid">
              <div className="panel provenance-panel">
                <PanelHeader icon={<Fingerprint size={18} />} title="FORENSIC PROVENANCE" action="LOSSLESS" />

                <div className="provenance-content">
                  <div className="provenance-stat">
                    <strong>RAW</strong>
                    <span>Original payload preserved</span>
                  </div>

                  <div className="provenance-line">
                    <ChevronRight size={16} />
                  </div>

                  <div className="provenance-stat">
                    <strong>SHA-256</strong>
                    <span>Cryptographic integrity</span>
                  </div>

                  <div className="provenance-line">
                    <ChevronRight size={16} />
                  </div>

                  <div className="provenance-stat">
                    <strong>CANONICAL</strong>
                    <span>Normalized event</span>
                  </div>

                  <div className="provenance-line">
                    <ChevronRight size={16} />
                  </div>

                  <div className="provenance-stat">
                    <strong>TRACE</strong>
                    <span>Raw ↔ normalized linkage</span>
                  </div>
                </div>
              </div>

              <div className="panel ai-panel">
                <PanelHeader icon={<Zap size={18} />} title="OFFLINE AI ENGINE" action="READY" />

                <div className="ai-content">
                  <div className="ai-indicator">
                    <span className="ai-pulse" />
                    <span>LOCAL INFERENCE AVAILABLE</span>
                  </div>

                  <p>
                    AI-assisted onboarding identifies fields and proposes semantic mappings. Approved mappings
                    become deterministic runtime rules.
                  </p>

                  <div className="ai-tags">
                    <span>LLAMA.CPP</span>
                    <span>GGUF</span>
                    <span>NO CLOUD</span>
                    <span>HUMAN APPROVAL</span>
                  </div>

                  <div style={{ marginTop: '14px' }}>
                    <button
                      className="nav-tab active"
                      style={{ padding: '6px 12px' }}
                      onClick={() => setActiveTab('timeline')}
                    >
                      <Layers3 size={14} /> Open AI Mapping Timeline &rarr;
                    </button>
                  </div>
                </div>
              </div>
            </section>
          </>
        )}

        {/* VIEW 2: AI MAPPING TIMELINE */}
        {activeTab === 'timeline' && (
          <section className="timeline-view">
            <div className="view-hero">
              <div>
                <div className="eyebrow">
                  <Layers3 size={14} />
                  ONBOARDING CONTROL PLANE
                </div>
                <h1>AI Mapping & Onboarding Timeline</h1>
                <p>
                  Trace how unseen log signatures progress from raw bytes to deterministic runtime rules
                  through local AI inference, semantic field mapping, and mandatory human approval.
                </p>
              </div>

              <div className="airgap-pill" style={{ marginTop: '10px' }}>
                <Lock size={13} />
                ZERO EXTERNAL TELEMETRY (AIR-GAPPED)
              </div>
            </div>

            {/* PRESET SAMPLE PICKER */}
            <div className="samples-strip">
              <div className="samples-strip-label">
                <Terminal size={14} />
                PRE-CONFIGURED BENCHMARK LOGS (CLICK TO TEST TIMELINE)
              </div>

              <div className="samples-buttons-row">
                {sampleLogs.map((s) => (
                  <button
                    key={s.id}
                    className={`sample-chip ${selectedSampleId === s.id ? 'active' : ''}`}
                    onClick={() => {
                      setSelectedSampleId(s.id)
                      setTimelineInput(s.log)
                      handleRunTimelineAnalysis(s.log)
                    }}
                  >
                    {s.name}
                  </button>
                ))}
              </div>
            </div>

            {/* RAW LOG INPUT BAR */}
            <div className="timeline-input-bar">
              <textarea
                className="timeline-textarea"
                placeholder="Enter or paste raw log event payload..."
                value={timelineInput}
                onChange={(e) => setTimelineInput(e.target.value)}
              />

              <button
                className="btn-analyze"
                onClick={() => handleRunTimelineAnalysis(timelineInput)}
                disabled={timelineLoading || !timelineInput.trim()}
              >
                {timelineLoading ? (
                  <>
                    <RefreshCw size={16} className="spin-icon" />
                    <span>ANALYZING...</span>
                  </>
                ) : (
                  <>
                    <Play size={16} />
                    <span>ANALYZE FLOW</span>
                  </>
                )}
              </button>
            </div>

            {/* THE 8-STAGE TIMELINE CARDS */}
            {timelineData && (
              <div className="timeline-stages-wrapper">
                {timelineData.stages.map((st: any) => {
                  const isDone = st.status === 'completed' || st.status === 'active' || st.status === 'approved'
                  const isAwaiting = st.status === 'awaiting_approval' || st.status === 'missing_mapping'

                  return (
                    <div
                      key={st.stage}
                      className={`timeline-stage-card ${isDone ? 'completed' : isAwaiting ? 'awaiting' : 'active'}`}
                    >
                      <div className="stage-header-row">
                        <div className="stage-title-wrap">
                          <div className={`stage-number ${isDone ? 'done' : ''}`}>
                            {isDone ? <Check size={14} /> : st.stage}
                          </div>
                          <h3>{st.name}</h3>
                        </div>

                        <div
                          className={`stage-status-badge ${
                            isDone ? 'completed' : isAwaiting ? 'awaiting' : 'active'
                          }`}
                        >
                          {st.status.toUpperCase().replace('_', ' ')}
                        </div>
                      </div>

                      <div className="stage-body-content">
                        {/* STAGE 1: RAW LOG */}
                        {st.stage === 1 && (
                          <div className="stage-data-grid">
                            <InspectorItem label="SHA-256 RAW HASH" value={st.details.sha256} mono />
                            <InspectorItem label="PAYLOAD SIZE" value={`${st.details.bytes} bytes`} />
                            <InspectorItem label="RECEPTION TIME" value={st.timestamp} mono />
                          </div>
                        )}

                        {/* STAGE 2: FORMAT DETECTION */}
                        {st.stage === 2 && (
                          <div className="stage-data-grid">
                            <InspectorItem label="MATCHED PARSER" value={st.details.matched_parser} />
                            <InspectorItem label="SOURCE FORMAT" value={st.details.source_format} />
                            <InspectorItem label="DETECTED VENDOR" value={st.details.vendor} />
                            <InspectorItem label="PRODUCT TYPE" value={st.details.product} />
                          </div>
                        )}

                        {/* STAGE 3: FIELD EXTRACTION */}
                        {st.stage === 3 && (
                          <div>
                            <div style={{ marginBottom: '8px', fontSize: '11px', color: '#64748b' }}>
                              EXTRACTED FIELDS ({st.details.field_count} DETECTED)
                            </div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                              {Object.entries(st.details.fields).map(([k, v]) => (
                                <div key={k} className="selected-file-pill" style={{ margin: 0 }}>
                                  <strong style={{ color: '#5d9fff' }}>{k}:</strong>{' '}
                                  <span>{String(v)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* STAGE 4: MAPPING ANALYSIS */}
                        {st.stage === 4 && (
                          <div className="stage-data-grid">
                            <InspectorItem
                              label="SCHEMA REGISTRATION"
                              value={st.details.has_mapping ? 'REGISTERED & ACTIVE' : 'NO SCHEMA REGISTERED'}
                            />
                            {st.details.mapping_id && (
                              <InspectorItem label="MAPPING ID" value={st.details.mapping_id} mono />
                            )}
                            <InspectorItem label="NOTE" value={st.details.note} />
                          </div>
                        )}

                        {/* STAGE 5: AI / RULE-BASED PROPOSALS */}
                        {st.stage === 5 && (
                          <div>
                            <div style={{ fontSize: '11px', color: '#64748b', marginBottom: '8px' }}>
                              INFERENCE ENGINE: {st.details.inference_mode}
                            </div>
                            <table className="proposals-table">
                              <thead>
                                <tr>
                                  <th>SOURCE FIELD</th>
                                  <th>SUGGESTED CANONICAL TARGET</th>
                                  <th>CONFIDENCE</th>
                                  <th>PROPOSAL SOURCE</th>
                                </tr>
                              </thead>
                              <tbody>
                                {st.details.proposals.map((p: any, idx: number) => (
                                  <tr key={idx}>
                                    <td>
                                      <strong>{p.source_field}</strong>
                                    </td>
                                    <td>
                                      <span style={{ color: '#55d992', fontFamily: 'monospace' }}>
                                        {p.suggested_target || 'null (unmapped)'}
                                      </span>
                                    </td>
                                    <td>
                                      <span
                                        style={{
                                          color: p.confidence >= 0.9 ? '#55d992' : '#e9a35a',
                                          fontWeight: 700,
                                        }}
                                      >
                                        {(p.confidence * 100).toFixed(0)}%
                                      </span>
                                    </td>
                                    <td>
                                      <span className={`source-badge-chip ${p.source}`}>
                                        {p.source.toUpperCase().replace('_', ' ')}
                                      </span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}

                        {/* STAGE 6: HUMAN APPROVAL REQUIRED */}
                        {st.stage === 6 && (
                          <div className="approval-gate-card">
                            <div className="approval-gate-notice">
                              <AlertTriangle size={18} />
                              <span>{st.details.message}</span>
                            </div>

                            {st.details.required && (
                              <div className="approval-form-row">
                                <label style={{ fontSize: '12px', color: '#c4d3e8', fontWeight: 600 }}>
                                  TARGET MAPPING ID:
                                </label>
                                <input
                                  className="approval-input"
                                  value={customMappingId}
                                  onChange={(e) => setCustomMappingId(e.target.value)}
                                  placeholder="e.g. perimeter-gateway"
                                />

                                <button
                                  className="btn-approve-mapping"
                                  onClick={handleApproveMapping}
                                  disabled={approvalLoading}
                                >
                                  {approvalLoading ? (
                                    <>
                                      <RefreshCw size={14} className="spin-icon" />
                                      <span>APPROVING...</span>
                                    </>
                                  ) : (
                                    <>
                                      <Check size={14} />
                                      <span>APPROVE & VERSION MAPPING</span>
                                    </>
                                  )}
                                </button>
                              </div>
                            )}
                          </div>
                        )}

                        {/* STAGE 7: VERSIONED MAPPING CREATED */}
                        {st.stage === 7 && (
                          <div className="stage-data-grid">
                            <InspectorItem
                              label="SCHEMA DEFINITION FILE"
                              value={st.details.file || 'Not generated yet'}
                              mono
                            />
                            <InspectorItem label="VERSION" value={st.details.version || '1.0.0'} />
                            <InspectorItem label="DEPLOYMENT NOTE" value={st.details.note} />
                          </div>
                        )}

                        {/* STAGE 8: DETERMINISTIC PROCESSING ACTIVATED */}
                        {st.stage === 8 && (
                          <div className="stage-data-grid">
                            <InspectorItem
                              label="PIPELINE STATUS"
                              value={
                                st.details.validation_pass
                                  ? 'DETERMINISTIC VALIDATION PASS'
                                  : 'AWAITING APPROVAL ACTIVATION'
                              }
                            />
                            <InspectorItem label="RUNTIME LATENCY" value={st.details.ai_latency} />
                            {st.details.event_id && (
                              <InspectorItem label="CANONICAL TRACE ID" value={st.details.event_id} mono />
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </section>
        )}

        {/* VIEW 3: ACTIVE DEVICE DISCOVERY (ACTIVE SCANNER) */}
        {activeTab === 'scanner' && (
          <section className="scanner-view">
            <div className="view-hero">
              <div>
                <div className="eyebrow">
                  <Radio size={14} />
                  PERIMETER RECONNAISSANCE
                </div>
                <h1>Authorized Host Device Discovery</h1>
                <p>
                  Perform authorized local asset identification through host OS capabilities. Discovered
                  nodes are immediately piped into the ULPF normalization pipeline as cryptographic security events.
                </p>
              </div>

              <div className="airgap-pill" style={{ marginTop: '10px' }}>
                <ShieldCheck size={14} />
                AUTHORIZED HOST CAPABILITY ONLY
              </div>
            </div>

            {/* ARCHITECTURE FLOW BANNER */}
            <div className="arch-flow-card">
              <span style={{ fontSize: '11px', color: '#64748b', marginRight: '6px' }}>ARCHITECTURE:</span>
              <div className="arch-flow-node">Frontend Dashboard</div>
              <ChevronRight size={14} />
              <div className="arch-flow-node">Backend Scanner API</div>
              <ChevronRight size={14} />
              <div className="arch-flow-node">Local OS Authorized Capability</div>
              <ChevronRight size={14} />
              <div className="arch-flow-node">Discovered Devices</div>
              <ChevronRight size={14} />
              <div className="arch-flow-node">ULPF Event Generation</div>
              <ChevronRight size={14} />
              <div className="arch-flow-node">Normalization Pipeline</div>
            </div>

            {/* HONEST OS / HARDWARE CAPABILITIES CARDS */}
            <div className="caps-grid">
              <div className="cap-card">
                <div>
                  <div className="cap-card-header">
                    <div className="cap-card-title">
                      <Network size={16} />
                      LAN DISCOVERY
                    </div>
                    <span className="cap-status-pill avail">AVAILABLE</span>
                  </div>
                  <p className="cap-desc">
                    {scannerCaps?.lan?.details || 'Local ARP cache neighbor inspection and NetBIOS/DNS resolution.'}
                  </p>
                </div>
                <small style={{ color: '#4a5568', marginTop: '10px', fontSize: '10px', fontFamily: 'monospace' }}>
                  {scannerCaps?.lan?.method || 'arp -a & socket inspection'}
                </small>
              </div>

              <div className="cap-card">
                <div>
                  <div className="cap-card-header">
                    <div className="cap-card-title">
                      <Wifi size={16} />
                      WI-FI DISCOVERY
                    </div>
                    <span
                      className={`cap-status-pill ${
                        scannerCaps?.wifi?.supported ? 'avail' : 'unavail'
                      }`}
                    >
                      {scannerCaps?.wifi?.supported ? 'AVAILABLE' : 'UNSUPPORTED'}
                    </span>
                  </div>
                  <p className="cap-desc">
                    {scannerCaps?.wifi?.supported
                      ? `Active 802.11 adapter: ${scannerCaps.wifi.adapter || 'WLAN'}. Connected BSSID and beacon query.`
                      : scannerCaps?.wifi?.reason || 'No active Wi-Fi adapter detected on this host.'}
                  </p>
                </div>
                <small style={{ color: '#4a5568', marginTop: '10px', fontSize: '10px', fontFamily: 'monospace' }}>
                  {scannerCaps?.wifi?.method || 'Windows WLAN Subsystem'}
                </small>
              </div>

              <div className="cap-card">
                <div>
                  <div className="cap-card-header">
                    <div className="cap-card-title">
                      <Bluetooth size={16} />
                      BLUETOOTH DISCOVERY
                    </div>
                    <span
                      className={`cap-status-pill ${
                        scannerCaps?.bluetooth?.supported ? 'avail' : 'unavail'
                      }`}
                    >
                      {scannerCaps?.bluetooth?.supported ? 'AVAILABLE' : 'UNSUPPORTED'}
                    </span>
                  </div>
                  <p className="cap-desc">
                    {scannerCaps?.bluetooth?.supported
                      ? 'Local Bluetooth PnP controller and nearby/paired endpoint detection.'
                      : scannerCaps?.bluetooth?.reason || 'No active Bluetooth controller in host subsystem.'}
                  </p>
                </div>
                <small style={{ color: '#4a5568', marginTop: '10px', fontSize: '10px', fontFamily: 'monospace' }}>
                  {scannerCaps?.bluetooth?.method || 'Windows Bluetooth PnP Subsystem'}
                </small>
              </div>
            </div>

            {/* SCAN CONTROLS BAR */}
            <div className="scan-controls-bar">
              <div className="scan-options-row">
                <label className="scan-option-label">
                  <input
                    type="checkbox"
                    checked={scanLan}
                    onChange={(e) => setScanLan(e.target.checked)}
                  />
                  <span>LAN Discovery</span>
                </label>

                <label className="scan-option-label">
                  <input
                    type="checkbox"
                    checked={scanWifi}
                    disabled={!scannerCaps?.wifi?.supported}
                    onChange={(e) => setScanWifi(e.target.checked)}
                  />
                  <span>Wi-Fi Discovery</span>
                </label>

                <label className="scan-option-label">
                  <input
                    type="checkbox"
                    checked={scanBluetooth}
                    disabled={!scannerCaps?.bluetooth?.supported}
                    onChange={(e) => setScanBluetooth(e.target.checked)}
                  />
                  <span>Bluetooth Discovery</span>
                </label>

                <label className="scan-option-label" style={{ marginLeft: '12px', color: '#55d992' }}>
                  <input
                    type="checkbox"
                    checked={ingestToUlpf}
                    onChange={(e) => setIngestToUlpf(e.target.checked)}
                  />
                  <span>Normalize & Ingest to ULPF Database</span>
                </label>
              </div>

              <button className="btn-run-scan" onClick={handleRunScan} disabled={scannerLoading}>
                {scannerLoading ? (
                  <>
                    <RefreshCw size={16} className="spin-icon" />
                    <span>SCANNING HOST OS...</span>
                  </>
                ) : (
                  <>
                    <Search size={16} />
                    <span>RUN AUTHORIZED DISCOVERY</span>
                  </>
                )}
              </button>
            </div>

            {/* SCAN SUMMARY PILLS */}
            {scanSummary && (
              <div className="results-summary-row" style={{ margin: 0 }}>
                <div className="summary-stat-pill valid">
                  <CheckCircle2 size={13} />
                  <span>TOTAL NODES: {scanSummary.total_devices}</span>
                </div>
                <div className="summary-stat-pill assisted">
                  <Clock size={13} />
                  <span>NEW IN THIS SCAN: {scanSummary.new_devices}</span>
                </div>
                <div className="summary-stat-pill valid">
                  <Database size={13} />
                  <span>ULPF EVENTS INGESTED: {scanSummary.ulpf_events_generated}</span>
                </div>
              </div>
            )}

            {/* DISCOVERED DEVICES TABLE */}
            <div className="panel devices-panel">
              <PanelHeader
                icon={<Radio size={18} />}
                title="DISCOVERED PERIMETER DEVICES"
                action={`${scannerDevices.length} IDENTIFIED`}
              />

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>DEVICE NAME / HOSTNAME</th>
                      <th>IP ADDRESS</th>
                      <th>HARDWARE IDENTIFIER</th>
                      <th>DISCOVERY TYPE</th>
                      <th>FIRST SEEN</th>
                      <th>LAST SEEN</th>
                      <th>STATUS</th>
                      <th>ULPF TRACE</th>
                    </tr>
                  </thead>

                  <tbody>
                    {scannerDevices.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="empty-state">
                          No devices discovered yet. Click "Run Authorized Discovery" above to begin.
                        </td>
                      </tr>
                    ) : (
                      scannerDevices.map((dev) => (
                        <tr key={dev.id} className="event-row">
                          <td>
                            <strong style={{ color: '#edf2f9' }}>{dev.name}</strong>
                          </td>

                          <td>
                            <span style={{ fontFamily: 'monospace', color: dev.ip ? '#8ab4f8' : '#64748b' }}>
                              {dev.ip || '—'}
                            </span>
                          </td>

                          <td>
                            <span style={{ fontFamily: 'monospace', color: dev.hardware_id ? '#a7f3d0' : '#64748b' }}>
                              {dev.hardware_id || '—'}
                            </span>
                          </td>

                          <td>
                            <span className={`discovery-type-pill ${dev.discovery_type}`}>
                              {dev.discovery_type === 'lan' && <Network size={11} />}
                              {dev.discovery_type === 'wifi' && <Wifi size={11} />}
                              {dev.discovery_type === 'bluetooth' && <Bluetooth size={11} />}
                              {dev.discovery_type.toUpperCase()}
                            </span>
                          </td>

                          <td>
                            <small style={{ color: '#718096', fontFamily: 'monospace' }}>
                              {new Date(dev.first_seen).toLocaleTimeString()}
                            </small>
                          </td>

                          <td>
                            <small style={{ color: '#718096', fontFamily: 'monospace' }}>
                              {new Date(dev.last_seen).toLocaleTimeString()}
                            </small>
                          </td>

                          <td>
                            <select
                              className="status-dropdown"
                              value={dev.status}
                              onChange={(e) => handleUpdateDeviceStatus(dev.id, e.target.value)}
                            >
                              <option value="known">Known</option>
                              <option value="new">New</option>
                              <option value="unknown">Unknown</option>
                            </select>
                          </td>

                          <td>
                            {dev.event_id ? (
                              <button
                                className="ulpf-trace-btn"
                                onClick={() => inspectEventById(dev.event_id!)}
                                title="Inspect canonical normalized event"
                              >
                                <Fingerprint size={12} />
                                {dev.event_id.slice(0, 8)}
                              </button>
                            ) : (
                              <span style={{ color: '#4a5568' }}>—</span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        )}

        {/* FOOTER */}
        <footer>
          <span>ULPF v1.0.0</span>
          <span>•</span>
          <span>CYBERSECURITY CONTROL PLANE</span>
          <span>•</span>
          <span>AIR-GAPPED DEPLOYMENT GUARANTEED</span>
        </footer>

        {/* FORENSIC EVENT INSPECTOR MODAL */}
        {selectedEvent && (
          <div className="inspector-overlay" onClick={() => setSelectedEvent(null)}>
            <div className="event-inspector" onClick={(e) => e.stopPropagation()}>
              <div className="inspector-header">
                <div>
                  <div className="eyebrow">
                    <Fingerprint size={14} />
                    FORENSIC EVENT INSPECTOR
                  </div>

                  <h2>Event {selectedEvent.id.slice(0, 8)}</h2>

                  <p>Complete forensic provenance and normalization trace.</p>
                </div>

                <button
                  className="inspector-close"
                  onClick={() => setSelectedEvent(null)}
                  aria-label="Close inspector"
                >
                  <X size={20} />
                </button>
              </div>

              <div className="inspector-content">
                {/* OVERVIEW */}
                <section className="inspector-section">
                  <div className="inspector-section-title">
                    <Activity size={16} />
                    EVENT OVERVIEW
                  </div>

                  <div className="inspector-grid">
                    <InspectorItem label="EVENT TYPE" value={selectedEvent.event_type ?? '—'} />
                    <InspectorItem label="ACTION" value={selectedEvent.action ?? '—'} />
                    <InspectorItem
                      label="SEVERITY"
                      value={selectedEvent.severity !== null ? String(selectedEvent.severity) : '—'}
                    />
                    <InspectorItem label="PROTOCOL" value={selectedEvent.protocol ?? '—'} />
                    <InspectorItem label="SOURCE FORMAT" value={selectedEvent.source_format ?? '—'} />
                    <InspectorItem label="PROCESSING MODE" value={selectedEvent.processing_mode ?? '—'} />
                  </div>
                </section>

                {/* NETWORK */}
                <section className="inspector-section">
                  <div className="inspector-section-title">
                    <Network size={16} />
                    NETWORK FLOW
                  </div>

                  <div className="network-inspector">
                    <div className="network-node">
                      <span>SOURCE</span>
                      <strong>{selectedEvent.source?.ip ?? '—'}</strong>
                      <small>Port {selectedEvent.source?.port ?? '—'}</small>
                    </div>

                    <ChevronRight size={22} />

                    <div className="network-node">
                      <span>DESTINATION</span>
                      <strong>{selectedEvent.destination?.ip ?? '—'}</strong>
                      <small>Port {selectedEvent.destination?.port ?? '—'}</small>
                    </div>
                  </div>
                </section>

                {/* PARSER AND MAPPING */}
                <section className="inspector-section">
                  <div className="inspector-section-title">
                    <Layers3 size={16} />
                    NORMALIZATION METADATA
                  </div>

                  <div className="inspector-grid">
                    <InspectorItem label="PARSER" value={selectedEvent.parser?.name ?? '—'} />
                    <InspectorItem label="PARSER VERSION" value={selectedEvent.parser?.version ?? '—'} />
                    <InspectorItem label="MAPPING" value={selectedEvent.mapping?.id ?? '—'} />
                    <InspectorItem label="MAPPING VERSION" value={selectedEvent.mapping?.version ?? '—'} />
                    <InspectorItem
                      label="NORMALIZATION STATUS"
                      value={selectedEvent.normalization_status ?? '—'}
                    />
                    <InspectorItem label="VALIDATION" value={selectedEvent.valid ? 'PASS' : 'FAIL'} />
                  </div>
                </section>

                {/* RAW PAYLOAD */}
                <section className="inspector-section">
                  <div className="inspector-section-title">
                    <Terminal size={16} />
                    RAW EVENT PAYLOAD
                  </div>

                  <pre className="code-viewer">{formatPayload(selectedEvent.raw_payload)}</pre>
                </section>

                {/* CANONICAL EVENT */}
                <section className="inspector-section">
                  <div className="inspector-section-title">
                    <FileJson size={16} />
                    CANONICAL NORMALIZED EVENT
                  </div>

                  <pre className="code-viewer">
                    {JSON.stringify(selectedEvent.normalized_event, null, 2)}
                  </pre>
                </section>

                {/* FORENSIC PROVENANCE */}
                <section className="inspector-section">
                  <div className="inspector-section-title">
                    <Fingerprint size={16} />
                    FORENSIC PROVENANCE
                  </div>

                  <div className="provenance-grid">
                    <InspectorItem
                      label="SHA-256 RAW HASH"
                      value={selectedEvent.raw_event_hash ?? '—'}
                      mono
                    />
                    <InspectorItem label="TRACE ID" value={selectedEvent.trace_id ?? '—'} mono />
                    <InspectorItem label="COLLECTOR ID" value={selectedEvent.collector_id ?? '—'} />
                    <InspectorItem label="EVENT ID" value={selectedEvent.id} mono />
                  </div>
                </section>
              </div>
            </div>
          </div>
        )}

        {/* LOG UPLOAD MODAL */}
        {uploadModalOpen && (
          <div className="upload-modal-overlay" onClick={() => setUploadModalOpen(false)}>
            <div className="upload-modal" onClick={(e) => e.stopPropagation()}>
              <div className="upload-modal-header">
                <div>
                  <h2>Upload Log / Perimeter Ingestion</h2>
                  <p>Submit .log, .txt, or .json files into the deterministic ULPF processing pipeline.</p>
                </div>

                <button className="modal-close-btn" onClick={() => setUploadModalOpen(false)}>
                  <X size={18} />
                </button>
              </div>

              <div className="upload-modal-body">
                <div className="upload-tabs">
                  <button
                    className={`upload-tab-btn ${uploadTab === 'file' ? 'active' : ''}`}
                    onClick={() => setUploadTab('file')}
                  >
                    <FileText size={14} />
                    FILE UPLOAD (.log, .txt, .json)
                  </button>

                  <button
                    className={`upload-tab-btn ${uploadTab === 'paste' ? 'active' : ''}`}
                    onClick={() => setUploadTab('paste')}
                  >
                    <Terminal size={14} />
                    PASTE RAW PAYLOAD
                  </button>
                </div>

                {uploadTab === 'file' ? (
                  <div>
                    <input
                      type="file"
                      ref={fileInputRef}
                      accept=".log,.txt,.json"
                      style={{ display: 'none' }}
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setUploadFile(e.target.files[0])
                        }
                      }}
                    />

                    <div
                      className={`dropzone-box ${dragOver ? 'drag-over' : ''}`}
                      onClick={() => fileInputRef.current?.click()}
                      onDragOver={(e) => {
                        e.preventDefault()
                        setDragOver(true)
                      }}
                      onDragLeave={() => setDragOver(false)}
                      onDrop={(e) => {
                        e.preventDefault()
                        setDragOver(false)
                        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                          setUploadFile(e.dataTransfer.files[0])
                        }
                      }}
                    >
                      <div className="dropzone-icon">
                        <Upload size={24} />
                      </div>
                      <div className="dropzone-title">
                        Click or drag log file to ingest
                      </div>
                      <div className="dropzone-sub">
                        Supports single-event or multi-line .log, .txt, and structured .json files
                      </div>

                      {uploadFile && (
                        <div className="selected-file-pill">
                          <FileText size={14} />
                          <span>{uploadFile.name} ({(uploadFile.size / 1024).toFixed(1)} KB)</span>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div>
                    <textarea
                      className="log-textarea"
                      placeholder="Paste raw log lines or JSON object here... (e.g. 2026-09-06T10:00:00Z FW01 ALLOW SRC=10.10.10.25 DST=172.16.1.20 ...)"
                      value={uploadText}
                      onChange={(e) => setUploadText(e.target.value)}
                    />
                  </div>
                )}

                <div className="upload-actions">
                  <div className="airgap-callout">
                    <Lock size={13} />
                    100% Local Ingestion — No cloud transmission
                  </div>

                  <button
                    className="btn-process-submit"
                    onClick={handleProcessUpload}
                    disabled={uploadLoading || (uploadTab === 'file' ? !uploadFile : !uploadText.trim())}
                  >
                    {uploadLoading ? (
                      <>
                        <RefreshCw size={14} className="spin-icon" />
                        <span>PROCESSING...</span>
                      </>
                    ) : (
                      <>
                        <Play size={14} />
                        <span>INGEST & PROCESS</span>
                      </>
                    )}
                  </button>
                </div>

                {/* INGESTION RESULTS SECTION */}
                {uploadResult && (
                  <div className="upload-results-panel">
                    <div className="results-summary-row">
                      <div className="summary-stat-pill valid">
                        <CheckCircle2 size={13} />
                        <span>VALID (PASS): {uploadResult.valid_count}</span>
                      </div>

                      {uploadResult.invalid_count > 0 && (
                        <div className="summary-stat-pill invalid">
                          <XCircle size={13} />
                          <span>INVALID (FAIL): {uploadResult.invalid_count}</span>
                        </div>
                      )}

                      {uploadResult.assisted_count > 0 && (
                        <div className="summary-stat-pill assisted">
                          <Clock size={13} />
                          <span>ASSISTED (PENDING MAPPING): {uploadResult.assisted_count}</span>
                        </div>
                      )}
                    </div>

                    <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                      {uploadResult.items?.map((item: any, idx: number) => (
                        <div key={idx} className="result-item-card">
                          <div className="result-item-main">
                            <div className="result-item-preview">{item.preview}</div>
                            <div className="result-item-meta">
                              <span>Parser: {item.parser || 'None'}</span>
                              <span>Mapping: {item.mapping_id || 'None'}</span>
                              {item.reason && <span style={{ color: '#e9a35a' }}>Reason: {item.reason}</span>}
                            </div>
                          </div>

                          <div>
                            {item.valid ? (
                              <span className="valid" style={{ fontSize: '11px' }}>
                                <CheckCircle2 size={13} /> PASS
                              </span>
                            ) : item.mode === 'assisted' ? (
                              <button
                                className="nav-tab active"
                                style={{ padding: '4px 8px', fontSize: '10px' }}
                                onClick={() => {
                                  setUploadModalOpen(false)
                                  setActiveTab('timeline')
                                  setTimelineInput(item.preview)
                                  handleRunTimelineAnalysis(item.preview)
                                }}
                              >
                                Open in Timeline &rarr;
                              </button>
                            ) : (
                              <span className="invalid" style={{ fontSize: '11px' }}>
                                <AlertTriangle size={13} /> FAIL
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

function MetricCard({
  icon,
  label,
  value,
  detail,
  accent,
}: {
  icon: React.ReactNode
  label: string
  value: string | number
  detail: string
  accent: string
}) {
  return (
    <div className={`metric-card ${accent}`}>
      <div className="metric-top">
        <div className="metric-icon">{icon}</div>
        <span>{label}</span>
      </div>

      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  )
}

function PanelHeader({
  icon,
  title,
  action,
}: {
  icon: React.ReactNode
  title: string
  action: string
}) {
  return (
    <div className="panel-header">
      <div className="panel-title">
        {icon}
        <span>{title}</span>
      </div>

      <span className="panel-action">{action}</span>
    </div>
  )
}

function PipelineNode({
  icon,
  title,
  subtitle,
  status,
}: {
  icon: React.ReactNode
  title: string
  subtitle: string
  status: string
}) {
  return (
    <div className="pipeline-node">
      <div className="pipeline-icon">{icon}</div>
      <strong>{title}</strong>
      <span>{subtitle}</span>
      <small>
        <span className="status-dot green" />
        {status}
      </small>
    </div>
  )
}

function PipelineArrow() {
  return (
    <div className="pipeline-arrow">
      <ChevronRight size={18} />
    </div>
  )
}

function HealthRow({
  name,
  value,
}: {
  name: string
  value: string
}) {
  return (
    <div className="health-row">
      <div>
        <span className="status-dot green" />
        <span>{name}</span>
      </div>

      <strong>{value}</strong>
    </div>
  )
}

function formatPayload(payload: string) {
  try {
    return JSON.stringify(JSON.parse(payload), null, 2)
  } catch {
    return payload
  }
}

function InspectorItem({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="inspector-item">
      <span>{label}</span>
      <strong className={mono ? 'mono-value' : ''}>{value}</strong>
    </div>
  )
}

export default App