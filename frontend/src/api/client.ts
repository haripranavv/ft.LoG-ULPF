export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const getToken = () => localStorage.getItem('ulpf_token');
export const setToken = (token: string) => localStorage.setItem('ulpf_token', token);
export const clearToken = () => localStorage.removeItem('ulpf_token');

async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(options.headers || {});
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const config = {
    ...options,
    headers,
  };
  const res = await fetch(url, config);
  if (res.status === 401) {
    clearToken();
    window.location.reload();
  }
  return res;
}



export interface StatsData {
  total_events: number;
  valid_events: number;
  invalid_events: number;
  source_formats: number;
  mappings: number;
  collectors: number;
}

export interface IngestItemResult {
  index: number;
  preview: string;
  valid: boolean;
  mode: string;
  parser?: string;
  source_format?: string;
  mapping_id?: string;
  event_id?: string;
  trace_id?: string;
  errors?: string[];
  latency_ms?: number;
  ai_assistance?: any;
}

export interface IngestionResponse {
  status: string;
  ingestion_id: string;
  filename: string;
  sha256_hash: string;
  file_size_bytes: number;
  total_events: number;
  valid_count: number;
  invalid_count: number;
  assisted_count: number;
  batch_merkle_root: string;
  detected_format: string;
  parser_used: string;
  processing_time_ms: number;
  storage_path: string;
  items: IngestItemResult[];
}

export interface DeviceItem {
  id: string;
  name: string;
  ip?: string | null;
  ip_address?: string | null;
  mac_address?: string | null;
  hardware_id?: string | null;
  manufacturer?: string | null;
  vendor?: string | null;
  device_type: string;
  device_type_confidence: number;
  discovery_method?: string;
  first_seen: string;
  last_seen: string;
  status: 'known' | 'new' | 'unknown';
  metadata?: Record<string, any>;
  event_id?: string;
  trace_id?: string;
}

export interface NormalizedEventRecord {
  id: string;
  timestamp: string | null;
  event_type: string | null;
  action: string | null;
  severity: number | null;
  source: {
    ip: string | null;
    port: number | null;
  } | null;
  destination: {
    ip: string | null;
    port: number | null;
  } | null;
  protocol: string | null;
  source_format: string | null;
  parser: {
    name: string | null;
    version: string | null;
  } | null;
  mapping: {
    id: string | null;
    version: string | null;
  } | null;
  processing_mode: string | null;
  normalization_status: string | null;
  valid: boolean;
  raw_event_hash: string | null;
  trace_id: string | null;
  collector_id: string | null;
  raw_payload: string;
  normalized_event: Record<string, any>;
  created_at?: string | null;
}

export interface MappingField {
  source_field: string;
  target_field: string;
  confidence: number;
  required?: boolean;
}

export interface MappingDefinitionItem {
  mapping_id: string;
  version: string;
  source_format: string;
  vendor?: string | null;
  product?: string | null;
  fields: MappingField[];
}

export interface ExportJob {
  id: string;
  target_type: string;
  destination?: string;
  status: string;
  event_count: number;
  config?: Record<string, any>;
  error_message?: string | null;
  created_at?: string;
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }
  return res.json();
}

export const api = {
  async login(username: string, password: string): Promise<{ token: string; user: any }> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await handleResponse<{ token: string; user: any }>(res);
    if (data.token) setToken(data.token);
    return data;
  },

  async logout(): Promise<void> {
    await fetchWithAuth(`${API_BASE_URL}/api/auth/logout`, { method: 'POST' });
    clearToken();
  },

  async getMe(): Promise<any> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/auth/me`);
    return handleResponse(res);
  },


  async getHealth(): Promise<{ status: string; service: string }> {
    const res = await fetchWithAuth(`${API_BASE_URL}/health`);
    return handleResponse(res);
  },

  async getStats(): Promise<StatsData> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/stats`);
    return handleResponse(res);
  },

  async uploadFileMultipart(file: File): Promise<IngestionResponse> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetchWithAuth(`${API_BASE_URL}/api/ingest/files`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse(res);
  },

  async uploadFilePayload(filename: string, content: string): Promise<IngestionResponse> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/ingest/payload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, content }),
    });
    return handleResponse(res);
  },

  async listIngestions(limit = 20, offset = 0): Promise<{ total: number; ingestions: any[] }> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/ingest?limit=${limit}&offset=${offset}`);
    return handleResponse(res);
  },

  async listDevices(): Promise<DeviceItem[]> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/devices`);
    return handleResponse(res);
  },

  async runDiscovery(options: { scan_lan?: boolean; scan_wifi?: boolean; scan_bluetooth?: boolean } = {}): Promise<any> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/devices/discover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scan_lan: options.scan_lan ?? true,
        scan_wifi: options.scan_wifi ?? true,
        scan_bluetooth: options.scan_bluetooth ?? false,
        ingest_to_ulpf: true,
      }),
    });
    return handleResponse(res);
  },

  async updateDeviceStatus(deviceId: string, status: string): Promise<DeviceItem> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/devices/${encodeURIComponent(deviceId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    return handleResponse(res);
  },

  async listEvents(params: {
    limit?: number;
    offset?: number;
    search?: string;
    source_format?: string;
    valid?: boolean;
  } = {}): Promise<{ total: number; count: number; events: NormalizedEventRecord[] }> {
    const q = new URLSearchParams();
    if (params.limit) q.set('limit', String(params.limit));
    if (params.offset) q.set('offset', String(params.offset));
    if (params.search) q.set('search', params.search);
    if (params.source_format) q.set('source_format', params.source_format);
    if (params.valid !== undefined) q.set('valid', String(params.valid));

    const res = await fetchWithAuth(`${API_BASE_URL}/api/events?${q.toString()}`);
    return handleResponse(res);
  },

  async getEvent(eventId: string): Promise<NormalizedEventRecord> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/events/${encodeURIComponent(eventId)}`);
    return handleResponse(res);
  },

  async listMappings(): Promise<MappingDefinitionItem[]> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/mappings`);
    return handleResponse(res);
  },

  async approveMapping(mapping: MappingDefinitionItem): Promise<any> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/mappings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(mapping),
    });
    return handleResponse(res);
  },

  async getSampleLogs(): Promise<Array<{ id: string; name: string; category: string; log: string }>> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/mappings/samples`);
    return handleResponse(res);
  },

  async listExports(): Promise<{ supported_targets: string[]; exports: ExportJob[] }> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/exports`);
    return handleResponse(res);
  },

  async triggerExport(payload: {
    target_type: string;
    limit?: number;
    config?: Record<string, any>;
    event_ids?: string[];
  }): Promise<any> {
    const res = await fetchWithAuth(`${API_BASE_URL}/api/exports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return handleResponse(res);
  },

  getDownloadJsonlUrl(limit = 1000): string {
    return `${API_BASE_URL}/api/exports/download?limit=${limit}`;
  },
};
