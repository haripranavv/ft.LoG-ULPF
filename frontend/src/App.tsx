import React, { useState, useEffect } from 'react';
import { Sidebar, type NavTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewView } from './views/OverviewView';
import { IngestView } from './views/IngestView';
import { DevicesView } from './views/DevicesView';
import { EventsView } from './views/EventsView';
import { MappingsView } from './views/MappingsView';
import { ExportsView } from './views/ExportsView';
import { SettingsView } from './views/SettingsView';
import { LoginView } from './views/LoginView';
import { api, getToken } from './api/client';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');
  const [eventCount, setEventCount] = useState<number>(0);
  const [deviceCount, setDeviceCount] = useState<number>(0);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const isAuthenticated = !!getToken();

  useEffect(() => {
    if (isAuthenticated) {
      refreshCounts();
    }
  }, [isAuthenticated]);

  const refreshCounts = async () => {
    setIsRefreshing(true);
    try {
      const [stats, devices] = await Promise.all([
        api.getStats().catch(() => ({ total_events: 0 })),
        api.listDevices().catch(() => []),
      ]);
      setEventCount(stats.total_events || 0);
      setDeviceCount(devices.length || 0);
    } finally {
      setIsRefreshing(false);
    }
  };

  const titles: Record<NavTab, { title: string; subtitle: string }> = {
    overview: {
      title: 'Platform Overview',
      subtitle: 'Universal Telemetry Ingestion & Normalization Platform',
    },
    ingest: {
      title: 'Log Ingestion',
      subtitle: 'Upload, parse, normalize, and validate raw telemetry',
    },
    devices: {
      title: 'Network Devices & Peripherals',
      subtitle: 'Non-intrusive LAN & Wi-Fi peripheral discovery',
    },
    events: {
      title: 'Canonical Events',
      subtitle: 'Query and inspect cryptographically verified ULPF telemetry events',
    },
    mappings: {
      title: 'Schema Mappings',
      subtitle: 'Deterministic mappings and AI-assisted unknown log inference',
    },
    exports: {
      title: 'Telemetry Exports',
      subtitle: 'Export normalized events to JSONL, Webhooks, or SIEM data lakes',
    },
    settings: {
      title: 'System Settings',
      subtitle: 'Configuration, raw file volume mounts, and local AI status',
    },
  };

  const currentMeta = titles[currentTab] || { title: 'ULPF', subtitle: '' };

  if (!isAuthenticated) {
    return <LoginView />;
  }

  return (
    <div style={{ display: 'flex', width: '100%', height: '100vh', overflow: 'hidden' }}>
      <Sidebar
        currentTab={currentTab}
        onTabChange={(tab) => {
          setCurrentTab(tab);
          refreshCounts();
        }}
        eventCount={eventCount}
        deviceCount={deviceCount}
      />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <Header
          title={currentMeta.title}
          subtitle={currentMeta.subtitle}
          onRefresh={refreshCounts}
          isRefreshing={isRefreshing}
        />

        <main style={{ flex: 1, overflowY: 'auto', padding: '24px 28px', backgroundColor: 'var(--bg-app)' }}>
          {currentTab === 'overview' && <OverviewView onNavigate={setCurrentTab} />}
          {currentTab === 'ingest' && <IngestView />}
          {currentTab === 'devices' && <DevicesView />}
          {currentTab === 'events' && <EventsView />}
          {currentTab === 'mappings' && <MappingsView />}
          {currentTab === 'exports' && <ExportsView />}
          {currentTab === 'settings' && <SettingsView />}
        </main>
      </div>
    </div>
  );
};

export default App;
