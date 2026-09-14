import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface JsonViewerProps {
  data: any;
  maxHeight?: string;
}

export const JsonViewer: React.FC<JsonViewerProps> = ({ data, maxHeight = '450px' }) => {
  const [copied, setCopied] = useState(false);

  const formattedJson = typeof data === 'string'
    ? data
    : JSON.stringify(data, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(formattedJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div
      style={{
        position: 'relative',
        backgroundColor: 'var(--bg-app)',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-md)',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          padding: '6px 10px',
          borderBottom: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-subtle)',
        }}
      >
        <button
          onClick={handleCopy}
          className="btn btn-secondary btn-sm"
          style={{ padding: '2px 8px', fontSize: '11px' }}
        >
          {copied ? <Check size={13} color="var(--success-text)" /> : <Copy size={13} />}
          {copied ? 'Copied' : 'Copy JSON'}
        </button>
      </div>
      <pre
        style={{
          margin: 0,
          padding: '14px',
          maxHeight,
          overflowY: 'auto',
          color: '#e5e7eb',
          fontSize: '11.5px',
          lineHeight: '1.6',
          fontFamily: 'var(--font-mono)',
        }}
      >
        {formattedJson}
      </pre>
    </div>
  );
};
