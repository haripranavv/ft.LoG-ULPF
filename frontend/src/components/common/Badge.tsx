import React from 'react';

interface BadgeProps {
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info' | 'purple' | 'outline';
  size?: 'sm' | 'md';
  children: React.ReactNode;
  icon?: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({
  variant = 'default',
  size = 'md',
  children,
  icon,
}) => {
  const variantStyles: Record<string, React.CSSProperties> = {
    default: {
      backgroundColor: 'rgba(255, 255, 255, 0.08)',
      color: '#d1d5db',
      border: '1px solid rgba(255, 255, 255, 0.1)',
    },
    success: {
      backgroundColor: 'rgba(16, 185, 129, 0.12)',
      color: '#34d399',
      border: '1px solid rgba(16, 185, 129, 0.25)',
    },
    warning: {
      backgroundColor: 'rgba(245, 158, 11, 0.12)',
      color: '#fbbf24',
      border: '1px solid rgba(245, 158, 11, 0.25)',
    },
    danger: {
      backgroundColor: 'rgba(239, 68, 68, 0.12)',
      color: '#f87171',
      border: '1px solid rgba(239, 68, 68, 0.25)',
    },
    info: {
      backgroundColor: 'rgba(59, 130, 246, 0.12)',
      color: '#60a5fa',
      border: '1px solid rgba(59, 130, 246, 0.25)',
    },
    purple: {
      backgroundColor: 'rgba(139, 92, 246, 0.12)',
      color: '#a78bfa',
      border: '1px solid rgba(139, 92, 246, 0.25)',
    },
    outline: {
      backgroundColor: 'transparent',
      color: '#9ca3af',
      border: '1px solid var(--border-color)',
    },
  };

  const isSmall = size === 'sm';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: isSmall ? '1px 6px' : '2px 8px',
        fontSize: isSmall ? '10.5px' : '11.5px',
        fontWeight: 500,
        borderRadius: '9999px',
        whiteSpace: 'nowrap',
        ...variantStyles[variant],
      }}
    >
      {icon}
      {children}
    </span>
  );
};
