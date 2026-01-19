import React, { useEffect, useRef, useState, useMemo } from 'react';
import mermaid from 'mermaid';

// Track if mermaid is initialized
let mermaidInitialized = false;

const initMermaid = () => {
  if (mermaidInitialized) return;

  mermaid.initialize({
    startOnLoad: false,
    theme: 'dark',
    securityLevel: 'loose',
    themeVariables: {
      primaryColor: '#8b5cf6',
      primaryTextColor: '#f8fafc',
      primaryBorderColor: '#8b5cf6',
      lineColor: '#06b6d4',
      secondaryColor: '#1e293b',
      tertiaryColor: '#0f172a',
      background: '#020617',
      mainBkg: '#0f172a',
      secondBkg: '#1e293b',
      noteBkgColor: 'rgba(139, 92, 246, 0.2)',
      noteTextColor: '#f8fafc',
      noteBorderColor: '#8b5cf6',
      actorBkg: '#1e293b',
      actorBorder: '#8b5cf6',
      actorTextColor: '#f8fafc',
      actorLineColor: '#64748b',
      signalColor: '#f8fafc',
      signalTextColor: '#f8fafc',
      labelBoxBkgColor: '#1e293b',
      labelBoxBorderColor: '#8b5cf6',
      labelTextColor: '#f8fafc',
    },
    sequence: {
      diagramMarginX: 20,
      diagramMarginY: 20,
      actorMargin: 80,
      width: 180,
      height: 50,
      boxMargin: 10,
      boxTextMargin: 5,
      noteMargin: 10,
      messageMargin: 40,
      mirrorActors: false,
      bottomMarginAdj: 10,
      useMaxWidth: true,
      rightAngles: false,
      showSequenceNumbers: true,
    }
  });

  mermaidInitialized = true;
};

// Protocol colors for styling
const PROTOCOL_COLORS = {
  'GTP': '#10b981',
  'SIP': '#ec4899',
  'Diameter': '#f59e0b',
  'PFCP': '#8b5cf6',
  'NGAP': '#a78bfa',
  'S1-AP': '#06b6d4',
  'DNS': '#64748b',
  'HTTP': '#6366f1',
  'RADIUS': '#14b8a6',
  'default': '#94a3b8'
};

function FlowDiagram({ messageSequence = [], maxMessages = 50 }) {
  const containerRef = useRef(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [viewMode, setViewMode] = useState('sequence'); // 'sequence' or 'timeline'
  const [selectedProtocol, setSelectedProtocol] = useState('all');
  const renderIdRef = useRef(0);

  // Initialize mermaid on mount
  useEffect(() => {
    initMermaid();
  }, []);

  // Get unique endpoints from messages
  const endpoints = useMemo(() => {
    const ips = new Set();
    messageSequence.forEach(msg => {
      if (msg.src_ip) ips.add(msg.src_ip);
      if (msg.dst_ip) ips.add(msg.dst_ip);
    });
    return Array.from(ips).slice(0, 8); // Limit to 8 endpoints for readability
  }, [messageSequence]);

  // Get unique protocols
  const protocols = useMemo(() => {
    const protos = new Set();
    messageSequence.forEach(msg => {
      if (msg.protocol) protos.add(msg.protocol.split('/')[0]);
    });
    return ['all', ...Array.from(protos)];
  }, [messageSequence]);

  // Filter and limit messages
  const filteredMessages = useMemo(() => {
    let msgs = messageSequence;

    // Filter by protocol if selected
    if (selectedProtocol !== 'all') {
      msgs = msgs.filter(m => m.protocol && m.protocol.includes(selectedProtocol));
    }

    // Limit messages and filter to known endpoints
    return msgs
      .filter(m => endpoints.includes(m.src_ip) && endpoints.includes(m.dst_ip))
      .slice(0, maxMessages);
  }, [messageSequence, selectedProtocol, endpoints, maxMessages]);

  // Create endpoint alias map for shorter names
  const endpointAliases = useMemo(() => {
    const aliases = {};
    endpoints.forEach((ip, idx) => {
      // Create short alias from last octet or index
      const parts = ip.split('.');
      if (parts.length === 4) {
        aliases[ip] = `Node_${parts[3]}`;
      } else {
        aliases[ip] = `Node_${idx + 1}`;
      }
    });
    return aliases;
  }, [endpoints]);

  // Generate Mermaid sequence diagram code
  const generateMermaidCode = useMemo(() => {
    if (filteredMessages.length === 0) return null;

    let code = 'sequenceDiagram\n';

    // Declare participants (endpoints) with aliases
    endpoints.forEach(ip => {
      const alias = endpointAliases[ip];
      code += `    participant ${alias} as ${ip}\n`;
    });

    code += '\n';

    // Add messages
    filteredMessages.forEach((msg, idx) => {
      const srcAlias = endpointAliases[msg.src_ip];
      const dstAlias = endpointAliases[msg.dst_ip];

      if (!srcAlias || !dstAlias) return;

      // Create message label
      let label = msg.info || msg.protocol || 'Data';
      // Sanitize label for Mermaid (remove special chars)
      // Ensure label is a string before calling replace
      label = String(label || '').replace(/[<>:;]/g, ' ').substring(0, 40);

      // Determine arrow style based on protocol
      const proto = msg.protocol || '';
      let arrowStyle = '->>';  // Default async arrow

      if (proto.includes('SIP') && String(msg.info || '').includes('INVITE')) {
        arrowStyle = '->>';
      } else if (proto.includes('SIP') && (String(msg.info || '').includes('200') || String(msg.info || '').includes('ACK'))) {
        arrowStyle = '-->>';
      }

      code += `    ${srcAlias}${arrowStyle}${dstAlias}: ${label}\n`;

      // Add notes for important messages (limit to avoid clutter)
      if (idx < 5 && (proto.includes('GTP') || proto.includes('SIP') || proto.includes('Diameter'))) {
        if (msg.gtp_teid) {
          code += `    Note right of ${dstAlias}: TEID: ${msg.gtp_teid}\n`;
        }
      }
    });

    return code;
  }, [filteredMessages, endpoints, endpointAliases]);

  // Render Mermaid diagram
  useEffect(() => {
    if (!generateMermaidCode || !containerRef.current || viewMode !== 'sequence') {
      return;
    }

    const renderDiagram = async () => {
      try {
        setError(null);
        setIsLoading(true);

        // Increment render ID for unique diagram ID
        renderIdRef.current += 1;
        const diagramId = `sequence-diagram-${renderIdRef.current}`;

        // Remove any existing diagram elements
        const existingDiagram = document.getElementById(diagramId);
        if (existingDiagram) {
          existingDiagram.remove();
        }

        // Render the diagram
        const { svg } = await mermaid.render(diagramId, generateMermaidCode);

        if (containerRef.current) {
          containerRef.current.innerHTML = svg;

          // Apply custom styling to SVG
          const svgEl = containerRef.current.querySelector('svg');
          if (svgEl) {
            svgEl.style.maxWidth = '100%';
            svgEl.style.height = 'auto';
            svgEl.style.minHeight = '400px';
          }
        }

        setIsLoading(false);
      } catch (err) {
        console.error('Mermaid render error:', err);
        setError(`Failed to render diagram: ${err.message || 'Unknown error'}`);
        setIsLoading(false);
      }
    };

    // Small delay to ensure DOM is ready
    const timeoutId = setTimeout(renderDiagram, 100);

    return () => clearTimeout(timeoutId);
  }, [generateMermaidCode, viewMode]);

  // Timeline view component
  const TimelineView = () => (
    <div className="timeline-container">
      {filteredMessages.map((msg, idx) => {
        const proto = msg.protocol?.split('/')[0] || 'default';
        const color = PROTOCOL_COLORS[proto] || PROTOCOL_COLORS.default;

        return (
          <div key={idx} className="timeline-item" style={{ '--accent': color }}>
            <div className="timeline-dot" />
            <div className="timeline-content">
              <div className="timeline-header">
                <span className="timeline-protocol" style={{ backgroundColor: `${color}20`, color }}>
                  {msg.protocol || 'Unknown'}
                </span>
                <span className="timeline-time">
                  +{((msg.timestamp - filteredMessages[0]?.timestamp) * 1000).toFixed(1)}ms
                </span>
              </div>
              <div className="timeline-endpoints">
                <span className="timeline-src">{msg.src_ip}:{msg.src_port}</span>
                <span className="timeline-arrow">→</span>
                <span className="timeline-dst">{msg.dst_ip}:{msg.dst_port}</span>
              </div>
              {msg.info && (
                <div className="timeline-info">{msg.info}</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );

  if (!messageSequence || messageSequence.length === 0) {
    return (
      <div className="flow-diagram-container">
        <div className="flow-diagram-empty">
          <span className="empty-icon">📊</span>
          <p>No message sequence data available</p>
          <span className="empty-hint">Sequence diagrams require captured protocol messages</span>
        </div>
      </div>
    );
  }

  return (
    <div className="flow-diagram-container">
      <div className="flow-diagram-header">
        <h3>🔀 Protocol Sequence Diagram</h3>
        <div className="flow-diagram-controls">
          <div className="view-toggle">
            <button
              className={`toggle-btn ${viewMode === 'sequence' ? 'active' : ''}`}
              onClick={() => setViewMode('sequence')}
            >
              Ladder
            </button>
            <button
              className={`toggle-btn ${viewMode === 'timeline' ? 'active' : ''}`}
              onClick={() => setViewMode('timeline')}
            >
              Timeline
            </button>
          </div>

          <select
            className="protocol-filter"
            value={selectedProtocol}
            onChange={(e) => setSelectedProtocol(e.target.value)}
          >
            {protocols.map(proto => (
              <option key={proto} value={proto}>
                {proto === 'all' ? 'All Protocols' : proto}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="flow-diagram-stats">
        <div className="stat-item">
          <span className="stat-value">{endpoints.length}</span>
          <span className="stat-label">Endpoints</span>
        </div>
        <div className="stat-item">
          <span className="stat-value">{filteredMessages.length}</span>
          <span className="stat-label">Messages</span>
        </div>
        <div className="stat-item">
          <span className="stat-value">{protocols.length - 1}</span>
          <span className="stat-label">Protocols</span>
        </div>
      </div>

      {error ? (
        <div className="flow-diagram-error">
          <span>⚠️</span> {error}
        </div>
      ) : viewMode === 'sequence' ? (
        <div className="mermaid-wrapper">
          {isLoading && (
            <div className="diagram-loading">
              <div className="spinner-small" />
              <span>Rendering diagram...</span>
            </div>
          )}
          <div
            className="mermaid-container"
            ref={containerRef}
            style={{ display: isLoading ? 'none' : 'flex' }}
          />
        </div>
      ) : (
        <TimelineView />
      )}

      <div className="flow-diagram-legend">
        <span className="legend-title">Protocol Colors:</span>
        <div className="legend-items">
          {Object.entries(PROTOCOL_COLORS).filter(([k]) => k !== 'default').map(([proto, color]) => (
            <div key={proto} className="legend-item">
              <span className="legend-dot" style={{ backgroundColor: color }} />
              <span className="legend-label">{proto}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default FlowDiagram;
