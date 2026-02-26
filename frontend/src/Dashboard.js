import React, { useState, useMemo, useEffect } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import FlowDiagram from './FlowDiagram';
import MermaidDiagram from './MermaidDiagram';
import ChatPanel from './ChatPanel';

// Colors for charts
const COLORS = ['#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#ec4899', '#6366f1', '#14b8a6'];

// Technology colors
const TECH_COLORS = {
  '5G/NR': '#8b5cf6',
  '5G/SBI': '#a78bfa',
  '4G/LTE': '#06b6d4',
  '3G/UMTS': '#10b981',
  '2G/GSM': '#f59e0b',
  '2G/3G/SS7': '#e17055',
  'VoLTE/VoNR': '#ec4899',
  'VoIP': '#fd79a8',
  'AAA': '#6366f1',
  'Infrastructure': '#64748b',
  'Signaling': '#a78bfa',
  'Unknown': '#94a3b8',
};

// Health status colors
const HEALTH_COLORS = {
  healthy: { bg: 'rgba(16, 185, 129, 0.15)', border: '#10b981', text: '#34d399' },
  warning: { bg: 'rgba(245, 158, 11, 0.15)', border: '#f59e0b', text: '#fbbf24' },
  critical: { bg: 'rgba(239, 68, 68, 0.15)', border: '#ef4444', text: '#f87171' },
};

// Severity badge colors
const SEVERITY_COLORS = {
  info: { bg: 'rgba(6, 182, 212, 0.15)', color: '#22d3ee' },
  warning: { bg: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24' },
  critical: { bg: 'rgba(239, 68, 68, 0.15)', color: '#f87171' },
};

// Main Tab Configuration
const MAIN_TABS = [
  { id: 'analysis', label: '🔍 Analysis', icon: '🔍' },
  { id: 'radio', label: '📡 Radio', icon: '📡' },
  { id: 'statistics', label: '📊 Statistics', icon: '📊' },
  { id: 'voice', label: '📞 Voice & IMS', icon: '📞' },
  { id: 'diagrams', label: '🧬 Diagrams', icon: '🧬' },
  { id: 'flows', label: '🌐 Flows', icon: '🌐' },
];

function Dashboard({ data, jobId, caseId, apiUrl, onNewAnalysis, onIterationUpload }) {
  // Always default to Analysis tab as it contains the LLM Root Cause Analysis
  const initialTab = 'analysis';
  const [mainTab, setMainTab] = useState(initialTab);
  const [visitedTabs, setVisitedTabs] = useState({ [initialTab]: true });

  // Sub-tab states
  const [activeAiTab, setActiveAiTab] = useState('overview');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedFlow, setExpandedFlow] = useState(null);
  const [showDebug, setShowDebug] = useState(false);
  const [showChat, setShowChat] = useState(false);

  // Track visited tabs for lazy loading
  const handleMainTabClick = (tabId) => {
    setMainTab(tabId);
    if (!visitedTabs[tabId]) {
      setVisitedTabs(prev => ({ ...prev, [tabId]: true }));
    }
  };

  // Debug logging
  useEffect(() => {
    console.log("Dashboard received data:", data);
  }, [data]);

  const { flows, root_cause_analysis, summary, protocol_stats, technology_stats, telecom_sessions, message_sequence,
    radio_findings, correlation_report, cross_plane_events, groundhog_summary, datasets } = data;

  // Safe checks for data existence
  if (!flows && !data.flows && !radio_findings) {
    return (
      <div className="error-message">
        <h3>⚠️ Data Structure Error</h3>
        <p>The analysis data appears to be incomplete.</p>
        <pre>{JSON.stringify(data, null, 2)}</pre>
      </div>
    );
  }

  if (!flows && !radio_findings) {
    console.error("Missing flows and radio data");
    return <div className="error-message">Error: No analysis data available</div>;
  }

  // Check if RCA is structured (object) or legacy (string)
  const isStructuredRCA = root_cause_analysis && typeof root_cause_analysis === 'object';
  const rca = isStructuredRCA ? root_cause_analysis : null;

  // Prepare chart data (memoized)
  const protocolChartData = useMemo(() => {
    if (!protocol_stats) return [];
    return Object.entries(protocol_stats)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [protocol_stats]);

  const technologyChartData = useMemo(() => {
    if (!technology_stats) return [];
    return Object.entries(technology_stats)
      .map(([name, value]) => ({ name, value, color: TECH_COLORS[name] || TECH_COLORS['Unknown'] }))
      .sort((a, b) => b.value - a.value);
  }, [technology_stats]);

  const topFlowsData = useMemo(() => {
    return (flows || [])
      .slice(0, 5)
      .map((flow, index) => ({
        name: `Flow ${index + 1}`,
        packets: flow.packet_count,
        bytes: Math.round(flow.total_bytes / 1024),
      }));
  }, [flows]);

  const filteredFlows = useMemo(() => {
    if (!searchTerm) return flows || [];
    const term = searchTerm.toLowerCase();
    return (flows || []).filter(flow =>
      flow.src_ip?.toLowerCase().includes(term) ||
      flow.dst_ip?.toLowerCase().includes(term) ||
      flow.protocol?.toLowerCase().includes(term) ||
      flow.primary_tech?.toLowerCase().includes(term)
    );
  }, [flows, searchTerm]);

  // Helper functions
  const formatBytes = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const formatDuration = (seconds) => {
    if (!seconds || seconds === 0) return '< 1ms';
    if (seconds < 1) return (seconds * 1000).toFixed(1) + ' ms';
    if (seconds < 60) return seconds.toFixed(2) + ' s';
    return (seconds / 60).toFixed(1) + ' min';
  };

  const getProtocolBadgeClass = (protocol) => {
    const p = protocol?.toLowerCase() || '';
    if (p.includes('gtp')) return 'protocol-badge gtp';
    if (p.includes('sip') || p.includes('rtp')) return 'protocol-badge sip';
    if (p.includes('diameter')) return 'protocol-badge diameter';
    if (p.includes('pfcp') || p.includes('ngap')) return 'protocol-badge fiveg';
    if (p.includes('s1-ap') || p.includes('x2-ap')) return 'protocol-badge lte';
    if (p.includes('m3ua') || p.includes('sua')) return 'protocol-badge ss7';
    return 'protocol-badge';
  };

  const getTechBadgeStyle = (tech) => ({
    backgroundColor: TECH_COLORS[tech] || TECH_COLORS['Unknown'],
    color: '#fff',
    padding: '0.2rem 0.5rem',
    borderRadius: '6px',
    fontSize: '0.7rem',
    fontWeight: '600',
    letterSpacing: '0.02em',
  });

  const getHealthColor = (status) => HEALTH_COLORS[status] || HEALTH_COLORS.warning;
  const getSeverityStyle = (severity) => SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;

  // Health Score Ring component
  const HealthScoreRing = ({ score, status }) => {
    const colors = getHealthColor(status);
    const circumference = 2 * Math.PI * 45;
    const strokeDasharray = `${(score / 100) * circumference} ${circumference}`;

    return (
      <div className="health-score-ring">
        <svg viewBox="0 0 100 100" width="120" height="120">
          <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
          <circle
            cx="50" cy="50" r="45" fill="none"
            stroke={colors.border} strokeWidth="8"
            strokeDasharray={strokeDasharray}
            strokeLinecap="round"
            transform="rotate(-90 50 50)"
            style={{ filter: `drop-shadow(0 0 8px ${colors.border})` }}
          />
        </svg>
        <div className="health-score-value" style={{ color: colors.text }}>
          <span className="score-number">{score}</span>
          <span className="score-label">{status}</span>
        </div>
      </div>
    );
  };

  // Tab loading placeholder
  const TabLoader = () => (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', gap: '1rem' }}>
      <div className="spinner" style={{ width: '32px', height: '32px' }}></div>
      <span style={{ color: 'var(--text-dim)' }}>Loading...</span>
    </div>
  );

  return (
    <div className="dashboard">
      {/* Dashboard Header */}
      <div className="dashboard-header">
        <div className="dashboard-title">
          <h2>📊 Analysis Results</h2>
          <p className="dashboard-subtitle">AI-powered network diagnostics</p>
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <button
            className="new-analysis-btn"
            style={{ background: '#334155' }}
            onClick={() => setShowDebug(!showDebug)}
          >
            🐞 {showDebug ? 'Hide' : 'Debug'}
          </button>
          <button className="new-analysis-btn" onClick={onNewAnalysis}>
            <span>🔄</span> New Analysis
          </button>
        </div>
      </div>

      {showDebug && (
        <div className="debug-view" style={{ padding: '1rem', background: '#0f172a', border: '1px solid #334155', borderRadius: '8px', marginBottom: '1rem', overflowX: 'auto' }}>
          <h3 style={{ color: '#94a3b8', marginBottom: '0.5rem' }}>Raw Data Inspector</h3>
          <pre style={{ color: '#cbd5e1', fontSize: '0.75rem' }}>
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      )}

      {/* Main Tab Navigation */}
      <div className="main-tabs-container">
        <div className="main-tabs">
          {MAIN_TABS.map(tab => (
            <button
              key={tab.id}
              className={`main-tab ${mainTab === tab.id ? 'active' : ''}`}
              onClick={() => handleMainTabClick(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content - Lazy Loaded */}
      <div className="tab-content">

        {/* ANALYSIS TAB - Always rendered (default) */}
        <div style={{ display: mainTab === 'analysis' ? 'block' : 'none' }}>
          {/* Health Overview Banner */}
          {isStructuredRCA && (
            <div className="health-banner" style={{
              background: getHealthColor(rca.health_status).bg,
              borderColor: getHealthColor(rca.health_status).border,
              marginBottom: '1.5rem'
            }}>
              <HealthScoreRing score={rca.health_score || 0} status={rca.health_status || 'warning'} />
              <div className="health-summary">
                <h3>Network Health Assessment</h3>
                <p className="health-overview">{rca.network_overview}</p>
                {rca.session_analysis && (
                  <div className="session-indicators">
                    <div className="session-indicator">
                      <span className="indicator-label">Control Plane</span>
                      <span className="indicator-value">{rca.session_analysis.signaling_health}</span>
                    </div>
                    <div className="session-indicator">
                      <span className="indicator-label">User Plane</span>
                      <span className="indicator-value">{rca.session_analysis.user_plane_health}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* AI Analysis Section */}
          <div className="ai-section">
            <div className="ai-header">
              <h3>🤖 AI Network Analysis</h3>
              <div className="ai-tabs">
                <button className={`ai-tab ${activeAiTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveAiTab('overview')}>Overview</button>
                <button className={`ai-tab ${activeAiTab === 'observations' ? 'active' : ''}`} onClick={() => setActiveAiTab('observations')}>Observations</button>
                <button className={`ai-tab ${activeAiTab === 'recommendations' ? 'active' : ''}`} onClick={() => setActiveAiTab('recommendations')}>Recommendations</button>
              </div>
            </div>

            <div className="ai-content">
              {activeAiTab === 'overview' && (
                <div className="ai-overview">
                  {isStructuredRCA ? (
                    <>
                      <div className="overview-text" style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '1.25rem', borderRadius: '12px', borderLeft: '4px solid #8b5cf6', marginBottom: '1.5rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                          <span style={{ fontSize: '1.25rem' }}>📋</span>
                          <span style={{ color: '#94a3b8', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Classification</span>
                          <span style={{
                            background: rca.classification === 'ESTABLISHED' ? 'rgba(16, 185, 129, 0.2)' :
                              rca.classification === 'REJECTED' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                            color: rca.classification === 'ESTABLISHED' ? '#34d399' :
                              rca.classification === 'REJECTED' ? '#f87171' : '#fbbf24',
                            padding: '0.25rem 0.75rem', borderRadius: '20px', fontSize: '0.75rem', fontWeight: '600'
                          }}>{rca.classification || 'N/A'}</span>
                        </div>
                        <h4 style={{ color: '#e2e8f0', fontSize: '1.1rem', marginBottom: '0.75rem', fontWeight: '600' }}>Root Cause Analysis</h4>
                        <p style={{ color: '#cbd5e1', lineHeight: '1.7', fontSize: '1rem', whiteSpace: 'pre-wrap' }}>
                          {rca.executive_narrative || rca.network_overview}
                        </p>
                      </div>

                      {/* Key Contributing Factors */}
                      {rca.contributing_factors && rca.contributing_factors.length > 0 && (
                        <div className="contributing-factors" style={{ marginBottom: '1.5rem', background: 'rgba(30, 41, 59, 0.5)', borderRadius: '12px', padding: '1.25rem' }}>
                          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', color: '#e2e8f0', fontSize: '1rem' }}>
                            <span style={{ color: '#f59e0b' }}>⚠️</span> Key Contributing Factors
                          </h4>
                          <ul style={{ margin: 0, paddingLeft: '1.5rem', color: '#cbd5e1', lineHeight: '1.6' }}>
                            {rca.contributing_factors.map((factor, idx) => (
                              <li key={idx} style={{ marginBottom: '0.5rem' }}>
                                {factor}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Pattern Matches */}
                      {rca.pattern_matches && rca.pattern_matches.length > 0 && (
                        <div className="pattern-matches" style={{ marginBottom: '1.5rem' }}>
                          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                            <span>📚</span> 3GPP Pattern Matches
                          </h4>
                          {rca.pattern_matches.map((pattern, idx) => (
                            <div key={idx} style={{ background: 'rgba(139, 92, 246, 0.1)', border: '1px solid rgba(139, 92, 246, 0.3)', borderRadius: '12px', padding: '1rem', marginBottom: '0.75rem' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                                <span style={{ color: '#a78bfa', fontWeight: '600' }}>{pattern.pattern_name}</span>
                                <span style={{
                                  background: pattern.confidence === 'HIGH' ? 'rgba(16, 185, 129, 0.2)' : pattern.confidence === 'MEDIUM' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(156, 163, 175, 0.2)',
                                  color: pattern.confidence === 'HIGH' ? '#34d399' : pattern.confidence === 'MEDIUM' ? '#fbbf24' : '#9ca3af',
                                  padding: '0.2rem 0.5rem', borderRadius: '6px', fontSize: '0.7rem', fontWeight: '600'
                                }}>{pattern.confidence}</span>
                              </div>
                              <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '0.5rem' }}>📖 {pattern.spec_reference}</div>
                              <p style={{ color: '#cbd5e1', fontSize: '0.85rem', marginBottom: '0.5rem' }}>{pattern.explanation}</p>
                              {pattern.evidence && pattern.evidence.length > 0 && (
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                                  {pattern.evidence.map((ev, ei) => (
                                    <span key={ei} style={{ background: 'rgba(6, 182, 212, 0.15)', color: '#22d3ee', padding: '0.2rem 0.5rem', borderRadius: '4px', fontSize: '0.7rem', fontFamily: 'monospace' }}>{ev}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Root Causes */}
                      {rca.root_causes && rca.root_causes.length > 0 && (
                        <div className="root-causes">
                          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                            <span>🔍</span> Root Cause Analysis
                          </h4>
                          {rca.root_causes.map((cause, idx) => (
                            <div key={idx} className="root-cause-item" style={{ background: 'rgba(15, 23, 42, 0.4)', border: '1px solid var(--border-light)', borderRadius: '12px', padding: '1.25rem', marginBottom: '1rem' }}>
                              <div className="cause-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                                <span className="cause-title" style={{ color: '#f8fafc', fontSize: '1rem', fontWeight: '600' }}>{cause.issue}</span>
                                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                                  {cause.confidence_pct !== undefined && (
                                    <span style={{
                                      background: cause.confidence_pct >= 80 ? 'rgba(16, 185, 129, 0.2)' : cause.confidence_pct >= 50 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(156, 163, 175, 0.2)',
                                      color: cause.confidence_pct >= 80 ? '#34d399' : cause.confidence_pct >= 50 ? '#fbbf24' : '#9ca3af',
                                      padding: '0.3rem 0.6rem', borderRadius: '8px', fontSize: '0.8rem', fontWeight: '700'
                                    }}>{cause.confidence_pct}%</span>
                                  )}
                                  <span style={{
                                    background: (cause.confidence_level || cause.confidence) === 'HIGH' ? 'rgba(16, 185, 129, 0.15)' : (cause.confidence_level || cause.confidence) === 'MEDIUM' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                                    color: (cause.confidence_level || cause.confidence) === 'HIGH' ? '#34d399' : (cause.confidence_level || cause.confidence) === 'MEDIUM' ? '#fbbf24' : '#f87171',
                                    padding: '0.25rem 0.5rem', borderRadius: '6px', fontSize: '0.7rem', fontWeight: '600', textTransform: 'uppercase'
                                  }}>{cause.confidence_level || cause.confidence || 'unknown'}</span>
                                </div>
                              </div>
                              <p className="cause-description" style={{ color: '#cbd5e1', lineHeight: '1.6', marginBottom: '0.75rem' }}>{cause.description}</p>

                              {cause.confidence_justification && (
                                <div style={{ background: 'rgba(139, 92, 246, 0.1)', borderRadius: '8px', padding: '0.75rem', marginBottom: '0.75rem', borderLeft: '3px solid #8b5cf6' }}>
                                  <span style={{ color: '#a78bfa', fontSize: '0.75rem', fontWeight: '600' }}>💡 Confidence Basis: </span>
                                  <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>{cause.confidence_justification}</span>
                                </div>
                              )}

                              {cause.impact && (
                                <p className="cause-impact" style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
                                  <strong style={{ color: '#f59e0b' }}>Impact:</strong> {cause.impact}
                                </p>
                              )}

                              {cause.evidence_refs && cause.evidence_refs.length > 0 && (
                                <div style={{ marginTop: '0.75rem' }}>
                                  <span style={{ color: '#64748b', fontSize: '0.75rem', marginRight: '0.5rem' }}>📎 Evidence:</span>
                                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.4rem' }}>
                                    {cause.evidence_refs.map((ref, ri) => (
                                      <span key={ri} style={{ background: 'rgba(6, 182, 212, 0.1)', color: '#22d3ee', padding: '0.2rem 0.5rem', borderRadius: '4px', fontSize: '0.7rem', fontFamily: 'monospace' }}>{ref}</span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Inconclusive Aspects */}
                      {rca.inconclusive_aspects && rca.inconclusive_aspects.length > 0 && (
                        <div style={{ marginTop: '1.5rem' }}>
                          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', color: '#94a3b8' }}>
                            <span>⚠️</span> Cannot Be Determined
                          </h4>
                          {rca.inconclusive_aspects.map((item, idx) => (
                            <div key={idx} style={{ background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.2)', borderRadius: '8px', padding: '0.75rem', marginBottom: '0.5rem' }}>
                              <div style={{ color: '#fbbf24', fontWeight: '500', marginBottom: '0.25rem' }}>{item.aspect}</div>
                              <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>{item.reason}</div>
                              {item.additional_capture_needed && (
                                <div style={{ color: '#64748b', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                                  📷 Needed: {item.additional_capture_needed}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Cross-Plane Correlation */}
                      {rca.session_analysis && (
                        <div className="session-analysis" style={{ marginTop: '1.5rem' }}>
                          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                            <span>🔗</span> Cross-Plane Correlation
                          </h4>
                          <div style={{ background: 'rgba(15, 23, 42, 0.4)', borderRadius: '12px', padding: '1rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                            {rca.session_analysis.signaling_health && (
                              <div>
                                <div style={{ color: '#64748b', fontSize: '0.75rem', marginBottom: '0.25rem' }}>📡 Control Plane</div>
                                <div style={{ color: '#e2e8f0', fontSize: '0.85rem' }}>{rca.session_analysis.signaling_health}</div>
                              </div>
                            )}
                            {rca.session_analysis.user_plane_health && (
                              <div>
                                <div style={{ color: '#64748b', fontSize: '0.75rem', marginBottom: '0.25rem' }}>📦 User Plane</div>
                                <div style={{ color: '#e2e8f0', fontSize: '0.85rem' }}>{rca.session_analysis.user_plane_health}</div>
                              </div>
                            )}
                            {rca.session_analysis.voice_quality && (
                              <div>
                                <div style={{ color: '#64748b', fontSize: '0.75rem', marginBottom: '0.25rem' }}>🎤 Voice Quality</div>
                                <div style={{ color: '#e2e8f0', fontSize: '0.85rem' }}>{rca.session_analysis.voice_quality}</div>
                              </div>
                            )}
                          </div>
                          {rca.session_analysis.cross_plane_correlation && (
                            <p style={{ color: '#cbd5e1', marginTop: '1rem', fontSize: '0.9rem' }}>{rca.session_analysis.cross_plane_correlation}</p>
                          )}
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="overview-text legacy">
                      {root_cause_analysis || 'No analysis available'}
                    </div>
                  )}
                </div>
              )}

              {activeAiTab === 'observations' && (
                <div className="ai-observations">
                  {isStructuredRCA && rca.observations ? (
                    <div className="observations-list">
                      {rca.observations.map((obs, idx) => (
                        <div key={idx} className="observation-item">
                          <div className="obs-badge" style={getSeverityStyle(obs.severity)}>{obs.severity}</div>
                          <div className="obs-content">
                            <span className="obs-category">{obs.category}</span>
                            <p className="obs-finding">{obs.finding}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="no-data">No structured observations available</p>
                  )}
                </div>
              )}

              {activeAiTab === 'recommendations' && (
                <div className="ai-recommendations">
                  {isStructuredRCA && rca.recommendations ? (
                    <div className="recommendations-list">
                      {rca.recommendations.map((rec, idx) => (
                        <div key={idx} className="recommendation-item">
                          <div className="rec-priority"><span className="priority-number">{rec.priority}</span></div>
                          <div className="rec-content">
                            <div className="rec-header">
                              <span className="rec-action">{rec.action}</span>
                              <span className="rec-category">{rec.category}</span>
                            </div>
                            <p className="rec-rationale">{rec.rationale}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="no-data">No recommendations available</p>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* RADIO TAB - Lazy loaded */}
        {visitedTabs.radio && (
          <div style={{ display: mainTab === 'radio' ? 'block' : 'none' }}>
            {/* Dataset Status */}
            {datasets && (
              <div className="dataset-status-panel">
                <h4>📂 Datasets</h4>
                <div className="dataset-cards">
                  <div className={`dataset-card ${datasets.pcap_present ? 'present' : 'missing'}`}>
                    <span className="ds-icon">{datasets.pcap_present ? '✅' : '❌'}</span>
                    <span className="ds-label">PCAP</span>
                    <span className="ds-file">{datasets.pcap_filename || 'Not uploaded'}</span>
                  </div>
                  <div className={`dataset-card ${datasets.groundhog_present ? 'present' : 'missing'}`}>
                    <span className="ds-icon">{datasets.groundhog_present ? '✅' : '❌'}</span>
                    <span className="ds-label">Radio Trace</span>
                    <span className="ds-file">{datasets.groundhog_filename || 'Not uploaded'}</span>
                    {datasets.groundhog_format && <span className="ds-format">{datasets.groundhog_format.toUpperCase()}</span>}
                  </div>
                </div>
                {onIterationUpload && caseId && (!datasets.pcap_present || !datasets.groundhog_present) && (
                  <div className="iteration-panel">
                    <p className="iteration-hint">
                      💡 {!datasets.pcap_present ? 'Upload a PCAP for cross-plane correlation' : 'Upload a Radio Trace for radio KPI analysis'}
                    </p>
                    <input
                      type="file"
                      id="iteration-file"
                      style={{ display: 'none' }}
                      accept={!datasets.pcap_present ? '.pcap,.pcapng' : '.html,.htm,.csv,.xls,.xlsx,.json,.xml'}
                      onChange={async (e) => {
                        if (e.target.files[0]) {
                          const fk = !datasets.pcap_present ? 'pcap' : 'groundhog';
                          const formData = new FormData();
                          formData.append('file', e.target.files[0]);
                          await fetch(`${apiUrl}/api/cases/${caseId}/upload?file_kind=${fk}`, {
                            method: 'POST',
                            body: formData,
                          });
                          onIterationUpload({});
                        }
                      }}
                    />
                    <button className="analyze-btn" onClick={() => document.getElementById('iteration-file').click()} style={{ padding: '0.75rem 1.5rem', fontSize: '0.9rem' }}>
                      📤 Add {!datasets.pcap_present ? 'PCAP' : 'Radio Trace'}
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Radio Summary */}
            {groundhog_summary && groundhog_summary.total_events > 0 && (
              <div className="radio-summary-section">
                <h3>📻 Radio Trace Summary</h3>
                <div className="summary-grid">
                  <div className="summary-card">
                    <div className="summary-card-icon">📊</div>
                    <div className="summary-card-content">
                      <div className="summary-card-label">Total Events</div>
                      <div className="summary-card-value">{groundhog_summary.total_events.toLocaleString()}</div>
                    </div>
                  </div>
                  {groundhog_summary.time_range?.duration_seconds > 0 && (
                    <div className="summary-card">
                      <div className="summary-card-icon">⏱️</div>
                      <div className="summary-card-content">
                        <div className="summary-card-label">Duration</div>
                        <div className="summary-card-value">{Math.round(groundhog_summary.time_range.duration_seconds)}s</div>
                      </div>
                    </div>
                  )}
                  {groundhog_summary.identifiers_found?.cell_id_count > 0 && (
                    <div className="summary-card">
                      <div className="summary-card-icon">📡</div>
                      <div className="summary-card-content">
                        <div className="summary-card-label">Cells</div>
                        <div className="summary-card-value">{groundhog_summary.identifiers_found.cell_id_count}</div>
                      </div>
                    </div>
                  )}
                </div>
                {groundhog_summary.event_type_counts && Object.keys(groundhog_summary.event_type_counts).length > 0 && (
                  <div className="event-type-breakdown">
                    <h4>Event Types</h4>
                    <div className="event-tags">
                      {Object.entries(groundhog_summary.event_type_counts).map(([type, count]) => (
                        <span key={type} className={`event-tag ${['RLF', 'HO_FAIL', 'PAGING'].includes(type) ? 'critical' : ''}`}>
                          {type}: {count}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {groundhog_summary.kpi_statistics && (
                  <div className="kpi-stats">
                    <h4>📈 KPI Statistics</h4>
                    <div className="kpi-grid">
                      {Object.entries(groundhog_summary.kpi_statistics).map(([kpi, stats]) => (
                        <div key={kpi} className="kpi-card">
                          <div className="kpi-name">{kpi.replace(/_/g, ' ').toUpperCase()}</div>
                          <div className="kpi-values">
                            <span>min: {stats.min} {stats.unit}</span>
                            <span>avg: {stats.avg} {stats.unit}</span>
                            <span>max: {stats.max} {stats.unit}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Radio Findings */}
            {radio_findings && radio_findings.length > 0 && (
              <div className="radio-findings-section">
                <h3>🔍 Radio Root Cause Findings</h3>
                {radio_findings.map((finding, idx) => (
                  <div key={idx} className={`radio-finding-card ${finding.confidence_level?.toLowerCase() || 'low'}`}>
                    <div className="rf-header">
                      <span className="rf-type">{finding.finding_type?.replace(/_/g, ' ')}</span>
                      <span className={`rf-confidence ${finding.confidence_level?.toLowerCase()}`}>
                        {finding.confidence_pct}% {finding.confidence_level}
                      </span>
                    </div>
                    <p className="rf-desc">{finding.description}</p>
                    {finding.evidence && finding.evidence.length > 0 && (
                      <div className="rf-evidence">
                        <span className="rf-label">Evidence:</span>
                        {finding.evidence.map((ev, ei) => (
                          <span key={ei} className="rf-ev-item">{ev}</span>
                        ))}
                      </div>
                    )}
                    {finding.limitations && finding.limitations.length > 0 && (
                      <div className="rf-limitations">
                        {finding.limitations.map((lim, li) => (
                          <span key={li} className="rf-lim-item">⚠️ {lim}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Correlation Report */}
            {correlation_report && correlation_report.status === 'CORRELATED' && (
              <div className="correlation-section">
                <h3>🔗 Cross-Plane Correlation</h3>
                <div className="corr-stats">
                  <span className="corr-stat">⏱ {correlation_report.time_alignment}</span>
                  <span className="corr-stat">🎯 {correlation_report.high_confidence_matches} high-conf matches</span>
                  <span className="corr-stat">📊 {correlation_report.total_correlations} total correlations</span>
                </div>
                {correlation_report.key_incidents && correlation_report.key_incidents.length > 0 && (
                  <div className="key-incidents">
                    <h4>Key Incidents</h4>
                    {correlation_report.key_incidents.map((inc, idx) => (
                      <div key={idx} className={`incident-card ${inc.severity}`}>
                        <span className="inc-type">{inc.type?.replace(/_/g, ' ')}</span>
                        <span className="inc-desc">{inc.description}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Correlation Timeline */}
            {cross_plane_events && cross_plane_events.length > 0 && (
              <div className="timeline-section">
                <h3>📋 Correlation Timeline</h3>
                <div className="timeline-list">
                  {cross_plane_events.slice(0, 50).map((ev, idx) => (
                    <div key={idx} className={`timeline-item ${ev.source.toLowerCase()}`}>
                      <span className={`tl-source ${ev.source.toLowerCase()}`}>{ev.source}</span>
                      <span className="tl-type">{ev.event_type}</span>
                      <span className="tl-desc">{ev.description}</span>
                      <span className={`tl-severity ${ev.severity}`}>{ev.severity}</span>
                    </div>
                  ))}
                  {cross_plane_events.length > 50 && (
                    <div className="tl-more">Showing 50 of {cross_plane_events.length} events</div>
                  )}
                </div>
              </div>
            )}

            {/* No radio data placeholder */}
            {!radio_findings?.length && !groundhog_summary && !correlation_report && (
              <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-dim)' }}>
                <span style={{ fontSize: '3rem' }}>📡</span>
                <p style={{ marginTop: '1rem' }}>No radio data available</p>
                <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>Upload a radio trace to see radio KPIs and correlation</p>
              </div>
            )}
          </div>
        )}

        {/* STATISTICS TAB - Lazy loaded */}
        {visitedTabs.statistics && (
          <div style={{ display: mainTab === 'statistics' ? 'block' : 'none' }}>
            {/* Summary Cards */}
            <div className="summary-grid" style={{ marginBottom: '1.5rem' }}>
              <div className="summary-card">
                <div className="summary-card-icon">📦</div>
                <div className="summary-card-content">
                  <div className="summary-card-label">Total Packets</div>
                  <div className="summary-card-value">{summary?.total_packets?.toLocaleString() || 0}</div>
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-card-icon">🌊</div>
                <div className="summary-card-content">
                  <div className="summary-card-label">Network Flows</div>
                  <div className="summary-card-value">{summary?.total_flows?.toLocaleString() || 0}</div>
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-card-icon">💾</div>
                <div className="summary-card-content">
                  <div className="summary-card-label">Data Volume</div>
                  <div className="summary-card-value">{formatBytes(summary?.total_bytes || 0)}</div>
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-card-icon">⏱️</div>
                <div className="summary-card-content">
                  <div className="summary-card-label">Duration</div>
                  <div className="summary-card-value">{formatDuration(summary?.duration)}</div>
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-card-icon">🔌</div>
                <div className="summary-card-content">
                  <div className="summary-card-label">Protocols</div>
                  <div className="summary-card-value">{summary?.protocols?.length || 0}</div>
                  <div className="summary-card-sub">{summary?.protocols?.slice(0, 3).join(', ')}{summary?.protocols?.length > 3 ? '...' : ''}</div>
                </div>
              </div>
            </div>

            {/* Telecom Sessions */}
            {telecom_sessions && telecom_sessions.length > 0 && (
              <div className="sessions-section" style={{ marginBottom: '1.5rem' }}>
                <h3>📡 Detected Telecom Sessions</h3>
                <div className="sessions-grid">
                  {telecom_sessions.map((session, idx) => (
                    <div key={idx} className="session-card">
                      <div className="session-type">{session.type}</div>
                      <div className="session-stats">
                        <span className="session-count">{session.flow_count}</span>
                        <span className="session-label">flows</span>
                      </div>
                      <div className="session-meta">
                        {session.total_packets?.toLocaleString()} packets
                        {session.teids && session.teids.length > 0 && (
                          <span className="session-teids">TEIDs: {session.teids.slice(0, 2).join(', ')}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Charts */}
            <div className="charts-section">
              <div className="chart-card">
                <h3>📈 Protocol Distribution</h3>
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie data={protocolChartData} cx="50%" cy="50%" innerRadius={65} outerRadius={100} paddingAngle={3} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={{ stroke: 'var(--text-dim)', strokeWidth: 1 }}>
                      {protocolChartData.map((entry, index) => (<Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />))}
                    </Pie>
                    <Tooltip formatter={(value) => [`${value.toLocaleString()} packets`, 'Count']} contentStyle={{ background: 'rgba(15, 23, 42, 0.95)', border: '1px solid rgba(139, 92, 246, 0.3)', borderRadius: '12px', boxShadow: '0 10px 40px rgba(0,0,0,0.5)' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-card">
                <h3>📱 Technology Stack</h3>
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie data={technologyChartData} cx="50%" cy="50%" innerRadius={65} outerRadius={100} paddingAngle={3} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={{ stroke: 'var(--text-dim)', strokeWidth: 1 }}>
                      {technologyChartData.map((entry, index) => (<Cell key={`tech-${index}`} fill={entry.color} />))}
                    </Pie>
                    <Tooltip formatter={(value) => [`${value.toLocaleString()} packets`, 'Count']} contentStyle={{ background: 'rgba(15, 23, 42, 0.95)', border: '1px solid rgba(6, 182, 212, 0.3)', borderRadius: '12px', boxShadow: '0 10px 40px rgba(0,0,0,0.5)' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Top Flows Chart */}
            <div className="chart-card full-width" style={{ marginTop: '1.5rem' }}>
              <h3>📊 Top Flows by Volume</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={topFlowsData} layout="vertical" margin={{ left: 10, right: 30 }}>
                  <XAxis type="number" stroke="var(--text-dim)" />
                  <YAxis dataKey="name" type="category" stroke="var(--text-dim)" width={60} />
                  <Tooltip contentStyle={{ background: 'rgba(15, 23, 42, 0.95)', border: '1px solid rgba(139, 92, 246, 0.3)', borderRadius: '12px' }} formatter={(value, name) => [name === 'packets' ? `${value.toLocaleString()} packets` : `${value} KB`, name === 'packets' ? 'Packets' : 'Size']} />
                  <Legend />
                  <Bar dataKey="packets" fill="#8b5cf6" name="Packets" radius={[0, 4, 4, 0]} />
                  <Bar dataKey="bytes" fill="#06b6d4" name="Size (KB)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* VOICE TAB - Lazy loaded */}
        {visitedTabs.voice && (
          <div style={{ display: mainTab === 'voice' ? 'block' : 'none' }}>
            {data.voice_analysis ? (
              <div className="voice-section">
                <div className="section-header">
                  <h3>📞 {data.voice_analysis.trace_type === 'REGISTRATION_ONLY' ? 'IMS Registration Analysis' : 'Voice & IMS Analysis'}</h3>
                  <div className="voice-badges">
                    {data.voice_analysis.trace_type === 'REGISTRATION_ONLY' ? (
                      <span className="badge-item total">{data.voice_analysis.registrations?.length || 0} Registrations</span>
                    ) : (
                      <>
                        <span className="badge-item total">{data.voice_analysis.stats?.total_calls || 0} Calls</span>
                        {data.voice_analysis.stats?.dropped > 0 && (<span className="badge-item critical">{data.voice_analysis.stats.dropped} Dropped</span>)}
                        {data.voice_analysis.stats?.media_issues > 0 && (<span className="badge-item warning">{data.voice_analysis.stats.media_issues} Media Issues</span>)}
                      </>
                    )}
                  </div>
                </div>

                {/* Media Findings */}
                {data.voice_analysis.findings && data.voice_analysis.findings.length > 0 && (
                  <div className="media-findings-grid">
                    {data.voice_analysis.findings.map((finding, idx) => (
                      <div key={idx} className={`finding-card ${finding.severity}`}>
                        <div className="finding-icon">{finding.title.includes('One-Way') ? '🔇' : '📉'}</div>
                        <div className="finding-content">
                          <h4>{finding.title}</h4>
                          <p>{finding.description}</p>
                          <div className="finding-meta">Call ID: {finding.call_id.substring(0, 8)}...</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Registrations Table */}
                {data.voice_analysis.registrations && data.voice_analysis.registrations.length > 0 && (
                  <div className="calls-table-container" style={{ marginBottom: '1.5rem' }}>
                    <h4 style={{ padding: '0.5rem 1rem', color: '#94a3b8', fontSize: '0.85rem' }}>IMS Registrations</h4>
                    <table className="analysis-table">
                      <thead>
                        <tr><th>Call ID</th><th>Time</th><th>Method</th><th>Status</th><th>Result</th><th>Msg Count</th></tr>
                      </thead>
                      <tbody>
                        {data.voice_analysis.registrations.map((reg, idx) => (
                          <tr key={idx} className={reg.state === 'FAILED' ? 'row-error' : ''}>
                            <td className="mono">{reg.call_id.substring(0, 12)}...</td>
                            <td>{new Date(reg.start_time * 1000).toLocaleTimeString()}</td>
                            <td>{reg.method}</td>
                            <td><span className={`status-badge ${reg.state.toLowerCase()}`}>{reg.state}</span></td>
                            <td>{reg.end_reason}</td>
                            <td>{reg.msg_count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Calls Table */}
                {data.voice_analysis.calls && data.voice_analysis.calls.length > 0 && (
                  <div className="calls-table-container">
                    <h4 style={{ padding: '0.5rem 1rem', color: '#94a3b8', fontSize: '0.85rem' }}>Voice Calls</h4>
                    <table className="analysis-table">
                      <thead>
                        <tr><th>Call ID</th><th>Start Time</th><th>Duration</th><th>Status</th><th>End Reason</th><th>Msg Count</th></tr>
                      </thead>
                      <tbody>
                        {data.voice_analysis.calls.map((call, idx) => (
                          <tr key={idx} className={call.state === 'FAILED' || call.end_reason?.includes('DROP') ? 'row-error' : ''}>
                            <td className="mono">{call.call_id.substring(0, 12)}...</td>
                            <td>{new Date(call.start_time * 1000).toLocaleTimeString()}</td>
                            <td>{call.duration_sec}s</td>
                            <td><span className={`status-badge ${call.state.toLowerCase()}`}>{call.state}</span></td>
                            <td>{call.end_reason}</td>
                            <td>{call.msg_count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-dim)' }}>
                <span style={{ fontSize: '3rem' }}>📞</span>
                <p style={{ marginTop: '1rem' }}>No Voice/IMS data detected in this capture</p>
              </div>
            )}
          </div>
        )}

        {/* DIAGRAMS TAB - Lazy loaded */}
        {visitedTabs.diagrams && (
          <div style={{ display: mainTab === 'diagrams' ? 'block' : 'none' }}>
            {/* Sequence Diagram */}
            {message_sequence && message_sequence.length > 0 && (
              <FlowDiagram messageSequence={message_sequence} maxMessages={50} />
            )}

            {/* AI-Generated Mermaid Diagram */}
            {isStructuredRCA && rca.sequence_diagram && (
              <div className="sequence-diagram-section" style={{ marginTop: '2rem', padding: '1.5rem', background: 'rgba(15, 23, 42, 0.4)', borderRadius: '12px', border: '1px solid var(--border-light)' }}>
                <h4 style={{ marginBottom: '1rem', color: '#f8fafc' }}>🧬 AI-Generated Trace Visualization</h4>
                <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', overflowX: 'auto' }}>
                  <MermaidDiagram chart={rca.sequence_diagram} />
                </div>
              </div>
            )}

            {(!message_sequence || message_sequence.length === 0) && (!rca || !rca.sequence_diagram) && (
              <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-dim)' }}>
                <span style={{ fontSize: '3rem' }}>🧬</span>
                <p style={{ marginTop: '1rem' }}>No diagram data available</p>
              </div>
            )}
          </div>
        )}

        {/* FLOWS TAB - Lazy loaded */}
        {visitedTabs.flows && (
          <div style={{ display: mainTab === 'flows' ? 'block' : 'none' }}>
            <div className="flows-section">
              <div className="flows-header">
                <h3>🌐 Network Flows</h3>
                <div className="flows-controls">
                  <span className="flows-count">{filteredFlows.length} flows</span>
                  <input
                    type="text"
                    className="flows-search"
                    placeholder="Search IP, protocol, technology..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
              </div>

              <div className="flows-table-container">
                <table className="flows-table">
                  <thead>
                    <tr>
                      <th>#</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Technology</th><th>Packets</th><th>Data</th><th>Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFlows.slice(0, 50).map((flow, index) => (
                      <React.Fragment key={index}>
                        <tr onClick={() => setExpandedFlow(expandedFlow === index ? null : index)} className={expandedFlow === index ? 'expanded' : ''}>
                          <td className="flow-index">{index + 1}</td>
                          <td className="flow-endpoint"><span className="ip">{flow.src_ip}</span><span className="port">:{flow.src_port}</span></td>
                          <td className="flow-endpoint"><span className="ip">{flow.dst_ip}</span><span className="port">:{flow.dst_port}</span></td>
                          <td><span className={getProtocolBadgeClass(flow.protocol)}>{flow.protocol}</span></td>
                          <td><span style={getTechBadgeStyle(flow.primary_tech)}>{flow.primary_tech || 'Unknown'}</span></td>
                          <td className="flow-metric">{flow.packet_count?.toLocaleString()}</td>
                          <td className="flow-metric">{formatBytes(flow.total_bytes)}</td>
                          <td className="flow-metric">{formatDuration(flow.duration)}</td>
                        </tr>
                        {expandedFlow === index && (
                          <tr className="flow-detail-row">
                            <td colSpan={8}>
                              <div className="flow-detail">
                                <div className="detail-grid">
                                  <div className="detail-item"><span className="detail-label">Transport</span><span className="detail-value">{flow.transport || 'N/A'}</span></div>
                                  <div className="detail-item"><span className="detail-label">PPS</span><span className="detail-value">{flow.pps || 'N/A'}</span></div>
                                  {flow.gtp_teids && flow.gtp_teids.length > 0 && (<div className="detail-item"><span className="detail-label">GTP TEIDs</span><span className="detail-value">{flow.gtp_teids.join(', ')}</span></div>)}
                                  {flow.diameter_apps && flow.diameter_apps.length > 0 && (<div className="detail-item"><span className="detail-label">Diameter Apps</span><span className="detail-value">{flow.diameter_apps.join(', ')}</span></div>)}
                                </div>
                                <div className="flow-insight-box">
                                  <span className="insight-label">🤖 AI Insight</span>
                                  <p className="insight-text">{flow.llm_insight || 'No insight available'}</p>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>

                {filteredFlows.length > 50 && (
                  <div className="flows-footer">Showing 50 of {filteredFlows.length} flows. Use search to filter.</div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Floating Chat FAB */}
      {!showChat && (
        <button
          className="chat-fab"
          onClick={() => setShowChat(true)}
          title="AI Assistant"
        >
          <span className="chat-fab-icon">💬</span>
          <span className="chat-fab-pulse"></span>
        </button>
      )}

      {/* Chat Panel */}
      {showChat && (
        <ChatPanel
          jobId={jobId}
          onClose={() => setShowChat(false)}
        />
      )}
    </div>
  );
}

export default Dashboard;
