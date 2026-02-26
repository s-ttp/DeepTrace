import React, { useState, useEffect, useRef } from 'react';
import FileUpload from './FileUpload';
import ProgressBar from './ProgressBar';
import Dashboard from './Dashboard';
import ErrorBoundary from './ErrorBoundary';

// Use relative path - React proxy will forward to http://localhost:8000
const API_URL = '';

function App() {
  const [jobId, setJobId] = useState(null);
  const [caseId, setCaseId] = useState(null);
  const [fileKind, setFileKind] = useState(null); // 'pcap' or 'groundhog'
  const [analysisData, setAnalysisData] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState(null);
  const [apiStatus, setApiStatus] = useState('checking');
  const wsRef = useRef(null);

  // Check API health on mount
  useEffect(() => {
    const checkApi = async () => {
      try {
        const response = await fetch(`${API_URL}/api/health`);
        if (response.ok) {
          setApiStatus('ready');
        } else {
          setApiStatus('error');
        }
      } catch (e) {
        setApiStatus('error');
      }
    };
    checkApi();
  }, []);

  // === Legacy PCAP-only upload flow (backward compat) ===
  const handleLegacyUploadComplete = (id) => {
    setJobId(id);
    setError(null);
    setProgress(5);
    setStage('parsing');
    setMessage('Starting analysis...');
    connectWebSocket(id);
  };

  // === New Case-based flow ===
  const handleStartWithFileKind = async (kind) => {
    setFileKind(kind);
    try {
      const resp = await fetch(`${API_URL}/api/cases`, { method: 'POST' });
      const data = await resp.json();
      setCaseId(data.case_id);
    } catch (e) {
      setError('Failed to create case: ' + e.message);
    }
  };

  const handleCaseUploadComplete = async (respData) => {
    const id = caseId;
    setJobId(id);
    setError(null);
    setProgress(5);
    setStage('starting');
    setMessage('Starting analysis...');

    // Trigger analysis
    try {
      await fetch(`${API_URL}/api/cases/${id}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          run_pcap_analysis: true,
          run_groundhog_analysis: true,
          run_correlation: true,
          run_final_rca: true,
        }),
      });
      connectWebSocket(id);
    } catch (e) {
      setError('Failed to start analysis: ' + e.message);
    }
  };

  // === Iteration: add more data to existing case ===
  const handleIterationUpload = async (respData) => {
    setProgress(5);
    setStage('starting');
    setMessage('Re-running analysis with new data...');
    setAnalysisData(null);

    try {
      await fetch(`${API_URL}/api/cases/${caseId}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          run_pcap_analysis: true,
          run_groundhog_analysis: true,
          run_correlation: true,
          run_final_rca: true,
        }),
      });
      connectWebSocket(caseId);
    } catch (e) {
      setError('Failed to re-run analysis: ' + e.message);
    }
  };

  const connectWebSocket = (id) => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/${id}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'keepalive') return;
        setProgress(data.progress || 0);
        setStage(data.stage || '');
        setMessage(data.message || '');

        if (data.progress === 100) {
          setTimeout(() => fetchResults(id), 500);
        }
        if (data.stage === 'failed') {
          setError(data.message);
        }
      } catch (e) {
        console.log('WebSocket message:', event.data);
      }
    };

    ws.onerror = () => {
      pollForResults(id);
    };
  };

  const fetchResults = async (id) => {
    try {
      const response = await fetch(`${API_URL}/api/analysis/${id}`);
      const data = await response.json();

      if (data.status === 'completed') {
        setAnalysisData(data.results);
        if (wsRef.current) wsRef.current.close();
      } else if (data.status === 'failed') {
        setError(data.error || 'Analysis failed');
      }
    } catch (error) {
      setError('Failed to fetch results: ' + error.message);
    }
  };

  const pollForResults = (id) => {
    const interval = setInterval(async () => {
      try {
        const response = await fetch(`${API_URL}/api/analysis/${id}`);
        const data = await response.json();
        setProgress(data.progress || 0);
        setStage(data.stage || '');

        if (data.status === 'completed') {
          clearInterval(interval);
          setAnalysisData(data.results);
        } else if (data.status === 'failed') {
          clearInterval(interval);
          setError(data.error || 'Analysis failed');
        }
      } catch (e) {
        // ignore polling errors briefly
      }
    }, 2000);
  };

  const handleNewAnalysis = () => {
    setJobId(null);
    setCaseId(null);
    setFileKind(null);
    setAnalysisData(null);
    setProgress(0);
    setStage('');
    setMessage('');
    setError(null);
    if (wsRef.current) wsRef.current.close();
  };

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // Determine what to show on landing page
  const showLanding = !jobId && !error && !fileKind;
  const showCaseUpload = !jobId && !error && fileKind && caseId;

  return (
    <div className="app">
      <header className="header">
        <div className="header-content">
          <div className="logo-section">
            <div className="logo-text">
              <h1>DeepTrace</h1>
              <p className="tagline">Intelligent Network Analysis</p>
            </div>
          </div>
          <div className="header-controls">
            <div className={`status-pill ${apiStatus === 'ready' ? 'success' : ''}`}>
              {apiStatus === 'ready' ? 'API Ready' : apiStatus === 'checking' ? 'Checking...' : 'API Error'}
            </div>
            <div className="status-pill success">AI Powered</div>
            {(jobId || analysisData || fileKind) && (
              <button className="primary-ghost" onClick={handleNewAnalysis}>
                🔄 New Analysis
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="main-content">
        {error && (
          <div className="error-message">
            <span>⚠️ <strong>Error:</strong> {error}</span>
            <button className="primary-ghost" onClick={handleNewAnalysis}>
              Try Again
            </button>
          </div>
        )}

        {showLanding && (
          <section className="hero">
            <div className="hero-text">
              <p className="eyebrow">AI-Powered Diagnostics</p>
              <h2>Deep Analysis for Mobile Network Traffic</h2>
              <p className="lead">
                Upload PCAP captures or Radio traces and let DeepTrace detect protocols across 2G through 5G,
                correlate radio KPIs with signaling, and deliver AI-powered root cause analysis.
              </p>
              <ul className="hero-list">
                <li>Full mobile stack: 2G/GSM → 3G/UMTS → 4G/LTE → 5G/NR</li>
                <li>Radio trace analysis (HTML, CSV, XLS, XLSX, JSON, XML)</li>
                <li>Cross-plane correlation: radio KPIs ↔ signaling events</li>
                <li>Iterative analysis: start with PCAP or radio, add the other later</li>
              </ul>
            </div>
            <div className="hero-upload">
              <div className="upload-choice-cards">
                <div className="upload-card" onClick={() => handleStartWithFileKind('pcap')}>
                  <div className="upload-card-icon">📡</div>
                  <h3>Start with PCAP</h3>
                  <p>Upload a network capture file (.pcap, .pcapng)</p>
                </div>
                <div className="upload-card" onClick={() => handleStartWithFileKind('groundhog')}>
                  <div className="upload-card-icon">📻</div>
                  <h3>Start with Radio Trace</h3>
                  <p>Upload radio trace (HTML, CSV, XLS, XLSX, JSON, XML)</p>
                </div>
              </div>
            </div>
          </section>
        )}

        {showCaseUpload && (
          <section className="hero">
            <div className="hero-text">
              <p className="eyebrow">
                {fileKind === 'pcap' ? '📡 PCAP Upload' : '📻 Radio Trace Upload'}
              </p>
              <h2>{fileKind === 'pcap' ? 'Upload Network Capture' : 'Upload Radio Trace'}</h2>
              <p className="lead">
                {fileKind === 'pcap'
                  ? 'Drag and drop your PCAP capture file for analysis.'
                  : 'Drag and drop your radio trace file.'}
              </p>
            </div>
            <div className="hero-upload">
              <FileUpload
                onUploadComplete={handleCaseUploadComplete}
                apiUrl={API_URL}
                fileKind={fileKind}
                caseId={caseId}
              />
            </div>
          </section>
        )}

        {jobId && !analysisData && !error && (
          <ProgressBar
            progress={progress}
            stage={stage}
            message={message}
          />
        )}

        {analysisData && (
          <ErrorBoundary>
            <Dashboard
              data={analysisData}
              jobId={jobId}
              caseId={caseId}
              apiUrl={API_URL}
              onNewAnalysis={handleNewAnalysis}
              onIterationUpload={handleIterationUpload}
            />
          </ErrorBoundary>
        )}
      </main>
    </div>
  );
}

export default App;
