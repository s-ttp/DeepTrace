import React, { useState, useEffect, useRef } from 'react';
import FileUpload from './FileUpload';
import ProgressBar from './ProgressBar';
import Dashboard from './Dashboard';
import ErrorBoundary from './ErrorBoundary';

// Use relative path - React proxy will forward to http://localhost:8000
const API_URL = '';

function App() {
  const [jobId, setJobId] = useState(null);
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

  const handleUploadComplete = (id) => {
    setJobId(id);
    setError(null);
    setProgress(5);
    setStage('parsing');
    setMessage('Starting analysis...');
    connectWebSocket(id);
  };

  const connectWebSocket = (id) => {
    // Determine WS protocol based on current page protocol
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Use window.location.host which includes port if present
    const wsUrl = `${protocol}//${window.location.host}/ws/${id}`;

    // In dev with proxy, we might need to be explicit if proxy doesn't handle WS well
    // But let's try relative/proxy first. 
    // Actually, CRA proxy doesn't always handle WS automatically to the stored proxy.
    // For cloud envs, relying on the same host but different path is safer if there's a gateway (like nginx).
    // But here we are relying on CRA proxy. CRA proxy DOES support WS.
    // However, we need to point to the *proxy target* for WS usually? 
    // No, usually in dev we connect to dev server port, and it proxies.

    // Let's hardcode localhost:8000 for WS if on localhost, else assume same origin (prod)
    // BUT the user issue is "Failed to fetch" (HTTP), so let's fix HTTP first.
    // For WS in cloud envs, it's tricky. Let's try to assume the backend is on the same host if we are running locally?
    // No, let's use the explicit logic that works with the proxy:


    // Wait, if I change http to relative, I should probably try to make WS relative too?
    // But WS doesn't use the HTTP proxy middleware in the same way for Upgrade requests sometimes.

    // Let's stick to the previous failing logic for WS *for now* but with localhost explicitly if we are sure?
    // Actually, if I use "proxy", requests to /ws might be proxied if I configured it as manual setup setupProxy.js, 
    // but just "proxy": "url" handles Accept: text/html exceptions.

    // Let's try using the backend URL directly for WS since standard proxying might be flaky for WS without setupProxy.js
    // Reverting to the logic that matches the backend location we know: localhost:8000 
    // Since I am setting "proxy": "http://localhost:8000", the backend IS at localhost:8000.
    const ws = new WebSocket(`ws://${window.location.hostname}:8000/ws/${id}`);

    // NOTE: If the user is on a cloud IDE, they might not be able to connect to :8000 directly.
    // They are seeing "Failed to fetch" which is HTTP. 
    // If HTTP works via proxy, WS might fail if blocked.
    // Let's fix HTTP first. I will leave WS as is for one step, or try to respect the proxy.

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
      // Fallback to polling
      pollForResults(id);
    };
  };

  const fetchResults = async (id) => {
    try {
      const response = await fetch(`${API_URL}/api/analysis/${id}`);
      const data = await response.json();

      if (data.status === 'completed') {
        setAnalysisData(data.results);
        if (wsRef.current) {
          wsRef.current.close();
        }
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
    setAnalysisData(null);
    setProgress(0);
    setStage('');
    setMessage('');
    setError(null);
    if (wsRef.current) {
      wsRef.current.close();
    }
  };

  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  return (
    <div className="app">
      <header className="header">
        <div className="header-content">
          <div className="logo-section">
            <div className="logo-icon">📡</div>
            <div className="logo-text">
              <h1>NetTrace AI</h1>
              <p className="tagline">Intelligent Network Analysis</p>
            </div>
          </div>
          <div className="header-controls">
            <div className={`status-pill ${apiStatus === 'ready' ? 'success' : ''}`}>
              {apiStatus === 'ready' ? 'API Ready' : apiStatus === 'checking' ? 'Checking...' : 'API Error'}
            </div>
            <div className="status-pill success">AI Powered</div>
            {(jobId || analysisData) && (
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

        {!jobId && !error && (
          <section className="hero">
            <div className="hero-text">
              <p className="eyebrow">AI-Powered Diagnostics</p>
              <h2>Deep Analysis for Mobile Network Traffic</h2>
              <p className="lead">
                Upload your PCAP captures and let NetTrace AI detect protocols across 2G through 5G, identify session patterns, and deliver AI-powered root cause analysis with actionable recommendations.
              </p>
              <ul className="hero-list">
                <li>Full mobile stack: 2G/GSM → 3G/UMTS → 4G/LTE → 5G/NR</li>
                <li>Protocol detection: GTP, Diameter, SIP, PFCP, NGAP, S1-AP & more</li>
                <li>Structured AI insights with health scoring</li>
                <li>Cross-plane session correlation</li>
              </ul>
            </div>
            <div className="hero-upload">
              <FileUpload onUploadComplete={handleUploadComplete} apiUrl={API_URL} />
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
              onNewAnalysis={handleNewAnalysis}
            />
          </ErrorBoundary>
        )}
      </main>
    </div>
  );
}

export default App;
