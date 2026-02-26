import React from 'react';

function ProgressBar({ progress, stage, message, fileKind }) {
  // Use dynamic stages depending on what's active, or just a comprehensive list
  const stages = [
    { id: 'uploading', label: 'Uploading', icon: '☁️' },
    { id: 'pcap_analysis', label: 'PCAP Engine', icon: '📄' },
    { id: 'groundhog_analysis', label: 'Radio Parser', icon: '📻' },
    { id: 'correlation', label: 'Correlation', icon: '🔗' },
    { id: 'rca', label: 'AI Insights', icon: '🤖' },
  ];

  const getStageStatus = (stageId) => {
    const stageOrder = ['uploading', 'pcap_analysis', 'groundhog_analysis', 'correlation', 'rca', 'completed'];
    const currentIndex = stageOrder.indexOf(stage);
    const stageIndex = stageOrder.indexOf(stageId);

    if (currentIndex === -1) return 'pending'; // Unknown stage currently active
    if (stageIndex < currentIndex) return 'completed';
    if (stageIndex === currentIndex) return 'active';
    return 'pending';
  };

  return (
    <div className="progress-container">
      <div className="progress-header">
        <div className="spinner"></div>
        <h2>Analyzing Your Capture</h2>
        <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', fontSize: '1rem' }}>
          {message || 'Processing network data...'}
        </p>
      </div>

      <div className="progress-bar-container">
        <div
          className="progress-bar"
          style={{ width: `${progress}%` }}
        ></div>
      </div>

      <div className="progress-text">
        <span style={{
          background: 'linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          fontWeight: '700',
          fontSize: '1.1rem'
        }}>
          {progress}%
        </span>
        <span style={{ textTransform: 'capitalize', color: 'var(--text-dim)' }}>
          {stage || 'Initializing'}
        </span>
      </div>

      <div className="progress-stages">
        {stages.map((s) => {
          const status = getStageStatus(s.id);
          return (
            <div
              key={s.id}
              className={`progress-stage ${status}`}
            >
              <div className="stage-dot">
                {status === 'completed' ? '✓' : s.icon}
              </div>
              <div className="stage-label">{s.label}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default ProgressBar;
