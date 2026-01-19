import React from 'react';

function ProgressBar({ progress, stage, message }) {
  const stages = [
    { id: 'uploading', label: 'Uploading', icon: '☁️', description: 'Sending file' },
    { id: 'parsing', label: 'Parsing', icon: '📄', description: 'Reading packets' },
    { id: 'analyzing', label: 'Analyzing', icon: '🔍', description: 'Detecting protocols' },
    { id: 'enriching', label: 'AI Insights', icon: '🤖', description: 'Deep analysis' },
    { id: 'completed', label: 'Complete', icon: '✅', description: 'Ready!' },
  ];

  const getStageStatus = (stageId) => {
    const stageOrder = ['uploading', 'parsing', 'analyzing', 'enriching', 'completed'];
    const currentIndex = stageOrder.indexOf(stage);
    const stageIndex = stageOrder.indexOf(stageId);

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
