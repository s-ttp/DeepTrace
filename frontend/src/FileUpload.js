import React, { useState, useRef } from 'react';

function FileUpload({ onUploadComplete, apiUrl }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const validateFile = (selectedFile) => {
    if (!selectedFile) return false;
    
    const validExtensions = ['.pcap', '.pcapng'];
    const fileName = selectedFile.name.toLowerCase();
    
    if (!validExtensions.some(ext => fileName.endsWith(ext))) {
      setError('Please upload a .pcap or .pcapng file');
      return false;
    }
    
    // 500MB limit
    if (selectedFile.size > 500 * 1024 * 1024) {
      setError('File size exceeds 500MB limit');
      return false;
    }
    
    setError(null);
    return true;
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    
    const droppedFile = e.dataTransfer.files[0];
    if (validateFile(droppedFile)) {
      setFile(droppedFile);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleFileSelect = (e) => {
    const selectedFile = e.target.files[0];
    if (validateFile(selectedFile)) {
      setFile(selectedFile);
    }
  };

  const handleBrowseClick = () => {
    fileInputRef.current?.click();
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const handleUpload = async () => {
    if (!file) return;
    
    setUploading(true);
    setError(null);
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
      const response = await fetch(`${apiUrl}/api/upload`, {
        method: 'POST',
        body: formData,
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Upload failed');
      }
      
      const data = await response.json();
      onUploadComplete(data.job_id);
    } catch (error) {
      setError('Upload failed: ' + error.message);
      setUploading(false);
    }
  };

  return (
    <div className="upload-container">
      <div 
        className={`drop-zone ${dragOver ? 'drag-over' : ''} ${file ? 'has-file' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={!file ? handleBrowseClick : undefined}
      >
        {file ? (
          <>
            <div className="drop-zone-icon">✅</div>
            <div className="file-info">
              <div className="file-info-name">{file.name}</div>
              <div className="file-info-size">{formatFileSize(file.size)}</div>
            </div>
            <button 
              className="browse-btn" 
              onClick={(e) => { e.stopPropagation(); setFile(null); }}
            >
              Choose Different File
            </button>
          </>
        ) : (
          <>
            <div className="drop-zone-icon">📡</div>
            <h3>Drop Your Network Capture</h3>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
              or click to browse files
            </p>
            <p style={{ 
              fontSize: '0.8rem', 
              marginTop: '1.5rem', 
              color: 'var(--text-dim)', 
              lineHeight: '1.8',
              maxWidth: '280px',
              margin: '1.5rem auto 0'
            }}>
              Supports <strong style={{ color: 'var(--accent-secondary)' }}>.pcap</strong> and <strong style={{ color: 'var(--accent-secondary)' }}>.pcapng</strong> files<br/>
              Maximum file size: <strong style={{ color: 'var(--text-secondary)' }}>500 MB</strong>
            </p>
          </>
        )}
        
        <input 
          ref={fileInputRef}
          type="file" 
          accept=".pcap,.pcapng"
          onChange={handleFileSelect}
          style={{ display: 'none' }}
        />
      </div>
      
      {error && (
        <div className="error-message" style={{ marginTop: '1rem' }}>
          ⚠️ {error}
        </div>
      )}
      
      {file && !uploading && (
        <button onClick={handleUpload} className="analyze-btn">
          <span style={{ marginRight: '0.5rem' }}>🚀</span>
          Start AI Analysis
        </button>
      )}
      
      {uploading && (
        <button className="analyze-btn" disabled>
          <span className="spinner" style={{ 
            width: '20px', 
            height: '20px', 
            display: 'inline-block', 
            marginRight: '0.75rem', 
            borderWidth: '2px',
            verticalAlign: 'middle'
          }}></span>
          Uploading & Processing...
        </button>
      )}
    </div>
  );
}

export default FileUpload;
