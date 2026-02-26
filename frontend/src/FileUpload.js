import React, { useState, useRef } from 'react';

const PCAP_EXTENSIONS = ['.pcap', '.pcapng'];
const GROUNDHOG_EXTENSIONS = ['.html', '.htm', '.csv', '.xls', '.xlsx', '.json', '.xml'];

const FILE_KIND_CONFIG = {
  pcap: {
    accept: PCAP_EXTENSIONS.join(','),
    extensions: PCAP_EXTENSIONS,
    label: 'PCAP Network Capture',
    description: 'Drop your .pcap or .pcapng file here',
    icon: '📡',
  },
  groundhog: {
    accept: GROUNDHOG_EXTENSIONS.join(','),
    extensions: GROUNDHOG_EXTENSIONS,
    label: 'Radio Trace',
    description: 'Drop your radio trace file (HTML, CSV, XLS, XLSX, JSON, XML)',
    icon: '📻',
  },
};

function FileUpload({ onUploadComplete, apiUrl, fileKind = 'pcap', caseId = null }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState(null);
  const [timezone, setTimezone] = useState('Asia/Qatar');
  const fileInputRef = useRef(null);

  const config = FILE_KIND_CONFIG[fileKind] || FILE_KIND_CONFIG.pcap;

  const validateFile = (f) => {
    if (!f) return 'No file selected';
    const name = f.name.toLowerCase();
    const valid = config.extensions.some(ext => name.endsWith(ext));
    if (!valid) {
      return `Invalid file type. Accepted: ${config.extensions.join(', ')}`;
    }
    const maxSize = 100 * 1024 * 1024; // 100MB
    if (f.size > maxSize) {
      return `File too large (max 100 MB)`;
    }
    return null;
  };

  const handleFile = (f) => {
    const err = validateFile(f);
    if (err) {
      setError(err);
      setFile(null);
      return;
    }
    setError(null);
    setFile(f);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleFileInput = (e) => {
    if (e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      let response;

      if (caseId) {
        // Case-based upload
        const url = `${apiUrl}/api/cases/${caseId}/upload?file_kind=${fileKind}${timezone ? '&timezone=' + timezone : ''}`;
        response = await fetch(url, {
          method: 'POST',
          body: formData,
        });
      } else {
        // Legacy PCAP upload
        response = await fetch(`${apiUrl}/api/upload`, {
          method: 'POST',
          body: formData,
        });
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Upload failed (${response.status})`);
      }

      const data = await response.json();
      onUploadComplete(data);
    } catch (err) {
      setError(err.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="upload-container">
      <div
        className={`drop-zone ${dragOver ? 'drag-over' : ''} ${file ? 'has-file' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => !file && fileInputRef.current.click()}
      >
        {!file ? (
          <div className="drop-zone-content">
            <span className="drop-icon">{config.icon}</span>
            <p className="drop-text">{config.description}</p>
            <p className="drop-hint">or click to browse</p>
          </div>
        ) : (
          <div className="file-info">
            <span className="file-icon">{config.icon}</span>
            <div className="file-details">
              <span className="file-name">{file.name}</span>
              <span className="file-size">{formatSize(file.size)}</span>
            </div>
            <button
              className="file-remove"
              onClick={(e) => {
                e.stopPropagation();
                setFile(null);
              }}
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {error && <p className="upload-error">⚠️ {error}</p>}

      {fileKind === 'groundhog' && (
        <div className="timezone-selector">
          <label htmlFor="tz-select">Timezone:</label>
          <select
            id="tz-select"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
          >
            <option value="Asia/Qatar">Asia/Qatar (UTC+3)</option>
            <option value="UTC">UTC</option>
            <option value="GMT">GMT</option>
            <option value="AST">AST (UTC+3)</option>
            <option value="GST">GST (UTC+4)</option>
            <option value="IST">IST (UTC+5:30)</option>
            <option value="CET">CET (UTC+1)</option>
            <option value="EET">EET (UTC+2)</option>
            <option value="EST">EST (UTC-5)</option>
            <option value="PST">PST (UTC-8)</option>
          </select>
        </div>
      )}

      <div className="upload-actions">
        <button
          className="analyze-btn"
          onClick={handleUpload}
          disabled={!file || uploading}
        >
          {uploading ? `✨ Uploading ${config.label}...` : `✨ Upload ${config.label} ✨`}
        </button>
      </div>

      <input
        ref={fileInputRef}
        type="file"
        accept={config.accept}
        onChange={handleFileInput}
        style={{ display: 'none' }}
      />
    </div>
  );
}

export default FileUpload;
