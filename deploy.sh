#!/bin/bash
# NetTrace AI Deployment Script
# Builds frontend and restarts backend service

set -e

echo "=== NetTrace AI Deployment ==="

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build Frontend
echo "[1/4] Building frontend..."
cd "$SCRIPT_DIR/frontend"
npm run build
echo "Frontend build complete."

# Install backend dependencies if needed
echo "[2/4] Checking backend dependencies..."
cd "$SCRIPT_DIR/backend"
if [ -f "venv/bin/pip" ]; then
    ./venv/bin/pip install -r requirements.txt -q
fi

# Create systemd service if it doesn't exist
echo "[3/4] Checking systemd service..."
SERVICE_FILE="/etc/systemd/system/nettrace-backend.service"

if [ ! -f "$SERVICE_FILE" ]; then
    echo "Creating systemd service file (requires sudo)..."
    sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=NetTrace AI Backend
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$SCRIPT_DIR/backend
ExecStart=$SCRIPT_DIR/backend/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable nettrace-backend
    echo "Systemd service created and enabled."
else
    echo "Systemd service already exists."
fi

# Restart service
echo "[4/4] Restarting backend service..."
sudo systemctl restart nettrace-backend

# Check status
sleep 2
if sudo systemctl is-active --quiet nettrace-backend; then
    echo ""
    echo "=== Deployment Complete ==="
    echo "Backend running on http://0.0.0.0:8000"
    echo "Service status: $(sudo systemctl is-active nettrace-backend)"
    echo ""
    echo "Useful commands:"
    echo "  View logs:    sudo journalctl -u nettrace-backend -f"
    echo "  Stop:         sudo systemctl stop nettrace-backend"
    echo "  Restart:      sudo systemctl restart nettrace-backend"
else
    echo "ERROR: Backend failed to start!"
    sudo journalctl -u nettrace-backend -n 20
    exit 1
fi
