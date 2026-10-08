#!/usr/bin/env bash
# DeepTrace Red Hat Linux Bootstrap
#
# Supported distros:
#   RHEL 8 / 9, CentOS Stream 8 / 9, Rocky Linux 8 / 9, AlmaLinux 8 / 9,
#   Fedora 38+, Oracle Linux 8 / 9.
#
# What it does (idempotent, safe to re-run):
#   1. Detects Red Hat family distribution and enables EPEL/CRB repos.
#   2. Installs system packages via dnf/yum: Python 3.9+, gcc, development headers,
#      wireshark-cli (tshark + dumpcap), nginx, cronie, policycoreutils, firewalld tools.
#   3. Installs Node.js 18+ (NodeSource 20 LTS if needed) & npm.
#   4. Grants dumpcap packet-capture capabilities (cap_net_raw, cap_net_admin).
#   5. Creates backend/venv and installs Python dependencies.
#   6. Installs frontend dependencies and builds production React bundle.
#   7. Configures admin credentials in backend/.env with bcrypt hash.
#   8. Installs systemd service (deeptrace.service) bound to the current user.
#   9. Installs native Nginx site at /etc/nginx/conf.d/deeptrace.conf.
#  10. Configures SELinux booleans (httpd_can_network_connect) and file contexts.
#  11. Configures firewalld to allow HTTP port 80.
#  12. Installs daily 23:00 privacy hygiene restart cron (crond).
#  13. Starts services and smoke-tests endpoints.

set -euo pipefail

# --- helpers ----------------------------------------------------------------
c_red()    { printf '\033[31m%s\033[0m\n' "$*"; }
c_green()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
c_cyan()   { printf '\033[36m%s\033[0m\n' "$*"; }
step() { c_cyan ""; c_cyan "==> $*"; }
ok()   { c_green "    ✓ $*"; }
warn() { c_yellow "    ! $*"; }
die()  { c_red   "    ✗ $*"; exit 1; }

# --- pre-flight -------------------------------------------------------------
if [[ "$(uname -s)" != "Linux" ]]; then
    die "bootstrap-rhel.sh supports Linux only (detected $(uname -s))."
fi
if [[ ! -r /etc/os-release ]]; then
    die "/etc/os-release not readable — cannot detect distro."
fi

. /etc/os-release
DISTRO_ID="${ID:-}"
DISTRO_LIKE="${ID_LIKE:-}"
DISTRO_VER="${VERSION_ID:-}"
MAJOR_VER="${DISTRO_VER%%.*}"

IS_RHEL_FAMILY=false
case "$DISTRO_ID" in
    rhel|centos|rocky|almalinux|fedora|ol) IS_RHEL_FAMILY=true ;;
    *)
        if [[ "$DISTRO_LIKE" =~ (rhel|centos|fedora) ]]; then
            IS_RHEL_FAMILY=true
        fi
        ;;
esac

if [[ "$IS_RHEL_FAMILY" != "true" ]]; then
    die "Unsupported distribution '${DISTRO_ID}'. bootstrap-rhel.sh is designed for RHEL, CentOS, Rocky Linux, AlmaLinux, Fedora, and Oracle Linux."
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_USER="$(whoami)"

if [[ "$RUN_USER" == "root" ]]; then
    die "Don't run bootstrap-rhel.sh as root. Run as a normal user with sudo privileges."
fi

if ! sudo -n true 2>/dev/null; then
    warn "This script will prompt for your sudo password as needed."
fi

REPO_BACKEND="$SCRIPT_DIR/backend"
REPO_FRONTEND="$SCRIPT_DIR/frontend"

[[ -d "$REPO_BACKEND"  ]] || die "Missing $REPO_BACKEND — run this from the repo root."
[[ -d "$REPO_FRONTEND" ]] || die "Missing $REPO_FRONTEND — run this from the repo root."

# Package manager
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    die "Neither dnf nor yum found."
fi

c_cyan "============================================================"
c_cyan "  DeepTrace Red Hat Linux Bootstrap"
c_cyan "============================================================"
c_cyan "  Repo root : $SCRIPT_DIR"
c_cyan "  Run user  : $RUN_USER"
c_cyan "  Distro    : ${PRETTY_NAME:-$DISTRO_ID}"
c_cyan "  Pkg Mgr   : $PKG_MGR"
c_cyan "============================================================"

# --- 1. Repositories (EPEL / CRB) -------------------------------------------
step "[1/11] Setting up package repositories"
if [[ "$DISTRO_ID" != "fedora" ]]; then
    # Enable CRB / PowerTools for build dependencies
    if command -v dnf >/dev/null 2>&1; then
        sudo dnf config-manager --set-enabled crb 2>/dev/null || \
        sudo dnf config-manager --set-enabled powertools 2>/dev/null || true
    fi

    # Enable EPEL
    if ! rpm -q epel-release >/dev/null 2>&1; then
        sudo $PKG_MGR install -y epel-release 2>/dev/null || \
        sudo $PKG_MGR install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${MAJOR_VER:-9}.noarch.rpm" 2>/dev/null || \
        warn "Could not auto-install epel-release; continuing with available repositories."
    fi
fi
ok "repositories configured"

# --- 2. System Packages -----------------------------------------------------
step "[2/11] Installing required system packages"
SYSTEM_PKGS=(
    gcc gcc-c++ make
    libxml2-devel libxslt-devel
    libpcap-devel
    libffi-devel openssl-devel
    wireshark-cli libcap
    nginx
    curl ca-certificates tar
    policycoreutils-python-utils
    cronie
)

sudo $PKG_MGR install -y "${SYSTEM_PKGS[@]}"
ok "base system packages installed"

# --- 3. Python 3.9+ ---------------------------------------------------------
step "[3/11] Ensuring Python 3.9+ runtime & development tools"
find_python() {
    for candidate in python3.12 python3.11 python3.10 python3.9 python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            ver="$("$candidate" -c 'import sys; print("%d.%d"%sys.version_info[:2])' 2>/dev/null || true)"
            maj="${ver%%.*}"
            min="${ver#*.}"
            if [[ "$maj" -eq 3 && "$min" -ge 9 ]]; then
                echo "$(command -v "$candidate")"
                return 0
            fi
        fi
    done
    return 1
}

PY_BIN="$(find_python || true)"
if [[ -z "$PY_BIN" ]]; then
    warn "Python >= 3.9 not found. Attempting to install Python 3.11..."
    sudo $PKG_MGR install -y python3.11 python3.11-devel python3.11-pip 2>/dev/null || \
    sudo $PKG_MGR install -y python39 python39-devel python39-pip 2>/dev/null || \
    sudo $PKG_MGR install -y python3-devel python3-pip || true
    PY_BIN="$(find_python || true)"
fi

if [[ -z "$PY_BIN" ]]; then
    die "Python >= 3.9 is required. Please install python3.9 or python3.11 and re-run."
fi

# Ensure devel package matching python is present
PY_SHORT_VER="$("$PY_BIN" -c 'import sys; print("%d%d"%sys.version_info[:2])')"
sudo $PKG_MGR install -y "python${PY_SHORT_VER}-devel" "python${PY_SHORT_VER}-pip" 2>/dev/null || \
sudo $PKG_MGR install -y python3-devel python3-pip 2>/dev/null || true

ok "using $($PY_BIN --version 2>&1) at $PY_BIN"

# --- 4. Node.js (>= 18) -----------------------------------------------------
step "[4/11] Checking Node.js and npm"
NEED_NODE_INSTALL=true
if command -v node >/dev/null 2>&1; then
    NODE_VER="$(node --version 2>/dev/null | sed 's/^v//;s/\..*//')"
    if [[ -n "$NODE_VER" && "$NODE_VER" -ge 18 ]]; then
        NEED_NODE_INSTALL=false
        ok "Node.js $(node --version) is already installed (>= 18)"
    fi
fi

if [[ "$NEED_NODE_INSTALL" == "true" ]]; then
    step "Installing Node.js 20 LTS via NodeSource"
    curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
    sudo $PKG_MGR install -y nodejs
    NODE_VER="$(node --version 2>/dev/null | sed 's/^v//;s/\..*//')"
    if [[ -z "$NODE_VER" || "$NODE_VER" -lt 18 ]]; then
        die "Failed to install Node.js 18+. Found '${NODE_VER:-none}'."
    fi
    ok "Node.js $(node --version) installed"
fi

# --- 5. Packet capture permissions ------------------------------------------
step "[5/11] Setting up packet capture permissions"
DUMPCAP_BIN="$(command -v dumpcap || which dumpcap 2>/dev/null || true)"
if [[ -z "$DUMPCAP_BIN" && -f /usr/sbin/dumpcap ]]; then
    DUMPCAP_BIN="/usr/sbin/dumpcap"
elif [[ -z "$DUMPCAP_BIN" && -f /usr/bin/dumpcap ]]; then
    DUMPCAP_BIN="/usr/bin/dumpcap"
fi

if [[ -n "$DUMPCAP_BIN" && -x "$DUMPCAP_BIN" ]]; then
    if ! getcap "$DUMPCAP_BIN" 2>/dev/null | grep -q cap_net_raw; then
        sudo setcap cap_net_raw,cap_net_admin+eip "$DUMPCAP_BIN" || true
    fi
    ok "dumpcap capabilities configured on $DUMPCAP_BIN"
else
    warn "dumpcap executable not found; skipping capabilities setup"
fi

if getent group wireshark >/dev/null 2>&1; then
    sudo usermod -aG wireshark "$RUN_USER" 2>/dev/null || true
fi

# --- 6. Python venv & dependencies -----------------------------------------
step "[6/11] Setting up Python virtual environment"
cd "$REPO_BACKEND"
if [[ ! -x "venv/bin/python" ]]; then
    "$PY_BIN" -m venv venv
    ok "created Python venv at backend/venv"
else
    ok "Python venv already exists at backend/venv"
fi
./venv/bin/pip install --upgrade --quiet --disable-pip-version-check pip wheel
./venv/bin/pip install --no-cache-dir --quiet --disable-pip-version-check -r requirements.txt
ok "Python backend dependencies installed"
cd "$SCRIPT_DIR"

# --- 7. Frontend build ------------------------------------------------------
step "[7/11] Building React frontend"
cd "$REPO_FRONTEND"
if [[ -f package-lock.json ]]; then
    npm ci --no-audit --no-fund --loglevel=error || npm install --no-audit --no-fund --loglevel=error
else
    npm install --no-audit --no-fund --loglevel=error
fi
NODE_OPTIONS="--max-old-space-size=768" GENERATE_SOURCEMAP=false CI=true \
    npm run build --loglevel=error
ok "frontend built successfully"
cd "$SCRIPT_DIR"

# --- 8. Admin credentials (.env) --------------------------------------------
step "[8/11] Generating backend/.env (admin credentials)"
ENV_FILE="$REPO_BACKEND/.env"
ENV_EXAMPLE="$REPO_BACKEND/.env.example"

if [[ -f "$ENV_FILE" ]]; then
    warn ".env already exists at $ENV_FILE — keeping existing configuration."
    warn "  (delete $ENV_FILE and re-run bootstrap to regenerate)"
else
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    # Allow automated non-interactive setup if environment variables are provided
    if [[ -n "${DEEPTRACE_ADMIN_USER:-}" && -n "${DEEPTRACE_ADMIN_PASS:-}" ]]; then
        ADMIN_USER="$DEEPTRACE_ADMIN_USER"
        ADMIN_PASS="$DEEPTRACE_ADMIN_PASS"
    else
        read -r -p "    Admin username (for /admin/llm) [admin]: " ADMIN_USER
        ADMIN_USER="${ADMIN_USER:-admin}"

        while :; do
            printf "    Admin password (no echo): "
            read -rs ADMIN_PASS; printf "\n"
            printf "    Confirm password:         "
            read -rs ADMIN_PASS2; printf "\n"
            if [[ -z "$ADMIN_PASS" ]]; then
                warn "Password cannot be empty."
            elif [[ "$ADMIN_PASS" != "$ADMIN_PASS2" ]]; then
                warn "Passwords don't match. Try again."
            else
                break
            fi
        done
    fi

    ADMIN_HASH="$("$REPO_BACKEND/venv/bin/python" -c '
import bcrypt, os
pw = os.environ["P"].encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
' P="$ADMIN_PASS")"
    unset ADMIN_PASS ADMIN_PASS2

    "$REPO_BACKEND/venv/bin/python" - "$ENV_FILE" "$ADMIN_USER" "$ADMIN_HASH" <<'PY'
import re, sys
path, user, h = sys.argv[1:4]
text = open(path).read()
text = re.sub(r'^ADMIN_USERNAME=.*$',      f'ADMIN_USERNAME={user}',    text, flags=re.M)
text = re.sub(r"^ADMIN_PASSWORD_HASH=.*$", f"ADMIN_PASSWORD_HASH='{h}'", text, flags=re.M)
open(path, 'w').write(text)
PY
    chmod 600 "$ENV_FILE"
    ok "wrote $ENV_FILE (mode 600) with admin user '$ADMIN_USER'"
fi

# --- 9. systemd unit --------------------------------------------------------
step "[9/11] Installing systemd service"
TMP_UNIT="$(mktemp)"
cat > "$TMP_UNIT" <<EOF
[Unit]
Description=DeepTrace - PCAP/Trace Analyzer Backend
After=network.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
WorkingDirectory=$REPO_BACKEND
Environment="PATH=$REPO_BACKEND/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$REPO_BACKEND/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
sudo install -m 0644 -o root -g root "$TMP_UNIT" /etc/systemd/system/deeptrace.service
rm -f "$TMP_UNIT"
sudo systemctl daemon-reload
sudo systemctl enable deeptrace.service >/dev/null
ok "/etc/systemd/system/deeptrace.service installed and enabled"

# --- 10. Nginx, SELinux, and Firewalld ---------------------------------------
step "[10/11] Configuring Nginx, SELinux, and Firewall"

# Ensure /etc/nginx/conf.d exists
sudo mkdir -p /etc/nginx/conf.d

# Write native Red Hat Nginx server block (self-contained proxy headers)
TMP_NGINX="$(mktemp)"
cat > "$TMP_NGINX" <<EOF
server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 500M;

    root $REPO_FRONTEND/build;
    index index.html index.htm;

    # Admin + report pages served by backend
    location /admin/ {
        proxy_pass http://127.0.0.1:8000/admin/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /report/ {
        proxy_pass http://127.0.0.1:8000/report/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
sudo install -m 0644 -o root -g root "$TMP_NGINX" /etc/nginx/conf.d/deeptrace.conf
rm -f "$TMP_NGINX"

# Disable conflicting default server block in /etc/nginx/nginx.conf if present
if [[ -f /etc/nginx/nginx.conf ]]; then
    if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
        sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    fi

    sudo "$PY_BIN" - <<'PY' || true
import re
conf_path = '/etc/nginx/nginx.conf'
try:
    with open(conf_path, 'r') as f:
        content = f.read()
    if 'default_server' in content:
        content_new = re.sub(r'(\blisten\s+[^;]*)\bdefault_server\b', r'\1', content)
        if content_new != content:
            with open(conf_path, 'w') as f:
                f.write(content_new)
except Exception:
    pass
PY
fi

# SELinux adjustments for Red Hat
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
    step "Applying SELinux policies"
    # Allow Nginx to connect upstream to 127.0.0.1:8000
    sudo setsebool -P httpd_can_network_connect 1 || warn "Could not set httpd_can_network_connect"

    # Ensure nginx user can traverse home directory
    chmod o+rx "$HOME" || true
    chmod -R o+rx "$REPO_FRONTEND/build" || true

    # Label frontend static files for web server access
    sudo chcon -R -t httpd_sys_content_t "$REPO_FRONTEND/build" 2>/dev/null || true
    if command -v semanage >/dev/null 2>&1; then
        sudo semanage fcontext -a -t httpd_sys_content_t "$REPO_FRONTEND/build(/.*)?" 2>/dev/null || true
        sudo restorecon -R "$REPO_FRONTEND/build" 2>/dev/null || true
    fi
    ok "SELinux permissions and contexts configured"
fi

# Firewall (firewalld)
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    sudo firewall-cmd --permanent --add-service=http 2>/dev/null || sudo firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
    sudo firewall-cmd --reload 2>/dev/null || true
    ok "firewalld allowed HTTP traffic (port 80)"
fi

# Test and enable Nginx
sudo nginx -t
sudo systemctl enable nginx >/dev/null 2>&1 || true
sudo systemctl restart nginx
ok "Nginx configured, enabled, and restarted"

# --- 11. Cron & Startup ----------------------------------------------------
step "[11/11] Setting up cron and starting DeepTrace"

# Daily 23:00 privacy hygiene restart
sudo tee /etc/cron.d/deeptrace-restart > /dev/null <<'CRON'
# DeepTrace privacy hygiene: nightly restart wipes in-memory + on-disk state.
0 23 * * * root systemctl restart deeptrace.service
CRON
sudo chmod 644 /etc/cron.d/deeptrace-restart

# Ensure cron service is active (crond on RHEL)
if systemctl list-unit-files crond.service &>/dev/null; then
    sudo systemctl enable --now crond.service >/dev/null 2>&1 || true
    ok "crond service enabled"
elif systemctl list-unit-files cron.service &>/dev/null; then
    sudo systemctl enable --now cron.service >/dev/null 2>&1 || true
    ok "cron service enabled"
fi

# Restart backend service
sudo systemctl restart deeptrace.service

for i in {1..15}; do
    sleep 1
    state="$(systemctl is-active deeptrace.service || true)"
    if [[ "$state" == "active" ]]; then
        ok "deeptrace.service is active"
        break
    fi
    [[ $i -eq 15 ]] && die "deeptrace.service failed to come up; inspect with 'journalctl -u deeptrace -n 50'"
done

# Smoke test
step "Smoke-testing services"
HEALTH_CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/health || true)"
if [[ "$HEALTH_CODE" == "200" ]]; then
    ok "Uvicorn direct backend /api/health: HTTP 200"
else
    die "Backend health probe failed (HTTP $HEALTH_CODE)"
fi

NGINX_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: localhost' http://127.0.0.1/api/health || true)"
if [[ "$NGINX_CODE" == "200" ]]; then
    ok "Nginx port 80 proxy /api/health: HTTP 200"
else
    warn "Nginx proxy probe returned HTTP $NGINX_CODE — verify /etc/nginx/conf.d/deeptrace.conf"
fi

# Done
IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")"
PUBLIC_URL="http://${IP_ADDR}"

echo
c_green "============================================================"
c_green "  DeepTrace is up and running on Red Hat Linux!"
c_green "============================================================"
echo
echo "  Dashboard       : $PUBLIC_URL/"
echo "  Admin (LLM cfg) : $PUBLIC_URL/admin/llm"
echo "  Logs            : sudo journalctl -u deeptrace -f"
echo "  Restart         : sudo systemctl restart deeptrace"
echo
c_yellow "Next steps:"
echo "  1. Open the dashboard in your browser ($PUBLIC_URL/)."
echo "  2. Sign in to /admin/llm (Basic Auth) with the admin credentials"
echo "     and configure your LLM provider, model, and API key."
echo "  3. Upload a PCAP, Groundhog, or Huawei IMS trace to begin analysis."
echo
echo "Re-running bootstrap-rhel.sh is safe: it skips already-completed steps."
