#!/usr/bin/env bash
# DeepTrace one-shot bootstrap
#
# Usage:
#   git clone <repo>      # or unzip the release archive
#   cd <repo>
#   ./bootstrap.sh
#
# What it does (idempotent, safe to re-run):
#   1. Installs system packages: python3, python3-venv, python3-pip,
#      build-essential, nodejs (>=18), npm, tshark, nginx, bcrypt-tools deps.
#   2. Creates the Python venv at backend/venv and installs requirements.
#   3. Installs frontend npm deps and builds the React bundle.
#   4. Prompts for the /admin/llm password (no echo), bcrypt-hashes it.
#   5. Writes backend/.env from .env.example with ADMIN_USERNAME/HASH set.
#   6. Installs the systemd unit (deeptrace.service) bound to $USER.
#   7. Installs the nginx site (port 80 → uvicorn 127.0.0.1:8000).
#   8. Installs the daily 23:00 restart cron (privacy hygiene).
#   9. Reloads everything and smoke-tests /api/health.
#
# Requires: sudo, Debian/Ubuntu. Skip the LLM provider step — configure it
# from the dashboard via /admin/llm after first login.

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
    die "bootstrap.sh supports Linux only (detected $(uname -s))."
fi
if [[ ! -r /etc/os-release ]]; then
    die "/etc/os-release not readable — can't detect distro."
fi
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "Unsupported distro '${ID:-?}'. This script targets Debian/Ubuntu." ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_USER="$(whoami)"

if [[ "$RUN_USER" == "root" ]]; then
    die "Don't run bootstrap.sh as root. Run as a normal user with sudo access."
fi
if ! sudo -n true 2>/dev/null; then
    warn "This script will prompt for your sudo password as needed."
fi

REPO_BACKEND="$SCRIPT_DIR/backend"
REPO_FRONTEND="$SCRIPT_DIR/frontend"
REPO_SERVICE_TEMPLATE="$SCRIPT_DIR/deeptrace.service"

[[ -d "$REPO_BACKEND"  ]] || die "Missing $REPO_BACKEND — run this from the repo root."
[[ -d "$REPO_FRONTEND" ]] || die "Missing $REPO_FRONTEND — run this from the repo root."

c_cyan "DeepTrace bootstrap"
c_cyan "  repo dir : $SCRIPT_DIR"
c_cyan "  run user : $RUN_USER"
c_cyan "  distro   : $PRETTY_NAME"

# --- 1. apt packages --------------------------------------------------------
step "[1/9] Installing system packages"
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
PKGS=(
    python3 python3-venv python3-pip
    build-essential
    nodejs npm
    tshark
    nginx
    curl ca-certificates
)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${PKGS[@]}"
ok "system packages installed"

# Sanity check versions
PY_VER="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
NODE_VER="$(node --version 2>/dev/null | sed 's/^v//;s/\..*//')"
if [[ -z "$NODE_VER" || "$NODE_VER" -lt 18 ]]; then
    die "node 18+ required (found '${NODE_VER:-none}'). Upgrade nodejs and re-run."
fi
ok "python ${PY_VER}, node $(node --version), $(tshark --version 2>&1 | head -1)"

# Permit packet capture without root if not already configured
if ! getcap "$(command -v dumpcap)" 2>/dev/null | grep -q cap_net_raw; then
    sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v dumpcap)" || true
    ok "granted dumpcap packet-capture capabilities"
fi

# --- 2. Python venv + deps --------------------------------------------------
step "[2/9] Setting up Python virtual environment"
cd "$REPO_BACKEND"
if [[ ! -x "venv/bin/python" ]]; then
    python3 -m venv venv
    ok "created venv"
else
    ok "venv already present"
fi
./venv/bin/pip install --upgrade --quiet --disable-pip-version-check pip wheel
./venv/bin/pip install --no-cache-dir --quiet --disable-pip-version-check -r requirements.txt
ok "Python dependencies installed"

# --- 3. Frontend build ------------------------------------------------------
step "[3/9] Installing frontend dependencies and building the React bundle"
cd "$REPO_FRONTEND"
# Use ci when a lockfile exists for reproducibility, else install
if [[ -f package-lock.json ]]; then
    npm ci --no-audit --no-fund --loglevel=error
else
    npm install --no-audit --no-fund --loglevel=error
fi
NODE_OPTIONS="--max-old-space-size=768" GENERATE_SOURCEMAP=false CI=true \
    npm run build --loglevel=error
ok "frontend built ($(grep -oE 'main\.[a-z0-9]+\.js' build/index.html))"
cd "$SCRIPT_DIR"

# --- 4. .env: admin credentials --------------------------------------------
step "[4/9] Generating backend/.env (admin credentials)"
ENV_FILE="$REPO_BACKEND/.env"
ENV_EXAMPLE="$REPO_BACKEND/.env.example"
if [[ -f "$ENV_FILE" ]]; then
    warn ".env already exists at $ENV_FILE — leaving it as-is."
    warn "  (re-run bootstrap.sh after deleting it to regenerate)"
else
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    # Prompt for username
    read -r -p "    Admin username (for /admin/llm) [admin]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-admin}"

    # Prompt twice for password
    while :; do
        printf "    Admin password (no echo): "
        read -rs ADMIN_PASS; printf "\n"
        printf "    Confirm:                  "
        read -rs ADMIN_PASS2; printf "\n"
        if [[ -z "$ADMIN_PASS" ]]; then
            warn "Password cannot be empty."
        elif [[ "$ADMIN_PASS" != "$ADMIN_PASS2" ]]; then
            warn "Passwords don't match. Try again."
        else
            break
        fi
    done

    # bcrypt-hash via the venv (bcrypt is a Python dep)
    ADMIN_HASH="$("$REPO_BACKEND/venv/bin/python" -c '
import bcrypt, os, sys
pw = os.environ["P"].encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
' P="$ADMIN_PASS")"
    unset ADMIN_PASS ADMIN_PASS2

    # Replace ADMIN_USERNAME / ADMIN_PASSWORD_HASH in .env
    # Single-quote the hash so $ chars aren't shell-interpolated when sourced
    python3 - "$ENV_FILE" "$ADMIN_USER" "$ADMIN_HASH" <<'PY'
import re, sys
path, user, h = sys.argv[1:4]
text = open(path).read()
text = re.sub(r'^ADMIN_USERNAME=.*$',      f'ADMIN_USERNAME={user}',    text, flags=re.M)
text = re.sub(r"^ADMIN_PASSWORD_HASH=.*$", f"ADMIN_PASSWORD_HASH='{h}'", text, flags=re.M)
open(path, 'w').write(text)
PY
    chmod 600 "$ENV_FILE"
    ok "wrote $ENV_FILE (perms 600), admin user '$ADMIN_USER'"
fi

# --- 5. systemd unit --------------------------------------------------------
step "[5/9] Installing systemd unit"
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

# --- 6. nginx site ----------------------------------------------------------
step "[6/9] Installing nginx site"
sudo tee /etc/nginx/sites-available/deeptrace > /dev/null <<NGINX
server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 500M;

    root $REPO_FRONTEND/build;
    index index.html index.htm;

    # Admin + report pages served by the backend. Must precede location /
    location /admin/  { proxy_pass http://127.0.0.1:8000/admin/;  include /etc/nginx/proxy_params; proxy_http_version 1.1; }
    location /report/ { proxy_pass http://127.0.0.1:8000/report/; include /etc/nginx/proxy_params; proxy_http_version 1.1; }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        include /etc/nginx/proxy_params;
        proxy_http_version 1.1;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGINX
sudo ln -sfn /etc/nginx/sites-available/deeptrace /etc/nginx/sites-enabled/deeptrace
# Disable the default catch-all if present so it doesn't fight our default_server
if [[ -e /etc/nginx/sites-enabled/default ]]; then
    sudo rm -f /etc/nginx/sites-enabled/default
    ok "removed conflicting /etc/nginx/sites-enabled/default"
fi
sudo nginx -t
sudo systemctl enable nginx >/dev/null
sudo systemctl reload nginx
ok "nginx reloaded"

# --- 7. Daily restart cron --------------------------------------------------
step "[7/9] Installing daily 23:00 restart cron (privacy hygiene)"
sudo tee /etc/cron.d/deeptrace-restart > /dev/null <<'CRON'
# DeepTrace privacy hygiene: nightly restart wipes in-memory + on-disk state.
0 23 * * * root systemctl restart deeptrace.service
CRON
sudo chmod 644 /etc/cron.d/deeptrace-restart
ok "/etc/cron.d/deeptrace-restart installed"

# --- 8. Start backend -------------------------------------------------------
step "[8/9] Starting the backend"
sudo systemctl restart deeptrace.service
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    state="$(systemctl is-active deeptrace.service || true)"
    if [[ "$state" == "active" ]]; then
        ok "deeptrace.service is active"
        break
    fi
    [[ $i -eq 10 ]] && die "deeptrace.service failed to come up; check 'journalctl -u deeptrace -n 50'"
done

# --- 9. Smoke test ----------------------------------------------------------
step "[9/9] Smoke-testing endpoints"
HEALTH_CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/health || true)"
if [[ "$HEALTH_CODE" == "200" ]]; then
    ok "uvicorn /api/health: HTTP 200"
else
    die "uvicorn health probe failed (HTTP $HEALTH_CODE)"
fi
NGINX_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: localhost' http://127.0.0.1/api/health || true)"
if [[ "$NGINX_CODE" == "200" ]]; then
    ok "nginx :80 proxy: HTTP 200"
else
    warn "nginx proxy probe returned $NGINX_CODE — check nginx config"
fi

# --- done -------------------------------------------------------------------
PUBLIC_URL="http://$(hostname -I | awk '{print $1}')"
echo
c_green "============================================================"
c_green "  DeepTrace is up."
c_green "============================================================"
echo
echo "  Dashboard       : $PUBLIC_URL/"
echo "  Admin (LLM cfg) : $PUBLIC_URL/admin/llm"
echo "  Logs            : sudo journalctl -u deeptrace -f"
echo "  Restart         : sudo systemctl restart deeptrace"
echo
c_yellow "Next steps:"
echo "  1. Open the dashboard and confirm the page loads."
echo "  2. Sign in to /admin/llm (Basic Auth) with the credentials you just set"
echo "     and configure your LLM provider + model + API key."
echo "  3. Upload a PCAP / Groundhog / Huawei IMS trace from the dashboard."
echo
echo "Re-running bootstrap.sh is safe: it skips already-completed steps."
