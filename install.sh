#!/usr/bin/env bash
set -euo pipefail

# XMonitor Installer
# Usage: sudo bash install.sh

INSTALL_DIR="/opt/xmonitor"
SERVICE_NAME="xmonitor"
DEFAULT_PORT=8080
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; exit 1; }

# --- Pre-checks ---
[[ $EUID -ne 0 ]] && err "This script must be run as root (use sudo)"

log "XMonitor Installer"
echo "========================================"

# --- Detect OS ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi
log "Detected OS: $OS"

# --- Install dependencies ---
log "Checking dependencies..."

install_pkg() {
    local pkg=$1
    if ! command -v "$pkg" &>/dev/null; then
        warn "$pkg not found, installing..."
        case $OS in
            ubuntu|debian)
                apt-get update -qq && apt-get install -y -qq "$pkg" ;;
            centos|rhel|rocky|alma|fedora)
                dnf install -y -q "$pkg" 2>/dev/null || yum install -y -q "$pkg" ;;
            arch|manjaro)
                pacman -S --noconfirm "$pkg" ;;
            *)
                err "Cannot auto-install $pkg on $OS. Please install manually." ;;
        esac
    else
        log "$pkg: OK"
    fi
}

# Python 3
if ! command -v python3 &>/dev/null; then
    warn "Python3 not found, installing..."
    case $OS in
        ubuntu|debian) apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip ;;
        centos|rhel|rocky|alma|fedora) dnf install -y -q python3 python3-pip ;;
        arch|manjaro) pacman -S --noconfirm python python-pip ;;
        *) err "Please install Python 3.10+ manually" ;;
    esac
else
    log "Python3: OK ($(python3 --version))"
fi

# Ensure venv module
python3 -c "import venv" 2>/dev/null || {
    warn "python3-venv not found, installing..."
    case $OS in
        ubuntu|debian) apt-get install -y -qq python3-venv ;;
        *) : ;;
    esac
}

# vnstat
install_pkg vnstat

# Enable and start vnstat
systemctl enable vnstat &>/dev/null || true
systemctl start vnstat &>/dev/null || true
log "vnstat service started"

# --- Install XMonitor ---
log "Installing XMonitor to $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR"

# Copy files
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp -r "$SCRIPT_DIR"/app "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR"/static "$INSTALL_DIR/"
cp "$SCRIPT_DIR"/requirements.txt "$INSTALL_DIR/"
cp "$SCRIPT_DIR"/run.py "$INSTALL_DIR/"

# Create data directory
mkdir -p "$INSTALL_DIR/data"

# --- Virtual environment ---
log "Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
log "Python dependencies installed"

# --- Generate config ---
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    log "Generating configuration..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    DEFAULT_PASS="admin"
    PASS_HASH=$("$INSTALL_DIR/venv/bin/python" -c "import bcrypt; print(bcrypt.hashpw(b'$DEFAULT_PASS', bcrypt.gensalt()).decode())")
    SERVER_ID=$(python3 -c "import uuid; print(uuid.uuid4())")

    cat > "$INSTALL_DIR/config.yaml" <<EOF
server:
  host: "0.0.0.0"
  port: $DEFAULT_PORT
  secret_key: "$SECRET_KEY"

auth:
  username: "admin"
  password_hash: "$PASS_HASH"
  ip_whitelist: []
  rate_limit_attempts: 5
  rate_limit_window: 60

monitoring:
  interfaces: []
  collection_interval: 2
  history_collection_interval: 60
  history_retention_days: 30
  vnstat_cache_ttl: 1

master_server:
  enabled: false
  url: ""
  api_key: ""
  server_id: "$SERVER_ID"
EOF
    log "Config generated with random secret key"
else
    warn "Config already exists, keeping existing"
fi

# --- systemd service ---
log "Installing systemd service..."
cp "$SCRIPT_DIR/xmonitor.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
log "Service installed and started"

# --- Done ---
echo ""
echo "========================================"
echo -e "${GREEN}XMonitor installed successfully!${NC}"
echo "========================================"
echo ""

# Get server IP
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
echo -e "  Dashboard:  ${CYAN}http://${SERVER_IP}:${DEFAULT_PORT}${NC}"
echo -e "  Username:   ${CYAN}admin${NC}"
echo -e "  Password:   ${CYAN}admin${NC}"
echo ""
echo -e "  ${YELLOW}IMPORTANT: Change the default password!${NC}"
echo -e "  Generate a new hash:"
echo -e "    ${INSTALL_DIR}/venv/bin/python -c \"import bcrypt; print(bcrypt.hashpw(b'YOUR_NEW_PASSWORD', bcrypt.gensalt()).decode())\""
echo -e "  Then update password_hash in: ${INSTALL_DIR}/config.yaml"
echo ""
echo "  Service commands:"
echo "    systemctl status $SERVICE_NAME"
echo "    systemctl restart $SERVICE_NAME"
echo "    journalctl -u $SERVICE_NAME -f"
echo ""
