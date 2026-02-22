#!/bin/bash
set -e

BOLD='\033[1m' GREEN='\033[0;32m' YELLOW='\033[1;33m' RED='\033[0;31m' DIM='\033[2m' NC='\033[0m'

fail() { echo -e "\n${RED}$1${NC}\n"; exit 1; }
step() { echo -e "  ${DIM}→${NC} $1"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }

# Prompt with a default value: ask "Label" DEFAULT_VALUE
# Returns result in $REPLY
ask() {
    local prompt="$1" default="$2"
    echo -ne "  ${BOLD}${prompt}${NC} ${DIM}[${default}]${NC}: "
    read -r REPLY
    REPLY="${REPLY:-$default}"
}

# Check if a port is in use
port_in_use() {
    lsof -iTCP:"$1" -sTCP:LISTEN &>/dev/null 2>&1 || ss -tlnp 2>/dev/null | grep -q ":$1 "
}

# Find next available port starting from $1
next_available_port() {
    local port="$1"
    while port_in_use "$port"; do
        port=$((port + 1))
    done
    echo "$port"
}

INSTALL_DIR="${1:-vault}"
REPO="bungleware/vault"

echo ""
echo -e "${BOLD}  vault${NC} setup"
echo ""

# Prerequisites
command -v docker &>/dev/null || fail "Docker is not installed. https://docs.docker.com/get-docker/"
docker compose version &>/dev/null || fail "Docker Compose v2 is required. Please update Docker."

# Install
mkdir -p "$INSTALL_DIR" && cd "$INSTALL_DIR"
step "Installing to $(pwd)"

step "Downloading docker-compose.yml"
curl -fsSL "https://raw.githubusercontent.com/$REPO/main/docker-compose.yml" -o docker-compose.yml
ok "docker-compose.yml"

step "Downloading update.sh"
curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/update.sh" -o update.sh
chmod +x update.sh
ok "update.sh"

echo ""
echo -e "  ${BOLD}Configuration${NC} ${DIM}(press Enter to accept defaults)${NC}"
echo ""

# --- Port ---
DEFAULT_PORT=$(next_available_port 8080)
if [ "$DEFAULT_PORT" != "8080" ]; then
    echo -e "  ${YELLOW}Port 8080 is in use.${NC}"
fi
while true; do
    ask "Port" "$DEFAULT_PORT"
    PORT="$REPLY"
    if [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
        break
    fi
    echo -e "  ${RED}Invalid port. Enter a number between 1 and 65535.${NC}"
done

# --- Data directory ---
while true; do
    ask "Data directory (host path)" "./data"
    DATA_DIR_HOST="$REPLY"
    [ -n "$DATA_DIR_HOST" ] && break
    echo -e "  ${RED}Data directory cannot be empty.${NC}"
done

# --- Secrets ---
echo -ne "  ${BOLD}Auto-generate secrets?${NC} ${DIM}[Y/n]${NC}: "
read -r GEN_SECRETS
GEN_SECRETS="${GEN_SECRETS:-Y}"

if [[ "$GEN_SECRETS" =~ ^[Yy]$ ]]; then
    JWT_SECRET=$(openssl rand -base64 32)
    SIGNED_URL_SECRET=$(openssl rand -base64 32)
    TOKEN_PEPPER=$(openssl rand -base64 32)
    ok "Secrets generated"
else
    ask "JWT_SECRET" ""; JWT_SECRET="$REPLY"
    ask "SIGNED_URL_SECRET" ""; SIGNED_URL_SECRET="$REPLY"
    ask "TOKEN_PEPPER" ""; TOKEN_PEPPER="$REPLY"
    [ -z "$JWT_SECRET" ] || [ -z "$SIGNED_URL_SECRET" ] || [ -z "$TOKEN_PEPPER" ] && fail "All three secrets are required."
fi

# --- Write .env ---
echo ""
step "Generating .env"
cat > .env <<EOF
HOST_PORT=$PORT

JWT_SECRET=$JWT_SECRET
SIGNED_URL_SECRET=$SIGNED_URL_SECRET
TOKEN_PEPPER=$TOKEN_PEPPER

ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=720h
SIGNED_URL_TTL=5m
EOF
ok ".env"

mkdir -p "$DATA_DIR_HOST" && chmod 777 "$DATA_DIR_HOST"
ok "Data directory ready: $DATA_DIR_HOST"

# --- Update volume mount if custom data dir ---
if [ "$DATA_DIR_HOST" != "./data" ]; then
    sed -i.bak "s|./data:/app/data|${DATA_DIR_HOST}:/app/data|" docker-compose.yml && rm -f docker-compose.yml.bak
    ok "docker-compose.yml updated with data directory: $DATA_DIR_HOST"
fi

# --- Summary ---
echo ""
echo -e "  ${BOLD}Summary${NC}"
echo -e "  ${DIM}Port:${NC}           $PORT"
echo -e "  ${DIM}Data:${NC}           $DATA_DIR_HOST"
echo ""

read -rp "  Start vault now? [Y/n] " answer
if [[ "${answer:-Y}" =~ ^[Yy]$ ]]; then
    docker compose up -d
    echo ""
    echo -e "  ${GREEN}${BOLD}Vault is running at http://localhost:$PORT${NC}"
else
    echo ""
    echo -e "  Run ${BOLD}docker compose up -d${NC} inside $(pwd) when ready."
fi

echo ""
echo -e "  ${DIM}Logs:   docker compose logs -f${NC}"
echo -e "  ${DIM}Stop:   docker compose down${NC}"
echo -e "  ${DIM}Update: docker compose pull && docker compose up -d${NC}"
echo ""
