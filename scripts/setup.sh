#!/bin/bash
set -e

BOLD='\033[1m' GREEN='\033[0;32m' YELLOW='\033[1;33m' RED='\033[0;31m' DIM='\033[2m' NC='\033[0m'

fail() { echo -e "\n${RED}$1${NC}\n"; exit 1; }
step() { echo -e "  ${DIM}→${NC} $1"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }

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

# Generate .env with secrets inline — no sed replacement needed
step "Generating .env"
cat > .env <<EOF
PORT=8080
DATA_DIR=/app/data

JWT_SECRET=$(openssl rand -base64 32)
SIGNED_URL_SECRET=$(openssl rand -base64 32)
TOKEN_PEPPER=$(openssl rand -base64 32)

ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=720h
SIGNED_URL_TTL=5m

COOKIE_SECURE=true
COOKIE_SAMESITE=Lax
EOF
ok ".env with generated secrets"

echo ""
echo -e "  ${YELLOW}Review $(pwd)/.env before starting.${NC}"
echo ""

read -rp "  Start vault now? [Y/n] " answer
if [[ "${answer:-Y}" =~ ^[Yy]$ ]]; then
    docker compose up -d
    echo ""
    echo -e "  ${GREEN}${BOLD}Vault is running at http://localhost:8080${NC}"
else
    echo ""
    echo -e "  Run ${BOLD}docker compose up -d${NC} inside $(pwd) when ready."
fi

echo ""
echo -e "  ${DIM}Logs:   docker compose logs -f${NC}"
echo -e "  ${DIM}Stop:   docker compose down${NC}"
echo -e "  ${DIM}Update: docker compose pull && docker compose up -d${NC}"
echo ""
