#!/bin/bash

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="${1:-vault}"

echo ""
echo -e "${BOLD}{ vault } setup${NC}"
echo ""

# Check Docker
if ! command -v docker &>/dev/null; then
    echo -e "${RED}Docker is not installed. Please install it first: https://docs.docker.com/get-docker/${NC}"
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo -e "${RED}Docker Compose v2 is required. Please update Docker.${NC}"
    exit 1
fi

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "Installing into: $(pwd)"
echo ""

# Download docker-compose.yml
echo "Downloading docker-compose.yml..."
curl -fsSL "https://raw.githubusercontent.com/bungleware/vault/main/docker-compose.yml" -o docker-compose.yml

# Generate .env
echo "Generating .env..."
JWT_SECRET=$(openssl rand -base64 32)
SIGNED_URL_SECRET=$(openssl rand -base64 32)
TOKEN_PEPPER=$(openssl rand -base64 32)

cat > .env <<EOF
PORT=8080
DATA_DIR=/app/data

JWT_SECRET=${JWT_SECRET}
SIGNED_URL_SECRET=${SIGNED_URL_SECRET}
TOKEN_PEPPER=${TOKEN_PEPPER}

ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=720h
SIGNED_URL_TTL=5m

COOKIE_SECURE=true
COOKIE_SAMESITE=Lax
EOF

echo ""
echo -e "${YELLOW}Review .env before starting if you need to change the port or cookie settings.${NC}"
echo ""

read -rp "Start vault now? [Y/n] " answer
answer="${answer:-Y}"

if [[ "$answer" =~ ^[Yy]$ ]]; then
    docker compose up -d
    echo ""
    echo -e "${GREEN}${BOLD}Done.${NC} Vault is running at http://localhost:8080"
else
    echo ""
    echo "Run 'docker compose up -d' inside $(pwd) when ready."
fi

echo ""
echo "Useful commands:"
echo "  Logs:    docker compose logs -f"
echo "  Stop:    docker compose down"
echo "  Update:  docker compose pull && docker compose up -d"
echo ""
