#!/bin/bash

set -e

BOLD='\033[1m' GREEN='\033[0;32m' DIM='\033[2m' NC='\033[0m'

step() { echo -e "  ${DIM}→${NC} $1"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }

echo ""
echo -e "${BOLD}  vault${NC} update"
echo ""

# Stop and remove containers
step "Stopping containers..."
docker-compose down

# Remove the old image to force a fresh pull
step "Removing old image..."
docker rmi ghcr.io/bungleware/vault:main 2>/dev/null || true

# Start services
step "Starting services..."
docker-compose up -d --force-recreate

echo ""
ok "Update complete!"
echo ""
echo -e "  ${DIM}To verify: docker exec vault-server ls -lah /app/frontend/dist/assets/ | head -5${NC}"
echo ""
