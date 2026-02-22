#!/bin/bash

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' 

echo -e "${BOLD}${BLUE}>> Starting Vault (production mode)...${NC}"
echo ""

if grep -q "change-this-secret-key" docker-compose.yml 2>/dev/null; then
    echo -e "${YELLOW}[!] WARNING: Using default JWT_SECRET in docker-compose.yml${NC}"
    echo "    Please edit docker-compose.yml and set a strong JWT_SECRET"
    echo "    Generate one with: openssl rand -base64 32"
    echo ""
    read -p "Press Enter to continue anyway, or Ctrl+C to cancel..."
fi

echo -e "${CYAN}[*] Preparing data directory...${NC}"
mkdir -p data
chmod 777 data

echo -e "${BLUE}[PULL] Pulling Docker image from GitHub Container Registry...${NC}"
docker pull ghcr.io/bungleware/vault:main

echo -e "${CYAN}[STOP] Stopping existing services...${NC}"
docker-compose down

echo -e "${BLUE}[>>] Starting services with new image...${NC}"
docker compose up -d --pull always

echo -e "${CYAN}[...] Waiting for services to be healthy...${NC}"
sleep 5

echo -e "${CYAN}[HEALTH] Checking service health...${NC}"
if docker-compose exec -T vault-server wget -qO- http://localhost:8080/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}[✓] Backend server is healthy${NC}"
else
    echo -e "${YELLOW}[!] Backend server health check failed (may still be starting)${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}[✓] Vault is starting up!${NC}"
echo ""
echo -e "${BOLD}Service URLs:${NC}"
echo "   Application: http://localhost:8080"
echo "   Health:       http://localhost:8080/api/health"
echo ""
echo -e "${BOLD}Useful commands:${NC}"
echo "   View logs:    VAULT_IMAGE=ghcr.io/bungleware/vault:main docker-compose logs -f"
echo "   Stop:         docker-compose down"
echo "   Restart:      VAULT_IMAGE=ghcr.io/bungleware/vault:main docker-compose restart"
echo "   Status:       docker-compose ps"
echo "   Update image: docker pull ghcr.io/bungleware/vault:main && VAULT_IMAGE=ghcr.io/bungleware/vault:main docker-compose up -d"
echo ""
