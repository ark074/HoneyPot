#!/bin/bash
###############################################################################
# AegisTrap - First-Time Setup Script
#
# Automates:
# 1. Directory structure creation
# 2. GeoIP database download (MaxMind GeoLite2 - requires free license key)
# 3. Community YARA rules download
# 4. Environment file generation from template
# 5. SSH host key generation
# 6. File permission hardening
# 7. Docker image pre-build (optional)
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh                    # Interactive setup
#   ./setup.sh --no-geoip         # Skip GeoIP download
#   ./setup.sh --docker-build     # Also build Docker images
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flags
SKIP_GEOIP=false
DOCKER_BUILD=false

for arg in "$@"; do
    case $arg in
        --no-geoip) SKIP_GEOIP=true ;;
        --docker-build) DOCKER_BUILD=true ;;
        --help|-h)
            echo "AegisTrap Setup Script"
            echo ""
            echo "Usage: ./setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-geoip       Skip GeoIP database download"
            echo "  --docker-build   Build Docker images after setup"
            echo "  --help, -h       Show this help message"
            exit 0
            ;;
    esac
done

echo -e "${BLUE}"
echo "    ___              _     _____                 "
echo "   /   \\  ___  __ _(_)___/__   \\_ __ __ _ _ __  "
echo "  / /\\ / / _ \\/ _\` | / __|  / /\\/ '__/ _\` | '_ \\ "
echo " / /_// |  __/ (_| | \\__ \\ / /  | | | (_| | |_) |"
echo "/___,'   \\___|\\___, |_|___/ \\/   |_|  \\__,_| .__/ "
echo "              |___/                         |_|    "
echo -e "${NC}"
echo -e "${GREEN}  AegisTrap - First-Time Setup${NC}"
echo "  =============================================="
echo ""

# =============================================================================
# Step 1: Create directory structure
# =============================================================================
echo -e "${YELLOW}[1/7]${NC} Creating directory structure..."

mkdir -p logs
mkdir -p data/geoip
mkdir -p data/yara_rules
mkdir -p data/ssh_host_key
mkdir -p grafana/provisioning/dashboards
mkdir -p grafana/provisioning/datasources
mkdir -p prometheus

echo -e "  ${GREEN}✓${NC} Directories created"

# =============================================================================
# Step 2: Generate .env file from template
# =============================================================================
echo -e "${YELLOW}[2/7]${NC} Generating environment configuration..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "  ${GREEN}✓${NC} .env created from .env.example"
        echo -e "  ${YELLOW}!${NC} Review and customize .env before deploying"
    else
        echo -e "  ${YELLOW}!${NC} No .env.example found, skipping"
    fi
else
    echo -e "  ${GREEN}✓${NC} .env already exists, skipping"
fi

# =============================================================================
# Step 3: Generate SSH host key
# =============================================================================
echo -e "${YELLOW}[3/7]${NC} Generating SSH host key..."

if [ ! -f "data/ssh_host_key" ]; then
    ssh-keygen -t rsa -b 2048 -f data/ssh_host_key -N "" -q 2>/dev/null || {
        # Fallback: let the application generate it on first run
        echo -e "  ${YELLOW}!${NC} ssh-keygen not available; key will be generated on first run"
    }
    if [ -f "data/ssh_host_key" ]; then
        echo -e "  ${GREEN}✓${NC} SSH host key generated at data/ssh_host_key"
    fi
else
    echo -e "  ${GREEN}✓${NC} SSH host key already exists"
fi

# =============================================================================
# Step 4: Download GeoIP databases (MaxMind GeoLite2)
# =============================================================================
echo -e "${YELLOW}[4/7]${NC} Setting up GeoIP databases..."

if [ "$SKIP_GEOIP" = true ]; then
    echo -e "  ${YELLOW}!${NC} Skipped (--no-geoip flag)"
else
    if [ -f "data/geoip/GeoLite2-City.mmdb" ] && [ -f "data/geoip/GeoLite2-ASN.mmdb" ]; then
        echo -e "  ${GREEN}✓${NC} GeoIP databases already present"
    else
        echo ""
        echo -e "  ${BLUE}GeoLite2 databases require a free MaxMind account.${NC}"
        echo "  1. Sign up at: https://www.maxmind.com/en/geolite2/signup"
        echo "  2. Generate a license key at: https://www.maxmind.com/en/accounts/current/license-key"
        echo ""
        read -p "  Enter your MaxMind license key (or press Enter to skip): " MAXMIND_KEY

        if [ -n "$MAXMIND_KEY" ]; then
            echo "  Downloading GeoLite2-City..."
            curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_KEY}&suffix=tar.gz" | \
                tar xz --strip-components=1 -C data/geoip/ --wildcards '*.mmdb' 2>/dev/null && \
                echo -e "  ${GREEN}✓${NC} GeoLite2-City.mmdb downloaded" || \
                echo -e "  ${RED}✗${NC} Download failed (check license key)"

            echo "  Downloading GeoLite2-ASN..."
            curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MAXMIND_KEY}&suffix=tar.gz" | \
                tar xz --strip-components=1 -C data/geoip/ --wildcards '*.mmdb' 2>/dev/null && \
                echo -e "  ${GREEN}✓${NC} GeoLite2-ASN.mmdb downloaded" || \
                echo -e "  ${RED}✗${NC} Download failed (check license key)"
        else
            echo -e "  ${YELLOW}!${NC} Skipped. GeoIP enrichment will be disabled."
            echo "  To add later, place .mmdb files in data/geoip/"
        fi
    fi
fi

# =============================================================================
# Step 5: Download community YARA rules
# =============================================================================
echo -e "${YELLOW}[5/7]${NC} Setting up YARA rules..."

if [ "$(ls -A data/yara_rules/ 2>/dev/null)" ]; then
    echo -e "  ${GREEN}✓${NC} YARA rules already present ($(ls data/yara_rules/*.yar 2>/dev/null | wc -l) files)"
else
    echo "  Downloading community YARA rules..."

    # Download a curated subset of public rules
    YARA_URLS=(
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Mirai.yar"
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Cryptominer.yar"
    )

    DOWNLOADED=0
    for url in "${YARA_URLS[@]}"; do
        filename=$(basename "$url")
        if curl -sL "$url" -o "data/yara_rules/$filename" 2>/dev/null; then
            # Verify it's a valid YARA rule (starts with 'rule' or has 'import')
            if head -5 "data/yara_rules/$filename" | grep -qiE '(^rule |^import )'; then
                DOWNLOADED=$((DOWNLOADED + 1))
            else
                rm -f "data/yara_rules/$filename"
            fi
        fi
    done

    if [ $DOWNLOADED -gt 0 ]; then
        echo -e "  ${GREEN}✓${NC} Downloaded $DOWNLOADED community YARA rules"
    else
        echo -e "  ${YELLOW}!${NC} No external rules downloaded; built-in rules will be used"
    fi

    echo -e "  ${BLUE}i${NC} Add custom .yar files to data/yara_rules/ anytime"
fi

# =============================================================================
# Step 6: Set file permissions
# =============================================================================
echo -e "${YELLOW}[6/7]${NC} Setting file permissions..."

# Make scripts executable
chmod +x setup.sh 2>/dev/null || true
chmod +x scripts/ollama-entrypoint.sh 2>/dev/null || true

# Restrict SSH key permissions
chmod 600 data/ssh_host_key 2>/dev/null || true

# Ensure log directory is writable
chmod 777 logs 2>/dev/null || true

# Protect sensitive config
chmod 600 .env 2>/dev/null || true

echo -e "  ${GREEN}✓${NC} Permissions configured"

# =============================================================================
# Step 7: Docker build (optional)
# =============================================================================
echo -e "${YELLOW}[7/7]${NC} Docker setup..."

if [ "$DOCKER_BUILD" = true ]; then
    if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
        echo "  Building Docker images..."
        docker-compose build --no-cache
        echo -e "  ${GREEN}✓${NC} Docker images built"
        echo ""
        echo -e "  ${BLUE}To start AegisTrap:${NC}"
        echo "    docker-compose up -d"
    else
        echo -e "  ${RED}✗${NC} Docker or docker-compose not found"
        echo "  Install Docker: https://docs.docker.com/engine/install/"
    fi
else
    if command -v docker &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Docker detected. Run 'docker-compose up -d' to start."
    else
        echo -e "  ${YELLOW}!${NC} Docker not found. Install from: https://docs.docker.com/engine/install/"
    fi
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Review/edit .env with your configuration"
echo "     (alert webhooks, model settings, etc.)"
echo ""
echo "  2. Start the honeypot:"
echo "     docker-compose up -d"
echo ""
echo "  3. Access the dashboard:"
echo "     API Docs:   http://localhost:9000/api/docs"
echo "     Grafana:    http://localhost:3000 (admin:aegistrap)"
echo "     Prometheus: http://localhost:9090"
echo ""
echo "  4. Monitor live activity:"
echo "     docker-compose logs -f aegistrap-app"
echo "     tail -f logs/honeypot_activity.json | jq ."
echo ""
echo "  5. WebSocket live stream:"
echo "     wscat -c ws://localhost:9000/ws/live"
echo ""
echo -e "  ${YELLOW}SECURITY REMINDER:${NC}"
echo "  Deploy on an isolated network segment or DMZ."
echo "  Never deploy on production infrastructure."
echo ""
