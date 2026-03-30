#!/bin/bash

# BOT53 Quick Run Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                      BOT53 LAUNCHER                             ${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"

# Check options
if [[ "$1" == "docker" ]]; then
    echo -e "${YELLOW}[*] Running with Docker...${NC}"
    
    # Build image
    docker build -t bot53:latest .
    
    # Run container
    docker run -it \
        --name bot53 \
        --rm \
        --privileged \
        --network host \
        -v bot53_data:/home/bot53/.bot53 \
        -v bot53_reports:/home/bot53/bot53_reports \
        bot53:latest
elif [[ "$1" == "docker-compose" ]]; then
    echo -e "${YELLOW}[*] Running with Docker Compose...${NC}"
    docker-compose up --build
elif [[ "$1" == "install" ]]; then
    echo -e "${YELLOW}[*] Installing BOT53...${NC}"
    chmod +x install.sh
    ./install.sh
else
    echo -e "${YELLOW}[*] Running natively...${NC}"
    
    # Check virtual environment
    if [[ ! -d "bot53_env" ]]; then
        echo -e "${YELLOW}[!] Virtual environment not found. Running installation...${NC}"
        chmod +x install.sh
        ./install.sh
    fi
    
    # Activate environment
    source bot53_env/bin/activate
    
    # Run application
    python3 bot53.py
fi

echo -e "${GREEN}[+] BOT53 finished${NC}"