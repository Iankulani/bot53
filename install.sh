#!/bin/bash

# BOT53 Installation Script
# Author: Ian Carter Kulani
# Description: Complete installation for BOT53 penetration testing platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    BOT53 INSTALLATION                          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"

# Check Python version
echo -e "${YELLOW}[*] Checking Python version...${NC}"
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ $(echo "$python_version < 3.7" | bc) -eq 1 ]]; then
    echo -e "${RED}[!] Python 3.7+ required. Current: $python_version${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Python $python_version found${NC}"

# Detect OS
OS=$(uname -s)
echo -e "${YELLOW}[*] Detected OS: $OS${NC}"

# Install system dependencies
echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
case "$OS" in
    Linux*)
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y python3-pip python3-dev python3-venv \
                build-essential libssl-dev libffi-dev \
                tcpdump wireshark net-tools dsniff \
                hping3 nikto nmap curl wget netcat-openbsd \
                macchanger ettercap-text-only bettercap \
                dnschef arp-scan fping \
                tshark tcpreplay tcprewrite \
                arping ngrep whois mtr \
                aircrack-ng reaver mdk4 \
                sqlmap gobuster ffuf \
                python3-venv python3-wheel
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3 python3-pip python3-devel \
                gcc openssl-devel libffi-devel \
                tcpdump wireshark net-tools \
                hping3 nikto nmap curl wget nc \
                macchanger ettercap bettercap \
                dnschef arp-scan fping \
                tshark whois mtr
        elif command -v pacman &> /dev/null; then
            sudo pacman -S python python-pip python-virtualenv \
                tcpdump wireshark-cli net-tools \
                hping nikto nmap curl wget netcat \
                macchanger ettercap bettercap \
                dnschef arp-scan fping \
                tshark whois mtr aircrack-ng
        fi
        ;;
    Darwin*)
        if command -v brew &> /dev/null; then
            brew install python3 tcpdump wireshark net-tools \
                hping nikto nmap curl wget netcat \
                macchanger ettercap bettercap \
                dnschef arp-scan fping \
                tshark whois mtr aircrack-ng
        else
            echo -e "${RED}[!] Homebrew not installed. Please install from https://brew.sh${NC}"
            exit 1
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo -e "${YELLOW}[!] Windows detected. Please install WSL2 for full functionality${NC}"
        echo -e "${YELLOW}[!] Installing Python packages only...${NC}"
        ;;
esac

# Create virtual environment
echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
python3 -m venv bot53_env
source bot53_env/bin/activate

# Install Python dependencies
echo -e "${YELLOW}[*] Installing Python packages...${NC}"
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Install additional security tools via pip
echo -e "${YELLOW}[*] Installing additional Python security tools...${NC}"
pip install shodan censys \
    pyOpenSSL certifi \
    python-nmap python-libnmap \
    impacket pymetasploit3 \
    pycryptodomex

# Setup directory structure
echo -e "${YELLOW}[*] Creating directory structure...${NC}"
mkdir -p ~/.bot53
mkdir -p ~/bot53_reports
mkdir -p ~/bot53_reports/scans
mkdir -p ~/.bot53/phishing
mkdir -p ~/.bot53/credentials
mkdir -p ~/.bot53/ssh_keys
mkdir -p ~/.bot53/whatsapp_session
mkdir -p ~/.bot53/signal_session
mkdir -p ~/.bot53/traffic_logs
mkdir -p ~/.bot53/nikto_results

# Set permissions
echo -e "${YELLOW}[*] Setting permissions...${NC}"
chmod 755 ~/.bot53
chmod 700 ~/.bot53/credentials
chmod 700 ~/.bot53/ssh_keys

# Check for signal-cli
echo -e "${YELLOW}[*] Checking for signal-cli...${NC}"
if ! command -v signal-cli &> /dev/null; then
    echo -e "${YELLOW}[!] signal-cli not found. Signal bot will be disabled.${NC}"
    echo -e "${YELLOW}[!] To install: https://github.com/AsamK/signal-cli/wiki/Quick-Start${NC}"
fi

# Check for Chrome/Chromium for WhatsApp
echo -e "${YELLOW}[*] Checking for Chrome/Chromium...${NC}"
if command -v google-chrome &> /dev/null || command -v chromium-browser &> /dev/null || command -v chromium &> /dev/null; then
    echo -e "${GREEN}[+] Chrome/Chromium found${NC}"
else
    echo -e "${YELLOW}[!] Chrome/Chromium not found. WhatsApp bot requires browser.${NC}"
fi

# Create executable script
echo -e "${YELLOW}[*] Creating launcher script...${NC}"
cat > ~/bot53 << 'EOF'
#!/bin/bash
source ~/bot53_env/bin/activate
python3 /path/to/bot53.py "$@"
EOF
# Note: Replace /path/to/bot53.py with actual path

# Make executable
chmod +x ~/bot53

echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    INSTALLATION COMPLETE!                      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo -e "${YELLOW}[*] To run BOT53:${NC}"
echo -e "    source bot53_env/bin/activate"
echo -e "    python3 bot53.py"
echo -e ""
echo -e "${YELLOW}[*] Or use the launcher:${NC}"
echo -e "    ~/bot53"
echo -e ""
echo -e "${YELLOW}[*] Configuration files are stored in: ~/.bot53/${NC}"
echo -e "${YELLOW}[*] Reports are stored in: ~/bot53_reports/${NC}"
echo -e ""
echo -e "${GREEN}[+] Happy Hacking! 🕶️${NC}"