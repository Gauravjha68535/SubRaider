#!/bin/bash
#
# SubRaider Installation - Recruit Your Crew!
# https://github.com/gauravjha68535/subraider

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[38;5;208m'
GOLD='\033[38;5;220m'
NC='\033[0m'

echo -e "${GOLD}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║              Recruiting the SubRaider Crew!                  ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "${GREEN}[✓] Land ho! Linux detected${NC}"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${GREEN}[✓] Ahoy! macOS detected${NC}"
else
    echo -e "${RED}[✗] Uncharted waters - unsupported OS${NC}"
    exit 1
fi

# Install system dependencies
echo -e "${YELLOW}[*] Stocking the ship with supplies...${NC}"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt update
    sudo apt install -y git curl wget jq parallel python3-pip build-essential cargo
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew install git curl wget jq parallel python3 cargo
fi

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[*] Installing the navigator (Go)...${NC}"
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    rm go1.21.5.linux-amd64.tar.gz
fi

# Create Go bin directory
mkdir -p ~/go/bin

# Install Go tools (the crew)
echo -e "${YELLOW}[*] Mustering the pirate crew...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/puredns/cmd/puredns@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/infosec-au/altdns@latest
go install -v github.com/Josue87/gotator@latest
go install -v github.com/sensepost/gowitness@latest

# Install Findomain (Dead Man's Chest)
echo -e "${YELLOW}[*] Raising the Jolly Roger (Findomain)...${NC}"
git clone https://github.com/Edu4rdSHL/findomain.git
cd findomain
cargo build --release
sudo cp target/release/findomain /usr/local/bin/
cd ..
rm -rf findomain

# Install Python tools
echo -e "${YELLOW}[*] Teaching the parrot to talk (Python tools)...${NC}"
pip3 install dnsgen

# Download wordlists (the treasure maps)
echo -e "${YELLOW}[*] Charting the treasure maps (wordlists)...${NC}"
sudo mkdir -p /usr/share/wordlists/seclists
sudo wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt -O /usr/share/wordlists/seclists/subdomains-top1million-20000.txt

# Download resolvers (the compass)
echo -e "${YELLOW}[*] Calibrating the compass (resolvers)...${NC}"
sudo mkdir -p /usr/share/wordlists
sudo wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O /usr/share/wordlists/resolvers.txt

# Make script executable
chmod +x subraider.sh

# Create config directory
mkdir -p ~/.config/subraider

# Create default config
cat > ~/.config/subraider/config << "EOF"
# SubRaider - Buried Treasure Map ☠️
VT_API_KEY=""
ST_API_KEY=""
CHAOS_KEY=""
CENSYS_ID=""
CENSYS_SECRET=""
SHODAN_KEY=""
GITHUB_TOKEN=""
EOF

# Add to PATH
echo -e "${YELLOW}[*] Adding SubRaider to the PATH...${NC}"
sudo ln -sf $(pwd)/subraider.sh /usr/local/bin/subraider

echo -e "${GOLD}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║              Crew Recruited! Ready to Raid!                  ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${GREEN}[✓] SubRaider installed successfully!${NC}"
echo -e "${YELLOW}[*] Usage: subraider -t example.com -A -p${NC}"
echo -e "${YELLOW}[*] Bury your API keys: subraider --bury-treasure${NC}"
echo -e "${GOLD}[*] Now go plunder some domains! 🏴‍☠️${NC}"
