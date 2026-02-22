# 🏴‍☠️ SubRaider

SubRaider is a powerful subdomain enumeration tool that combines 20+ data sources to discover every possible subdomain for your target. Fast, thorough, and ready to use.

---

## 🚀 Quick Start

### Basic scan
```bash
./subraider.sh -t example.com
```

### Full scan with live probing
```bash
./subraider.sh -t example.com -A -p
```

### Scan multiple domains
```bash
./subraider.sh -T domains.txt -o results.txt
```

---

## 📦 Installation

```bash
git clone https://github.com/Gauravjha68535/SubRaider
cd SubRaider
chmod +x install.sh
./install.sh
```

---

## 🎯 Common Commands

| Command | Description |
|---------|------------|
| `./subraider.sh -t example.com` | Basic enum |
| `./subraider.sh -t example.com -A -p` | Full scan |
| `./subraider.sh -t example.com --fast-sloop` | Quick scan |
| `./subraider.sh -t example.com --raid 3` | Recursive scan |
| `./subraider.sh -T domains.txt -o all.txt` | Multiple targets |
| `./subraider.sh -t example.com -f json` | JSON output |

---

## 🔧 Main Options

- `-t, --target DOMAIN` → Target domain  
- `-T, --targets FILE` → File with domains  
- `-A, --all-crew` → Use all modules  
- `-p, --board` → Probe live hosts  
- `-o, --chest FILE` → Output file  
- `-f, --format TYPE` → txt/json/csv/html  
- `-q, --quiet` → Subdomains only  
- `--fast-sloop` → Fast mode  
- `--raid [N]` → Recursive mode  
- `--rum` → Enable permutations  
- `--bury-treasure` → Setup API keys  

---

## 🔑 API Setup (Optional)

```bash
./subraider --bury-treasure
nano ~/.config/subraider/config
```

Add keys:

```
VT_API_KEY="your-virustotal-key"
ST_API_KEY="your-securitytrails-key"
CHAOS_KEY="your-chaos-key"
CENSYS_ID="your-censys-id"
CENSYS_SECRET="your-censys-secret"
SHODAN_KEY="your-shodan-key"
GITHUB_TOKEN="your-github-token"
BE_API_KEY="your-binaryedge-key"
ALIENVAULT_KEY="your-alienvault-key"
URLSCAN_KEY="your-urlscan-key"
```

---

## 🤝 Contributing

PRs welcome! Report bugs or suggest features.
