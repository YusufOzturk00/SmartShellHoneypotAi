# 🍯 SmartShell AI Honeypot v3.0

> **An advanced, production-ready SSH honeypot with AI-powered threat analysis, adaptive decoys, and MITRE ATT&CK classification**

---

## 📖 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Core Components](#core-components)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Dashboard & Monitoring](#dashboard--monitoring)
- [Alerting](#alerting)
- [Docker Deployment](#docker-deployment)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**SmartShell AI Honeypot** is a sophisticated SSH honeypot designed to lure, trap, and analyze attackers in a realistic, isolated environment. Unlike traditional honeypots that simulate limited shell interactions, this system provides **full SSH sessions inside hardened Docker containers** with AI-driven behavioral analysis, adaptive deception, and enterprise-grade logging.

### Why SmartShell?

| Traditional Honeypots | SmartShell AI Honeypot |
|----------------------|------------------------|
| Simulated shell (fake responses) | **Real containerized environment** |
| Static decoys | **AI-generated adaptive decoys** |
| Basic logging | **MITRE ATT&CK classification + LLM analysis** |
| No threat intelligence | **GeoIP + AbuseIPDB + Tor detection** |
| Single-threaded | **Multi-threaded, rate-limited, scalable** |
| No alerting | **Slack/Telegram/Webhook alerting** |

---
﻿
## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SMARTSHELL AI HONEYPOT ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ATTACKER                                                                   │
│     │                                                                       │
│     ▼                                                                       │
│  ┌─────────┐    SSH (port 2225)    ┌─────────────────────────────────┐    │
│  │  SSH    │ ────────────────────▶ │  HONEYPOT SERVER (honeypot.py)  │    │
│  │ Client  │                       │  • Paramiko SSH Server          │    │
│  └─────────┘                       │  • Auth Trap (fake creds)       │    │
│                                    │  • Rate Limiter & IP Ban        │    │
│                                    └──────────────┬──────────────────┘    │
│                                                   │                        │
│                                    ┌──────────────▼──────────────────┐    │
│                                    │      CONTAINER MANAGER          │    │
│                                    │  • Creates isolated Docker      │    │
│                                    │    container per session        │    │
│                                    │  • Resource limits (CPU/RAM)    │    │
│                                    │  • Security: no-new-privs,      │    │
│                                    │    cap-drop, network=none       │    │
│                                    └──────────────┬──────────────────┘    │
│                                                   │                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

### 🔐 **Real SSH Server with Credential Traps**
- Full Paramiko-based SSH server on port 2225
- Pre-configured "valid" credentials (root/toor, admin/admin, etc.) that grant access to the honeypot
- Progressive authentication delays to mimic real servers
- Brute-force tracking with exponential backoff

### 🐳 **Isolated Docker Containers per Session**
- Each attacker gets a **fresh, hardened Ubuntu 22.04 container**
- Resource limits: 64MB RAM, 10% CPU, 50 PIDs, 100MB disk
- Security hardening: `no-new-privileges`, `cap-drop=ALL`, `network_mode=none`
- Container hostname: `prod-db-01.finansbank.local` (realistic banking server persona)

### 📝 **MITRE ATT&CK Command Classification**
- **150+ regex rules** mapping commands to MITRE ATT&CK techniques
- Covers all tactics: Reconnaissance, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Defense Evasion, Execution, Privilege Escalation, Impact
- Real-time risk scoring (0-100) with automatic alerting thresholds
### 🎭 **AI-Powered Adaptive Decoys**
- Analyzes attacker command patterns in real-time
- Identifies interest areas: databases, credentials, crypto keys, network, web, cloud, source code, logs
- **Generates realistic fake files on-demand** using Groq LLM (llama-3.3-70b)
- Files created with backdated timestamps, proper permissions, realistic content

### 🧠 **LLM Session Analysis (Groq API)**
- Post-session deep analysis using Llama-3.3-70B
- **Attacker profiling**: type (script_kiddie/opportunistic/advanced/apt/insider), skill level, motivation
- **Kill chain mapping**: current stage, completed stages, next likely action
- **Psychological profile** in Turkish & English
- **IOC extraction**: suspicious IPs, domains, files, commands
- **Actionable recommendations** for SOC teams

### 🌍 **Threat Intelligence Integration**
- GeoIP lookup via ip-api.com (country, city, ISP, organization)
- AbuseIPDB integration for abuse confidence scores
- Tor exit node detection
- Private IP simulation with realistic threat actor profiles (China, Russia, NK, Iran, US)

### 🚨 **Multi-Channel Alerting**
- **Slack** (webhook & blocks format)
- **Telegram** (HTML formatted)
- **Generic Webhooks** (Discord, custom endpoints)
- Configurable cooldown (default 60s) to prevent spam
- Severity levels: INFO, WARNING, ALERT, CRITICAL

### 📊 **Session Recording & Replay**
- **Asciinema v2 format** terminal recordings
- Full input/output capture with timing
- Command buffer extraction for analysis
- Downloadable replay files

### ⚡ **Rate Limiting & IP Banning**
- Max 5 concurrent connections per IP
- Ban after 15 connections in 5 minutes (1-hour ban)
- Progressive delays for rate-limited connections
- Manual ban/unban API

### 🗄️ **Persistent SQLite Database**
- All logs, commands, sessions stored locally
- Queryable via dashboard or CLI
- Automatic table creation on startup
---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|------------|
| **SSH Server** | Paramiko 3.4+ |
| **Containerization** | Docker SDK for Python 7.0+ |
| **AI/LLM** | Groq API (Llama-3.3-70B-Versatile) |
| **Database** | SQLite 3 |
| **Web Framework** | Flask 3.0 + Flask-SocketIO 5.3 |
| **Threat Intel** | ip-api.com, AbuseIPDB API |
| **GeoIP** | MaxMind GeoIP2 (optional) |
| **Async/Networking** | aiohttp 3.9, requests 2.31 |
| **Serialization** | PyYAML 6.0, JSON |
| **Cryptography** | cryptography 42.0 |
| **Base OS** | Ubuntu 22.04 (container) |

---

## 📦 Installation

### Prerequisites

- **Docker** 24.0+ with BuildKit enabled
- **Python** 3.10+
- **Groq API Key** (free at [console.groq.com](https://console.groq.com))
- **Linux/macOS/WSL2** (Windows native Docker works but WSL2 recommended)

### Quick Start (Docker Compose - Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/SmartShellHoneypotAi.git
cd SmartShellHoneypotAi

# 2. Build the honeypot image
docker build -t honeypot-jail:latest -f Dockerfile.honeypot .

# 3. Create environment file
cp .env.example .env
# Edit .env with your keys:
# GROQ_API_KEY=your_groq_key_here
# ALERT_WEBHOOK=https://hooks.slack.com/services/...
# TELEGRAM_TOKEN=your_bot_token
# TELEGRAM_CHAT=your_chat_id
# ABUSEIPDB_API_KEY=your_key (optional)

# 4. Start the stack
docker-compose up -d

# 5. Verify it's running
docker-compose logs -f honeypot
```

### Manual Installation (Development)

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Build Docker image
docker build -t honeypot-jail:latest -f Dockerfile.honeypot .

# 4. Set environment variables
export GROQ_API_KEY="your_key_here"
export HONEYPOT_PORT=2225

# 5. Run directly
python honeypot.py
```
---

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GROQ_API_KEY` | **Yes** | - | Groq API key for LLM analysis |
| `GROQ_MODEL` | No | `llama-3.3-70b-versatile` | LLM model to use |
| `HONEYPOT_PORT` | No | `2225` | SSH port to listen on |
| `ALERT_WEBHOOK` | No | - | Slack/Discord/webhook URL |
| `TELEGRAM_TOKEN` | No | - | Telegram bot token |
| `TELEGRAM_CHAT` | No | - | Telegram chat ID |
| `ABUSEIPDB_API_KEY` | No | - | AbuseIPDB API key for threat intel |
| `ENCRYPTION_KEY` | No | auto-generated | Key for encrypting sensitive data |
| `REDIS_URL` | No | `redis://localhost:6379` | Redis connection (for distributed mode) |
| `LOG_LEVEL` | No | `INFO` | Logging level |

### Docker Compose Override

Create `docker-compose.override.yml` for custom settings:

```yaml
version: "3.9"
services:
  honeypot:
    environment:
      - LOG_LEVEL=DEBUG
      - HONEYPOT_PORT=2225
    ports:
      - "2225:2225"
      - "8080:8080"  # Dashboard port
    volumes:
      - ./custom_decoy:/app/decoy:ro  # Custom decoy files
```

---

## 🚀 Usage

### Connecting to the Honeypot

```bash
# Using any SSH client
ssh root@localhost -p 2225
# Password: toor  (or any from VALID_CREDS list)

# Valid credential pairs (honeypot.py:42-54):
# root:toor, root:123456, root:password, root:root
# admin:admin, admin:12345, admin:password123
# postgres:P@ssw0rd2024!, postgres:postgres
# dba_user:dba2024, ahmet:Ahmet2024!
```

### Monitoring Active Sessions

```bash
# View active containers
docker ps --filter "label=honeypot=true"

# Check honeypot logs
docker-compose logs -f honeypot | grep -E "(ALERT|CRITICAL|WARNING)"

# Database queries
sqlite3 data/honeypot.db "SELECT * FROM logs ORDER BY id DESC LIMIT 20;"
```

### Dashboard (Web UI)

Access the real-time dashboard at **http://localhost:8080** (when implemented)

Features:
- Live session monitoring
- Command stream with MITRE tags
- Threat level indicators
- Session replay (asciinema)
- Geographic attack map
- Alert history

### Session Replay

```bash
# Download recording from container
docker exec hp-<session_id> cat /tmp/session.cast > session.cast

# Play with asciinema
asciinema play session.cast

# Or use the built-in replay endpoint (when dashboard active)
```
---

## 📁 Project Structure

```
SmartShellHoneypotAi/
├── honeypot.py                 # Main entry point - SSH server
├── requirements.txt            # Python dependencies
├── docker-compose.yml          # Production deployment
├── Dockerfile.honeypot         # Honeypot container image
├── README.md                   # This file
├── .gitignore                  # Git ignore rules
├── .env.example                # Environment template
│
├── core/                       # Core Python modules
│   ├── __init__.py
│   ├── container_manager.py    # Docker container lifecycle
│   ├── pty_bridge.py           # PTY bridge + session recording
│   ├── command_logger.py       # MITRE ATT&CK classification
│   ├── adaptive_decoy.py       # AI-generated decoy files
│   ├── llm_analyst.py          # Post-session LLM analysis
│   ├── llm_engine.py           # Groq API wrapper
│   ├── threat_intel.py         # GeoIP + AbuseIPDB + Tor
│   ├── alert_manager.py        # Slack/Telegram/Webhook alerts
│   ├── rate_limiter.py         # Connection rate limiting
│   ├── event_bus.py            # Internal event system
│   └── database.py             # SQLite persistence
│
├── decoy/                      # Static decoy files (baked into image)
│   ├── bash_history            # Fake command history
│   ├── passwords.txt           # Fake passwords
│   ├── config.php              # Fake PHP config with DB creds
│   ├── .env                    # Fake environment variables
│   ├── aws_credentials         # Fake AWS keys
│   ├── id_rsa                  # Fake SSH private key
│   ├── auth.log                # Fake auth logs
│   ├── postgresql.conf         # Fake Postgres config
│   ├── backup_db.sql           # Fake SQL dump
│   └── todo.txt                # Fake admin notes
│
├── scripts/                    # Container startup scripts
│   ├── entrypoint.sh           # Container initialization
│   └── canary_watcher.sh       # Inotify-based file access monitor
│
├── data/                       # Runtime data (gitignored)
│   ├── host_key.pem            # SSH host key
│   ├── honeypot.db             # SQLite database
│   └── recordings/             # Session recordings
│
└── logs/                       # Application logs (gitignored)
```

---

## 🔧 Core Components

### 1. **HoneypotServer** (`honeypot.py:88`)
Paramiko `ServerInterface` implementation handling:
- SSH channel/pty requests
- Password authentication with credential traps
- Session lifecycle management

### 2. **ContainerManager** (`core/container_manager.py`)
Manages Docker containers per session:
- `create_session_container()` - Spawns hardened container
- `destroy_session_container()` - Forensic cleanup + removal
- `get_container_exec()` - Gets exec socket for PTY bridge
- Resource limits & security hardening
- Escape attempt monitoring (proc/self/exe, docker.sock, nsenter)
- 30-minute session timeout

### 3. **PTYBridge** (`core/pty_bridge.py`)
Bidirectional byte bridge between:
- Paramiko SSH channel (attacker side)
- Docker exec socket (container side)
- **SessionRecorder** - Asciinema v2 format recording
- Line-based command extraction with ANSI stripping
- Event emission for each command

### 4. **CommandLogger** (`core/command_logger.py`)
MITRE ATT&CK classification engine:
- 150+ compiled regex patterns
- Maps to technique IDs (T1033, T1082, T1552, etc.)
- Risk scoring (5-100)
- Automatic log level escalation (INFO→WARNING→ALERT)

### 5. **AdaptiveDecoyEngine** (`core/adaptive_decoy.py`)
Real-time deception:
- Tracks attacker "interests" from command patterns
- Triggers every 5 commands after 3rd command
- Calls Groq LLM to generate contextual decoys
- Creates files inside running container via exec
- Backdates timestamps for realism

### 6. **LLMAnalyst** (`core/llm_analyst.py`)
Post-session intelligence:
- `analyze_session()` - Full MITRE + kill chain + IOCs
- `analyze_attacker_psychology()` - Behavioral profile
- `generate_adaptive_decoy()` - Real-time decoy prompts
- Structured JSON output with validation

### 7. **ThreatIntel** (`core/threat_intel.py`)
IP reputation:
- `get_ip_intel()` - Cached lookup (1hr TTL)
- GeoIP via ip-api.com
- AbuseIPDB confidence scoring
- Tor exit node detection
- Private IP simulation with APT profiles

### 8. **AlertManager** (`core/alert_manager.py`)
Async alert delivery:
- Queue-based non-blocking
- Slack (blocks + markdown)
- Telegram (HTML)
- Generic webhooks
- 60-second cooldown per IP/alert-type

### 9. **RateLimiter** (`core/rate_limiter.py`)
Connection control:
- Sliding window (5 min)
- Max 5 concurrent / 15 total per window
- Auto-ban (1 hour)
- Progressive delays

### 10. **EventBus** (`core/event_bus.py`)
Decoupled event system:
- Typed event emission
- Wildcard listeners
- In-memory log (10k events)
- Dashboard integration ready

### 11. **Database** (`core/database.py`)
SQLite persistence:
- Thread-safe connection pooling
- Auto-schema creation
- JSON details column
- Query helpers
---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Techniques Covered | Example Rules |
|--------|-------------------|---------------|
| **Reconnaissance** | T1033, T1082, T1016, T1018, T1057, T1083, T1087, T1518 | `whoami`, `uname`, `ifconfig`, `nmap`, `ps aux`, `cat /etc/passwd` |
| **Credential Access** | T1552.001, T1552, T1003.008, T1552.004 | `cat /etc/shadow`, `find . -name *.pem`, `grep -r password` |
| **Discovery** | T1082, T1083, T1057, T1018, T1016, T1518 | `ls /`, `df -h`, `iptables -L`, `env` |
| **Lateral Movement** | T1021.004, T1550.002, T1550.003 | `ssh user@host`, `scp file`, `ssh -i key` |
| **Collection** | T1005, T1560.001, T1039, T1041 | `tar -czf`, `zip -r`, `cat *.conf`, `mysqldump` |
| **Exfiltration** | T1048, T1041, T1567 | `scp`, `curl -T`, `nc -l`, `base64` |
| **Defense Evasion** | T1070.004, T1070.003, T1222 | `rm -rf /var/log`, `history -c`, `chmod 777` |
| **Execution** | T1059, T1059.004, T1204 | `python -c`, `curl \| bash`, `chmod +x; ./script` |
| **Privilege Escalation** | T1548, T1548.001, T1548.003 | `sudo`, `find -perm 4000`, `cat /etc/sudoers` |
| **Impact** | T1485 | `rm -rf /`, `dd if=/dev/zero`, fork bomb |

**Total: 150+ rules across 10 tactics**

---

## 📊 Dashboard & Monitoring

The Flask-SocketIO dashboard (port 8080) provides:

### Real-Time Views
- **Active Sessions**: Live container list with duration, IP, command count
- **Command Stream**: Real-time feed with MITRE tags, risk scores, color coding
- **Threat Map**: Geographic visualization of attacker IPs
- **Alert Panel**: Recent alerts with severity, acknowledgment

### Historical Analysis
- **Session Explorer**: Filter by date, IP, threat level, tactic
- **Command Search**: Full-text search across all sessions
- **MITRE Heatmap**: Technique frequency visualization
- **Attacker Profiles**: LLM-generated psychology summaries

### Session Replay
- Embedded asciinema player
- Timeline scrubbing
- Command highlighting
- Download `.cast` files

---

## 🚨 Alerting

### Alert Types & Triggers

| Alert Type | Trigger | Channels |
|------------|---------|----------|
| `high_threat_session` | LLM analysis returns HIGH/CRITICAL | All |
| `escape_attempt` | Container escape indicators detected | All |
| `credential_access` | Shadow file, SSH keys, .env accessed | Slack, Webhook |
| `data_exfiltration` | Archive + transfer commands detected | Webhook |
| `new_connection` | First connection from new IP (optional) | Telegram |

### Slack Message Format
```
🔴 Honeypot CRITICAL
```json
{
  "event": "high_threat_session",
  "session_id": "a1b2c3d4...",
  "ip": "203.0.113.42",
  "threat_level": "CRITICAL",
  "summary": "Attacker performed credential dumping...",
  "commands_count": 47
}
```

### Telegram Message Format
```
🔴 <b>Honeypot CRITICAL</b>

<pre>{"event": "high_threat_session", ...}</pre>
```

---

## 🐳 Docker Deployment Details

### Honeypot Container (`Dockerfile.honeypot`)

**Base**: Ubuntu 22.04

**Installed Tools**:
- System: `bash`, `coreutils`, `procps`, `iproute2`, `net-tools`
- Editors: `vim`, `nano`
- Network: `curl`, `wget`, `htop`, `dnsutils`, `traceroute`, `nmap`, `whois`
- Database: `postgresql-client`, `redis-tools`
- Security: `file`, `inotify-tools`, `jq`

**Pre-created Users**:
- `admin` (UID 1001) / `12345`
- `dba_user` (UID 1002)
- `ahmet` (UID 1003) / `Ahmet2024!`
- `root` / `toor`

**Realistic Artifacts**:
- Hostname: `prod-db-01.finansbank.local`
- `/etc/hosts` with internal IPs
- Fake PostgreSQL, Redis, Nginx processes (via `exec -a`)
- SSH config with `backup-srv` host
- Cron job for backups
- Systemd service files
- Log files with realistic entries
- MOTD banner

**Decoy Files** (copied from `./decoy/`):
- `/root/.bash_history` - Command history
- `/root/passwords.txt` - Plaintext passwords
- `/root/config.php` - DB credentials
- `/root/.env` - API keys, AWS creds
- `/root/.aws/credentials` - AWS access keys
- `/root/backup_key.pem` - SSH private key
- `/var/log/auth.log` - Failed login attempts
- `/tmp/backup_20240115.sql` - SQL dump

**Security**:
- Removes `/.dockerenv` and `/run/.containerenv`
- Canary watcher monitors sensitive file access via `inotifywait`

### Docker Compose Services

```yaml
services:
  honeypot:
    # Runs the SSH server + manages containers
    # Requires: docker.sock mount for container management
    # Ports: 2225 (SSH), 8080 (Dashboard)
    
  redis:
    # Session cache, rate limiting, pub/sub for distributed mode
    image: redis:7-alpine
```
---

## 🔒 Security Considerations

### For the Honeypot Operator

1. **Never expose port 2225 directly to internet** without:
   - Firewall rules limiting source IPs
   - VPN or bastion host access
   - Rate limiting at network level

2. **Docker socket mount** (`/var/run/docker.sock`) gives root-equivalent access:
   - Only run on dedicated host
   - Consider rootless Docker or Podman
   - Monitor for container escape attempts

3. **API Keys** in `.env`:
   - Use Docker secrets in swarm mode
   - Rotate regularly
   - Restrict Groq API key permissions

4. **Data Protection**:
   - Encrypt `data/honeypot.db` at rest
   - Secure backup of recordings
   - GDPR considerations for IP logging

### Container Hardening Applied

- ✅ `--network=none` (no network access)
- ✅ `--cap-drop=ALL` + minimal `--cap-add`
- ✅ `--security-opt=no-new-privileges:true`
- ✅ `--pids-limit=50` (fork bomb protection)
- ✅ `--mem-limit=64m` + `--memswap-limit=64m`
- ✅ `--cpu-quota=10000` (10% CPU)
- ✅ `tmpfs /tmp noexec` (no executable in /tmp)
- ✅ Read-only root filesystem (where possible)
- ✅ Removed container fingerprints (`/.dockerenv`)

---

## 🧪 Testing

### Unit Tests (Planned)
```bash
# Run tests
pytest tests/ -v

# Coverage
pytest --cov=core tests/
```

### Integration Testing
```bash
# Test SSH connection
ssh -o StrictHostKeyChecking=no root@localhost -p 2225
# Try commands: whoami, ls, cat /etc/passwd, cat /etc/shadow

# Verify logging
sqlite3 data/honeypot.db "SELECT * FROM logs WHERE log_type='ALERT';"
```

### Load Testing
```bash
# Simulate concurrent connections
for i in {1..20}; do
  ssh -o ConnectTimeout=5 root@localhost -p 2225 "echo test" &
done
wait
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 (use `black` formatter)
- Add type hints to new functions
- Write docstrings for public APIs
- Update MITRE rules in `command_logger.py` with new techniques
- Test with real SSH clients before PR

### Adding New MITRE Rules

```python
# In core/command_logger.py MITRE_RULES list:
{
    "pattern": r"\byour_regex_pattern\b",
    "tactic": "Tactic Name",
    "technique": "TXXXX",
    "name": "Technique Name",
    "risk": 50,  # 5-100
},
```

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **MITRE ATT&CK®** framework for technique mappings
- **Groq** for fast LLM inference (Llama-3.3-70B)
- **Paramiko** for SSH protocol implementation
- **Docker** for containerization
- **ip-api.com** for free GeoIP lookup
- **AbuseIPDB** for threat reputation data
- **Asciinema** for terminal recording format

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/SmartShellHoneypotAi/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/SmartShellHoneypotAi/discussions)
- **Security**: Report vulnerabilities privately via [security@example.com](mailto:security@example.com)

---

> ⚠️ **Legal Disclaimer**: This honeypot is designed for authorized security research, threat intelligence gathering, and defensive cybersecurity purposes only. Deploy only on systems you own or have explicit permission to monitor. Ensure compliance with local laws regarding data collection, privacy, and computer misuse. The authors assume no liability for misuse.
---

# 🍯 SmartShell AI Honeypot v3.0 (Türkçe)

> **AI destekli tehdit analizi, uyarlanabilir tuzaklar ve MITRE ATT&CK sınıflandırması ile gelişmiş, production-ready SSH honeypot**

---

## 📖 İçindekiler

- [Genel Bakış](#genel-bakış)
- [Mimari](#mimari)
- [Temel Özellikler](#temel-özellikler)
- [Teknoloji Yığını](#teknoloji-yığını)
- [Kurulum](#kurulum)
- [Yapılandırma](#yapılandırma)
- [Kullanım](#kullanım)
- [Proje Yapısı](#proje-yapısı)
- [Temel Bileşenler](#temel-bileşenler)
- [MITRE ATT&CK Kapsamı](#mitre-attck-kapsamı)
- [Dashboard ve İzleme](#dashboard-ve-izleme)
- [Uyarı Sistemi](#uyarı-sistemi)
- [Docker Dağıtımı](#docker-dağıtımı)
- [Katkıda Bulunma](#katkıda-bulunma)
- [Lisans](#lisans)

---

## 🎯 Genel Bakış

**SmartShell AI Honeypot**, saldırganları çekmek, tuzağa düşürmek ve gerçekçi, izole bir ortamda analiz etmek için tasarlanmış gelişmiş bir SSH honeypot'tur. Sınırlı shell simülasyonu yapan geleneksel honeypot'ların aksine, bu sistem **sertleştirilmiş Docker container'ları içinde tam SSH oturumları**, AI destekli davranış analizi, uyarlanmış aldatmaca ve kurumsal seviyede loglama sağlar.

### Neden SmartShell?

| Geleneksel Honeypot'lar | SmartShell AI Honeypot |
|------------------------|------------------------|
| Simüle edilmiş shell (sahte yanıtlar) | **Gerçek containerize ortam** |
| Statik tuzaklar | **AI üretimli uyarlanabilir tuzaklar** |
| Temel loglama | **MITRE ATT&CK sınıflandırması + LLM analizi** |
| Tehdit istihbaratı yok | **GeoIP + AbuseIPDB + Tor tespiti** |
| Tek iş parçacıklı | **Çok iş parçacıklı, rate-limited, ölçeklenebilir** |
| Uyarı sistemi yok | **Slack/Telegram/Webhook uyarıları** |
---

## 🏗️ Mimari

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SMARTSHELL AI HONEYPOT MİMARİSİ                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  SALDIRGAN                                                                  │
│     │                                                                       │
│     ▼                                                                       │
│  ┌─────────┐    SSH (port 2225)    ┌─────────────────────────────────┐    │
│  │  SSH    │ ────────────────────▶ │  HONEYPOT SUNUCUSU (honeypot.py)│    │
│  │ Client  │                       │  • Paramiko SSH Server          │    │
│  └─────────┘                       │  • Auth Trap (sahte creds)      │    │
│                                    │  • Rate Limiter & IP Ban        │    │
│                                    └──────────────┬──────────────────┘    │
│                                                   │                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Temel Özellikler

### 🔐 **Kimlik Bilgisi Tuzağı ile Gerçek SSH Sunucusu**
- Port 2225'te tam Paramiko tabanlı SSH sunucusu
- Honeypot'a erişim veren önceden yapılandırılmış "geçerli" kimlik bilgileri (root/toor, admin/admin, vb.)
- Gerçek sunucuları taklit eden kademeli kimlik doğrulama gecikmeleri
- Üstel geri çekilme ile brute-force takibi

### 🐳 **Oturum Başına İzole Docker Container'ları**
- Her saldırgan **taze, sertleştirilmiş Ubuntu 22.04 container'ı** alır
- Kaynak limitleri: 64MB RAM, %10 CPU, 50 PID, 100MB disk
- Güvenlik sertleştirmesi: `no-new-privileges`, `cap-drop=ALL`, `network_mode=none`
- Container hostname: `prod-db-01.finansbank.local` (gerçekçi banka sunucusu personas)

### 📝 **MITRE ATT&CK Komut Sınıflandırması**
- Komutları MITRE ATT&CK tekniklerine eşleyen **150+ regex kuralı**
- Tüm taktikleri kapsar: Reconnaissance, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Defense Evasion, Execution, Privilege Escalation, Impact
- Gerçek zamanlı risk skorlaması (0-100) otomatik uyarı eşikleriyle
### 🎭 **AI Destekli Uyarlanabilir Tuzaklar**
- Saldırgan komut kalıplarını gerçek zamanlı analiz eder
- İlgi alanlarını tespit eder: veritabanları, kimlik bilgileri, kripto anahtarları, ağ, web, bulut, kaynak kod, loglar
- **Groq LLM (llama-3.3-70b) kullanarak talep üzerine gerçekçi sahte dosyalar üretir**
- Gerçekçilik için geriye doğru tarihli zaman damgaları, uygun izinler, gerçekçi içerikle dosyalar oluşturur

### 🧠 **LLM Oturum Analizi (Groq API)**
- Llama-3.3-70B kullanarak oturum sonu derin analizi
- **Saldırgan profillemesi**: tip (script_kiddie/opportunistic/advanced/apt/insider), beceri seviyesi, motivasyon
- **Kill chain haritalama**: mevcut aşama, tamamlanan aşamalar, bir sonraki olası eylem
- **Psikoloji profili** Türkçe ve İngilizce
- **IOC çıkarma**: şüpheli IP'ler, domainler, dosyalar, komutlar
- **SOC ekiplerine yönelik eyleme geçirilebilir öneriler**

### 🌍 **Tehdit İstihbaratı Entegrasyonu**
- ip-api.com üzerinden GeoIP sorgulama (ülke, şehir, ISP, organizasyon)
- Kötüye kullanım güven skorları için AbuseIPDB entegrasyonu
- Tor çıkış nodu tespiti
- Gerçekçi tehdit aktörü profilleriyle (Çin, Rusya, KK, İran, ABD) özel IP simülasyonu

### 🚨 **Çok Kanallı Uyarı Sistemi**
- **Slack** (webhook ve blocks formatı)
- **Telegram** (HTML formatlı)
- **Genel Webhook'lar** (Discord, özel uç noktalar)
- Spam önleme için yapılandırılabilir soğuma süresi (varsayılan 60sn)
- Şiddet seviyeleri: INFO, WARNING, ALERT, CRITICAL

### 📊 **Oturum Kaydı ve Yeniden Oynatma**
- **Asciinema v2 formatında** terminal kayıtları
- Zamanlama ile tam input/output yakalama
- Analiz için komut tamponu çıkarma
- İndirilebilir yeniden oynatma dosyaları

### ⚡ **Rate Limiting ve IP Yasaklama**
- IP başına en fazla 5 eşzamanlı bağlantı
- 5 dakikada 15 bağlantıdan sonra yasaklama (1 saat ban)
- Rate-limited bağlantılar için kademeli gecikmeler
- Manuel ban/unban API'si

### 🗄️ **Kalıcı SQLite Veritabanı**
- Tüm loglar, komutlar, oturumlar yerel olarak saklanır
- Dashboard veya CLI üzerinden sorgulanabilir
- Başlangıçta otomatik tablo oluşturma
---

## 🛠️ Teknoloji Yığını

| Bileşen | Teknoloji |
|---------|-----------|
| **SSH Sunucusu** | Paramiko 3.4+ |
| **Containerization** | Docker SDK for Python 7.0+ |
| **AI/LLM** | Groq API (Llama-3.3-70B-Versatile) |
| **Veritabanı** | SQLite 3 |
| **Web Framework** | Flask 3.0 + Flask-SocketIO 5.3 |
| **Tehdit İstihbaratı** | ip-api.com, AbuseIPDB API |
| **GeoIP** | MaxMind GeoIP2 (opsiyonel) |
| **Async/Ağ** | aiohttp 3.9, requests 2.31 |
| **Serileştirme** | PyYAML 6.0, JSON |
| **Kriptografi** | cryptography 42.0 |
| **Taban OS** | Ubuntu 22.04 (container) |

---

## 📦 Kurulum

### Ön Koşullar

- **Docker** 24.0+ BuildKit etkin
- **Python** 3.10+
- **Groq API Anahtarı** (ücretsiz: [console.groq.com](https://console.groq.com))
- **Linux/macOS/WSL2** (Windows native Docker çalışır ama WSL2 önerilir)

### Hızlı Başlangıç (Docker Compose - Önerilen)

```bash
# 1. Depoyu klonlayın
git clone https://github.com/yourusername/SmartShellHoneypotAi.git
cd SmartShellHoneypotAi

# 2. Honeypot imajını build edin
docker build -t honeypot-jail:latest -f Dockerfile.honeypot .

# 3. Ortam dosyası oluşturun
cp .env.example .env
# .env dosyasını anahtarlarınızla düzenleyin:
# GROQ_API_KEY=your_groq_key_here
# ALERT_WEBHOOK=https://hooks.slack.com/services/...
# TELEGRAM_TOKEN=your_bot_token
# TELEGRAM_CHAT=your_chat_id
# ABUSEIPDB_API_KEY=your_key (opsiyonel)

# 4. Stack'i başlatın
docker-compose up -d

# 5. Çalıştığını doğrulayın
docker-compose logs -f honeypot
```

### Manuel Kurulum (Geliştirme)

```bash
# 1. Sanal ortam oluşturun
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 3. Docker imajını build edin
docker build -t honeypot-jail:latest -f Dockerfile.honeypot .

# 4. Ortam değişkenlerini ayarlayın
export GROQ_API_KEY="your_key_here"
export HONEYPOT_PORT=2225

# 5. Doğrudan çalıştırın
python honeypot.py
```
---

## ⚙️ Yapılandırma

### Ortam Değişkenleri

| Değişken | Zorunlu | Varsayılan | Açıklama |
|----------|---------|------------|----------|
| `GROQ_API_KEY` | **Evet** | - | LLM analizi için Groq API anahtarı |
| `GROQ_MODEL` | Hayır | `llama-3.3-70b-versatile` | Kullanılacak LLM modeli |
| `HONEYPOT_PORT` | Hayır | `2225` | Dinlenecek SSH portu |
| `ALERT_WEBHOOK` | Hayır | - | Slack/Discord/webhook URL'i |
| `TELEGRAM_TOKEN` | Hayır | - | Telegram bot token'ı |
| `TELEGRAM_CHAT` | Hayır | - | Telegram chat ID'si |
| `ABUSEIPDB_API_KEY` | Hayır | - | Tehdit istihbaratı için AbuseIPDB API anahtarı |
| `ENCRYPTION_KEY` | Hayır | auto-generated | Hassas veri şifreleme anahtarı |
| `REDIS_URL` | Hayır | `redis://localhost:6379` | Redis bağlantısı (dağıtık mod için) |
| `LOG_LEVEL` | Hayır | `INFO` | Log seviyesi |

### Docker Compose Override

Özel ayarlar için `docker-compose.override.yml` oluşturun:

```yaml
version: "3.9"
services:
  honeypot:
    environment:
      - LOG_LEVEL=DEBUG
      - HONEYPOT_PORT=2225
    ports:
      - "2225:2225"
      - "8080:8080"  # Dashboard portu
    volumes:
      - ./custom_decoy:/app/decoy:ro  # Özel tuzak dosyaları
```

---

## 🚀 Kullanım

### Honeypot'a Bağlanma

```bash
# Herhangi bir SSH client ile
ssh root@localhost -p 2225
# Şifre: toor  (veya VALID_CREDS listesinden herhangi biri)

# Geçerli kimlik bilgisi çiftleri (honeypot.py:42-54):
# root:toor, root:123456, root:password, root:root
# admin:admin, admin:12345, admin:password123
# postgres:P@ssw0rd2024!, postgres:postgres
# dba_user:dba2024, ahmet:Ahmet2024!
```

### Aktif Oturumları İzleme

```bash
# Aktif container'ları görüntüle
docker ps --filter "label=honeypot=true"

# Honeypot loglarını kontrol et
docker-compose logs -f honeypot | grep -E "(ALERT|CRITICAL|WARNING)"

# Veritabanı sorguları
sqlite3 data/honeypot.db "SELECT * FROM logs ORDER BY id DESC LIMIT 20;"
```

### Dashboard (Web Arayüzü)

Gerçek zamanlı dashboard'a **http://localhost:8080** adresinden erişim (implement edildiğinde)

Özellikler:
- Canlı oturum izleme
- MITRE etiketleriyle komut akışı
- Tehdit seviyesi göstergeleri
- Oturum yeniden oynatma (asciinema)
- Coğrafi saldırı haritası
- Uyarı geçmişi

### Oturum Yeniden Oynatma

```bash
# Container'dan kaydı indir
docker exec hp-<session_id> cat /tmp/session.cast > session.cast

# asciinema ile oynat
asciinema play session.cast

# Veya yerleşik yeniden oynatma endpoint'ini kullanın (dashboard aktifse)
```
---

## 📁 Proje Yapısı

```
SmartShellHoneypotAi/
├── honeypot.py                 # Ana giriş noktası - SSH sunucusu
├── requirements.txt            # Python bağımlılıkları
├── docker-compose.yml          # Production dağıtımı
├── Dockerfile.honeypot         # Honeypot container imajı
├── README.md                   # Bu dosya
├── .gitignore                  # Git ignore kuralları
├── .env.example                # Ortam şablonu
│
├── core/                       # Temel Python modülleri
│   ├── __init__.py
│   ├── container_manager.py    # Docker container yaşam döngüsü
│   ├── pty_bridge.py           # PTY köprüsü + oturum kaydı
│   ├── command_logger.py       # MITRE ATT&CK sınıflandırması
│   ├── adaptive_decoy.py       # AI üretimli tuzak dosyalar
│   ├── llm_analyst.py          # Oturum sonu LLM analizi
│   ├── llm_engine.py           # Groq API wrapper
│   ├── threat_intel.py         # GeoIP + AbuseIPDB + Tor
│   ├── alert_manager.py        # Slack/Telegram/Webhook uyarıları
│   ├── rate_limiter.py         # Bağlantı rate limiting
│   ├── event_bus.py            # Dahili event sistemi
│   └── database.py             # SQLite kalıcılığı
│
├── decoy/                      # Statik tuzak dosyaları (imajda baked)
│   ├── bash_history            # Sahte komut geçmişi
│   ├── passwords.txt           # Sahte şifreler
│   ├── config.php              # Sahte PHP config + DB creds
│   ├── .env                    # Sahte ortam değişkenleri
│   ├── aws_credentials         # Sahte AWS anahtarları
│   ├── id_rsa                  # Sahte SSH private key
│   ├── auth.log                # Sahte auth logları
│   ├── postgresql.conf         # Sahte Postgres config
│   ├── backup_db.sql           # Sahte SQL dump
│   └── todo.txt                # Sahte admin notları
│
├── scripts/                    # Container başlangıç scriptleri
│   ├── entrypoint.sh           # Container başlatma
│   └── canary_watcher.sh       # İnotify tabanlı dosya erişim izleyici
│
├── data/                       # Çalışma zamanı verileri (gitignored)
│   ├── host_key.pem            # SSH host anahtarı
│   ├── honeypot.db             # SQLite veritabanı
│   └── recordings/             # Oturum kayıtları
│
└── logs/                       # Uygulama logları (gitignored)
```

---

## 🔧 Temel Bileşenler

### 1. **HoneypotServer** (`honeypot.py:88`)
Paramiko `ServerInterface` implementasyonu:
- SSH kanal/pty istekleri
- Kimlik bilgisi tuzakları ile parola kimlik doğrulaması
- Oturum yaşam döngüsü yönetimi

### 2. **ContainerManager** (`core/container_manager.py`)
Oturum başına Docker container yönetimi:
- `create_session_container()` - Sertleştirilmiş container başlatır
- `destroy_session_container()` - Forensic temizlik + kaldırma
- `get_container_exec()` - PTY köprüsü için exec socket'i alır
- Kaynak limitleri ve güvenlik sertleştirmesi
- Kaçış denemesi izleme (proc/self/exe, docker.sock, nsenter)
- 30 dakikalık oturum zaman aşımı

### 3. **PTYBridge** (`core/pty_bridge.py`)
İki yönlü byte köprüsü:
- Paramiko SSH kanalı (saldırgan tarafı)
- Docker exec socket (container tarafı)
- **SessionRecorder** - Asciinema v2 formatında kayıt
- ANSI temizleme ile satır bazlı komut çıkarma
- Her komut için event emission

### 4. **CommandLogger** (`core/command_logger.py`)
MITRE ATT&CK sınıflandırma motoru:
- 150+ derlenmiş regex pattern
- Teknik ID'lerine eşleme (T1033, T1082, T1552, vb.)
- Risk skorlaması (5-100)
- Otomatik log seviyesi yükseltme (INFO→WARNING→ALERT)

### 5. **AdaptiveDecoyEngine** (`core/adaptive_decoy.py`)
Gerçek zamanlı aldatmaca:
- Komut kalıplarından saldırgan "ilgi alanlarını" takip eder
- 3. komuttan sonra her 5 komutta bir tetiklenir
- Bağlamsal tuzaklar için Groq LLM'yi çağırır
- Container içinde exec ile dosya oluşturur
- Gerçekçilik için zaman damgalarını geriye doğru tarihler

### 6. **LLMAnalyst** (`core/llm_analyst.py`)
Oturum sonu istihbaratı:
- `analyze_session()` - Tam MITRE + kill chain + IOC'ler
- `analyze_attacker_psychology()` - Davranışsal profil
- `generate_adaptive_decoy()` - Gerçek zamanlı tuzak promptları
- Doğrulama ile yapılandırılmış JSON çıktısı

### 7. **ThreatIntel** (`core/threat_intel.py`)
IP reputation:
- `get_ip_intel()` - Önbellekli sorgulama (1 saat TTL)
- ip-api.com üzerinden GeoIP
- AbuseIPDB güven skoru
- Tor çıkış nodu tespiti
- APT profilleriyle özel IP simülasyonu

### 8. **AlertManager** (`core/alert_manager.py`)
Async uyarı teslimi:
- Kuyruk tabanlı non-blocking
- Slack (blocks + markdown)
- Telegram (HTML)
- Genel webhook'lar
- 60 saniyelik soğuma per IP/uyarı tipi

### 9. **RateLimiter** (`core/rate_limiter.py`)
Bağlantı kontrolü:
- Kayan pencere (5 dk)
- Maks 5 eşzamanlı / pencere başına 15 toplam
- Otomatik ban (1 saat)
- Kademeli gecikmeler

### 10. **EventBus** (`core/event_bus.py`)
Bağımsız event sistemi:
- Tip event emission
- Wildcard listener'lar
- Bellek içi log (10k event)
- Dashboard entegrasyonu hazır

### 11. **Database** (`core/database.py`)
SQLite kalıcılığı:
- Thread-safe connection pooling
- Otomatik şema oluşturma
- JSON details kolonu
- Sorgu yardımcıları
---

## 🎯 MITRE ATT&CK Kapsamı

| Taktik | Kapsanan Teknikler | Örnek Kurallar |
|--------|-------------------|---------------|
| **Reconnaissance** | T1033, T1082, T1016, T1018, T1057, T1083, T1087, T1518 | `whoami`, `uname`, `ifconfig`, `nmap`, `ps aux`, `cat /etc/passwd` |
| **Credential Access** | T1552.001, T1552, T1003.008, T1552.004 | `cat /etc/shadow`, `find . -name *.pem`, `grep -r password` |
| **Discovery** | T1082, T1083, T1057, T1018, T1016, T1518 | `ls /`, `df -h`, `iptables -L`, `env` |
| **Lateral Movement** | T1021.004, T1550.002, T1550.003 | `ssh user@host`, `scp file`, `ssh -i key` |
| **Collection** | T1005, T1560.001, T1039, T1041 | `tar -czf`, `zip -r`, `cat *.conf`, `mysqldump` |
| **Exfiltration** | T1048, T1041, T1567 | `scp`, `curl -T`, `nc -l`, `base64` |
| **Defense Evasion** | T1070.004, T1070.003, T1222 | `rm -rf /var/log`, `history -c`, `chmod 777` |
| **Execution** | T1059, T1059.004, T1204 | `python -c`, `curl \| bash`, `chmod +x; ./script` |
| **Privilege Escalation** | T1548, T1548.001, T1548.003 | `sudo`, `find -perm 4000`, `cat /etc/sudoers` |
| **Impact** | T1485 | `rm -rf /`, `dd if=/dev/zero`, fork bomb |

**Toplam: 10 taktik genelinde 150+ kural**

---

## 📊 Dashboard ve İzleme

Flask-SocketIO dashboard (port 8080) şunları sağlar:

### Gerçek Zamanlı Görünümler
- **Aktif Oturumlar**: Süre, IP, komut sayısıyla canlı container listesi
- **Komut Akışı**: MITRE etiketleri, risk skorları, renk kodlamasıyla gerçek zamanlı besleme
- **Tehdit Haritası**: Saldırgan IP'lerinin coğrafi görselleştirmesi
- **Uyarı Paneli**: Şiddet, onaylama ile son uyarılar

### Geçmiş Analiz
- **Oturum Keşfi**: Tarih, IP, tehdit seviyesi, taktik ile filtreleme
- **Komut Arama**: Tüm oturumlarda tam metin arama
- **MITRE Heatmap**: Teknik frekansı görselleştirmesi
- **Saldırgan Profilleri**: LLM üretimli psikoloji özetleri

### Oturum Yeniden Oynatma
- Gömülü asciinema oynatıcı
- Zaman çizelgesi scrubbing
- Komut vurgulama
- `.cast` dosyalarını indirme

---

## 🚨 Uyarı Sistemi

### Uyarı Türleri ve Tetikleyiciler

| Uyarı Türü | Tetikleyici | Kanallar |
|------------|-------------|----------|
| `high_threat_session` | LLM analizi HIGH/CRITICAL döndürür | Hepsi |
| `escape_attempt` | Container kaçış göstergeleri tespit edilir | Hepsi |
| `credential_access` | Shadow dosyası, SSH anahtarları, .env erişilir | Slack, Webhook |
| `data_exfiltration` | Arşivleme + transfer komutları tespit edilir | Webhook |
| `new_connection` | Yeni IP'den ilk bağlantı (opsiyonel) | Telegram |

### Slack Mesaj Formatı
```
🔴 Honeypot CRITICAL
```json
{
  "event": "high_threat_session",
  "session_id": "a1b2c3d4...",
  "ip": "203.0.113.42",
  "threat_level": "CRITICAL",
  "summary": "Attacker performed credential dumping...",
  "commands_count": 47
}
```

### Telegram Mesaj Formatı
```
🔴 <b>Honeypot CRITICAL</b>

<pre>{"event": "high_threat_session", ...}</pre>
```

---

## 🐳 Docker Dağıtım Detayları

### Honeypot Container (`Dockerfile.honeypot`)

**Taban**: Ubuntu 22.04

**Kurulu Araçlar**:
- Sistem: `bash`, `coreutils`, `procps`, `iproute2`, `net-tools`
- Editörler: `vim`, `nano`
- Ağ: `curl`, `wget`, `htop`, `dnsutils`, `traceroute`, `nmap`, `whois`
- Veritabanı: `postgresql-client`, `redis-tools`
- Güvenlik: `file`, `inotify-tools`, `jq`

**Önceden Oluşturulmuş Kullanıcılar**:
- `admin` (UID 1001) / `12345`
- `dba_user` (UID 1002)
- `ahmet` (UID 1003) / `Ahmet2024!`
- `root` / `toor`

**Gerçekçi Artifaktlar**:
- Hostname: `prod-db-01.finansbank.local`
- İç IP'lerle `/etc/hosts`
- Sahte PostgreSQL, Redis, Nginx süreçleri (`exec -a` ile)
- `backup-srv` host ile SSH config
- Yedekler için cron job
- Systemd servis dosyaları
- Gerçekçi girdilerle log dosyaları
- MOTD banner

**Tuzak Dosyaları** (`./decoy/`'den kopyalanır):
- `/root/.bash_history` - Komut geçmişi
- `/root/passwords.txt` - Düz metin şifreler
- `/root/config.php` - DB kimlik bilgileri
- `/root/.env` - API anahtarları, AWS creds
- `/root/.aws/credentials` - AWS erişim anahtarları
- `/root/backup_key.pem` - SSH private key
- `/var/log/auth.log` - Başarısız giriş denemeleri
- `/tmp/backup_20240115.sql` - SQL dump

**Güvenlik**:
- `/.dockerenv` ve `/run/.containerenv` kaldırılır
- Canary watcher `inotifywait` ile hassas dosya erişimini izler

### Docker Compose Servisleri

```yaml
services:
  honeypot:
    # SSH sunucusunu çalıştırır + container'ları yönetir
    # Gerektirir: container yönetimi için docker.sock mount
    # Portlar: 2225 (SSH), 8080 (Dashboard)
    
  redis:
    # Oturum önbelleği, rate limiting, dağıtık mod için pub/sub
    image: redis:7-alpine
```
---

## 🔒 Güvenlik Hususları

### Honeypot Operatörü İçin

1. **Port 2225'i hiçbir zaman doğrudan internete açmayın** şunlar olmadan:
   - Kaynak IP'leri sınırlayan firewall kuralları
   - VPN veya bastion host erişimi
   - Ağ seviyesinde rate limiting

2. **Docker socket mount** (`/var/run/docker.sock`) root-eşdeğer erişim verir:
   - Sadece adanmış host'ta çalıştırın
   - Rootless Docker veya Podman düşünün
   - Container kaçış denemelerini izleyin

3. **`.env` içindeki API Anahtarları**:
   - Swarm modunda Docker secrets kullanın
   - Düzenli rotasyon
   - Groq API anahtarı izinlerini kısıtlayın

4. **Veri Koruması**:
   - `data/honeypot.db`yi restte şifreleyin
   - Kayıtların güvenli yedeği
   - IP loglaması için GDPR hususları

### Uygulanan Container Sertleştirmesi

- ✅ `--network=none` (ağ erişimi yok)
- ✅ `--cap-drop=ALL` + minimal `--cap-add`
- ✅ `--security-opt=no-new-privileges:true`
- ✅ `--pids-limit=50` (fork bomb koruması)
- ✅ `--mem-limit=64m` + `--memswap-limit=64m`
- ✅ `--cpu-quota=10000` (%10 CPU)
- ✅ `tmpfs /tmp noexec` (/tmp'de executable yok)
- ✅ Salt okunur root dosya sistemi (mümkün olduğunda)
- ✅ Container parmak izleri kaldırıldı (`/.dockerenv`)

---

## 🧪 Test

### Birim Testleri (Planlanıyor)
```bash
# Testleri çalıştır
pytest tests/ -v

# Coverage
pytest --cov=core tests/
```

### Entegrasyon Testleri
```bash
# SSH bağlantısını test et
ssh -o StrictHostKeyChecking=no root@localhost -p 2225
# Komutları dene: whoami, ls, cat /etc/passwd, cat /etc/shadow

# Loglamayı doğrula
sqlite3 data/honeypot.db "SELECT * FROM logs WHERE log_type='ALERT';"
```

### Yük Testleri
```bash
# Eşzamanlı bağlantıları simüle et
for i in {1..20}; do
  ssh -o ConnectTimeout=5 root@localhost -p 2225 "echo test" &
done
wait
```

---

## 🤝 Katkıda Bulunma

1. Depoyu fork edin
2. Özellik dalı oluşturun: `git checkout -b feature/harika-ozellik`
3. Değişiklikleri commit edin: `git commit -m 'Harika özellik eklendi'`
4. Dalı push edin: `git push origin feature/harika-ozellik`
5. Pull Request açın

### Geliştirme Kuralları

- PEP 8 takip edin (`black` formatter kullanın)
- Yeni fonksiyonlara type hint ekleyin
- Public API'ler için docstring yazın
- `command_logger.py` dosyasındaki MITRE kurallarını yeni tekniklerle güncelleyin
- PR öncesi gerçek SSH client'larla test edin

### Yeni MITRE Kuralı Ekleme

```python
# In core/command_logger.py MITRE_RULES list:
{
    "pattern": r"\byour_regex_pattern\b",
    "tactic": "Tactic Name",
    "technique": "TXXXX",
    "name": "Technique Name",
    "risk": 50,  # 5-100
},
```

---

## 📄 Lisans

Bu proje **MIT Lisansı** altında lisanslanmıştır - detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 🙏 Teşekkürler

- **MITRE ATT&CK®** çerçevesi teknik eşlemeleri için
- **Groq** hızlı LLM inference için (Llama-3.3-70B)
- **Paramiko** SSH protokol implementasyonu için
- **Docker** containerization için
- **ip-api.com** ücretsiz GeoIP sorgulama için
- **AbuseIPDB** tehdit reputation verisi için
- **Asciinema** terminal kayıt formatı için

---

> ⚠️ **Yasal Uyarı**: Bu honeypot, yetkili güvenlik araştırması, tehdit istihbaratı toplama ve savunma siber güvenlik amaçları için tasarlanmıştır. Yalnızca size ait veya izniniz olan sistemlerde dağıtın. Veri toplama, gizlilik ve bilgisayar kötüye kullanımı konularundaki yerel yasalarla uyumluluğu sağlayın. Yazarlar kötüye kullanımdan dolayı hiçbir sorumluluk kabul etmez.
