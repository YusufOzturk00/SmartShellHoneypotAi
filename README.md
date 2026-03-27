cat > README.md << 'EOF'
# 🍯 AI Honeypot v3.0 — Adaptive Deception with LLM

Saldırganları gerçek zamanlı analiz eden, yapay zeka destekli SSH honeypot sistemi.

## 🚀 Özellikler

### ✅ Temel Özellikler
- **Docker Container Isolation** — Her oturum izole container içinde
- **PTY Bridge** — Gerçek bash shell deneyimi
- **Session Recording** — Asciinema formatında kayıt
- **MITRE ATT&CK Framework** — 50+ komut pattern eşleştirmesi

### 🆕 Yenilikçi Özellikler
- **Adaptive Decoy Engine** — Saldırganın ilgi alanına göre dinamik tuzak dosyaları
- **LLM Session Analysis** — Groq LLM ile otomatik saldırgan profili ve niyet analizi
- **Real-time Threat Intel** — IP geolocation, AbuseIPDB, threat feeds
- **Attack Kill Chain** — MITRE ATT&CK zinciri otomatik oluşturma

## 📋 Gereklilikler

```bash
- Python 3.8+
- Docker
- Groq API Key (ücretsiz: https://console.groq.com)

# Clone
git clone https://github.com/YusufOzturk00/mezuniyet.git
cd mezuniyet

# Bağımlılıkları kur
pip install -r requirements.txt

# Docker imajını build et
docker build -t honeypot-jail:latest -f Dockerfile.honeypot .

# Groq API Key'i ayarla
export GROQ_API_KEY="your_key_here"

# Çalıştır
python3 honeypot.py

# Başka terminalde
ssh root@localhost -p 2225
# Şifre: toor

Internet Saldırgan
        ↓
   SSH (port 2225)
        ↓
   Paramiko SSH Server
        ↓
   Docker Container (Ubuntu 22.04)
        ↓
   ├─ PTY Bridge (real bash)
   ├─ Command Logger (MITRE etiketleme)
   ├─ Adaptive Decoy Engine (LLM)
   └─ Session Recorder (asciinema)
        ↓
   SQLite Database (loglar)
        ↓
   Groq LLM Analysis (rapor)
