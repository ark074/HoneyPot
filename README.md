# AegisTrap

**Multi-Service AI-Driven Honeypot Framework**

AegisTrap is an open-source honeypot that uses a locally-hosted LLM (via Ollama) to dynamically generate realistic responses to attacker interactions across SSH, Telnet, HTTP, and FTP services.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AegisTrap Framework                       │
├─────────────┬──────────────┬─────────────┬─────────────────┤
│  SSH :2222  │  Telnet :23  │  HTTP :80   │    FTP :21      │
│             │              │       :8080  │                 │
├─────────────┴──────────────┴─────────────┴─────────────────┤
│              Security Gateway (Rate Limit, Payload Capture) │
├────────────────────────────────────────────────────────────┤
│              AI Context Bridge + Session Manager            │
├────────────────────────────────────────────────────────────┤
│              Ollama LLM (llama3:8b)                         │
├────────────────────────────────────────────────────────────┤
│              Structured JSON Logger → SIEM/Elastic          │
└────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/ark074/HoneyPot.git
cd HoneyPot

# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f aegistrap-app

# Monitor threat activity
tail -f logs/honeypot_activity.json | jq .
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| SSH     | 2222 | Interactive shell with LLM-generated responses |
| Telnet  | 23   | Interactive shell with realistic Linux emulation |
| HTTP    | 80, 8080 | Corporate login panel, exposed config files |
| FTP     | 21   | vsFTPd emulation with fake file system |

## Security Features

- **Absolute Isolation**: Commands are NEVER executed on the host OS
- **Payload Capture**: wget/curl URLs are logged without downloading
- **Rate Limiting**: 50 requests/minute/IP with auto-block
- **Session Throttle**: Auto-disconnect after 15 minutes

## Configuration

All settings are in `config.py` and can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `llama3:8b` | LLM model to use |
| `SSH_PORT` | `2222` | SSH listen port |
| `TELNET_PORT` | `23` | Telnet listen port |
| `HTTP_PORT` | `80` | HTTP listen port |
| `FTP_PORT` | `21` | FTP listen port |
| `LOG_DIR` | `logs` | Log output directory |

## Log Format

Each interaction is logged as flat JSON to `logs/honeypot_activity.json`:

```json
{
  "timestamp": "2024-01-18T14:35:22.123456+00:00",
  "attacker_ip": "192.168.1.100",
  "attacker_port": 54321,
  "service_targeted": "SSH",
  "input_received": "cat /etc/passwd",
  "ai_response": "root:x:0:0:root:/root:/bin/bash\n...",
  "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

## Requirements

- Docker & Docker Compose
- 8GB+ RAM (for Ollama LLM)
- Network ports: 21, 22, 23, 80, 8080

## License

Open source. Use responsibly and only on networks you own or have authorization to monitor.
