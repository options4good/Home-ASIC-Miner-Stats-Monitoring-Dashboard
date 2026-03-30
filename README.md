# Home ASIC Miner Stats Monitoring Dashboard

Terminal dashboard for monitoring home ASIC miners. Supports Avalon, Antminer, NerdAxe, Bitaxe, Lucky Miner, Gamma, and any cgminer-compatible device.

## Quick Start

```bash
chmod +x run.sh
./run.sh
```

First run launches an interactive setup wizard that auto-scans your LAN for miners.

## Requirements

- Python 3.8+
- `run.sh` handles everything else (creates virtualenv, installs `rich` and `requests`)

## CLI Commands

```bash
# Run dashboard (setup wizard on first run)
./run.sh

# Scan LAN for miners and add to config
./run.sh --scan
./run.sh --scan --subnet 10.0.0.0/24

# Manage miners
./run.sh --add 192.168.1.10 --name Avalon-Q --type avalon
./run.sh --rename 192.168.1.10 --new-name Avalon-Q
./run.sh --remove 192.168.1.10
./run.sh --list

# Re-run setup wizard
./run.sh --setup
```

## Supported Miners

| Miner | API | Port |
|-------|-----|------|
| Avalon (all models) | cgminer | 4028 |
| Antminer S9 / S17 / S19 | cgminer | 4028 |
| NerdAxe / Bitaxe | HTTP | 80, 8080 |
| Lucky Miner | HTTP | 80, 8080 |
| Gamma | HTTP | 80, 8080 |

## Config File

Miners are stored in `miners.json` next to the script. Edit it directly or use the CLI commands above.

```json
[
  {"ip": "192.168.1.10", "name": "Avalon-Q", "type_hint": "avalon"},
  {"ip": "192.168.1.11", "name": "NerdAxe-1", "type_hint": "nerd"}
]
```

## Manual Run (no run.sh)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 minerdashboard.py
```

## Credits

Original dashboard by [options4good](https://github.com/options4good/Home-ASIC-Miner-Stats-Monitoring-Dashboard) (V2.2.2). This is a community-contributed rewrite (V3.1.0).
