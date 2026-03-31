#!/bin/bash
# Auto-setup and launch ASIC Miner Dashboard
cd "$(dirname "$0")"

if [ ! -d venv ]; then
    echo "First run - setting up Python environment..."
    python3 -m venv venv
    ./venv/bin/pip install -r requirements.txt
    echo ""
fi

./venv/bin/python3 minerdashboard.py "$@"
