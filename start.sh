#!/usr/bin/env bash
# CyberSim start script

set -euo pipefail

PORT="${CYBERSIM_PORT:-8002}"

echo "=========================================="
echo "  CyberSim - Cybersecurity Simulator"
echo "  Starting on http://0.0.0.0:$PORT"
echo "=========================================="

# Create directories
mkdir -p instance seed_data static/css static/js templates

# Install dependencies if needed
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || true

pip install -q -r requirements.txt

echo "[*] Launching uvicorn..."
exec uvicorn app:app --host 0.0.0.0 --port "$PORT" --reload
