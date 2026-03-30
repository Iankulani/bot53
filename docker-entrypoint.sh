#!/bin/bash

# BOT53 Docker Entrypoint
set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    BOT53 Docker Container                       ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# Check if running as root
if [ "$(id -u)" = "0" ]; then
    echo "⚠️  Running as root. Switching to bot53 user..."
    exec su bot53 -c "$*"
else
    echo "✅ Running as bot53 user"
fi

# Activate virtual environment
source /opt/venv/bin/activate

# Check if configuration exists
if [ ! -f "/home/bot53/.bot53/config.json" ]; then
    echo "ℹ️  No configuration found. First run will prompt for setup."
fi

# Execute command
exec "$@"