#!/bin/bash
# Duck DNS auto-update script for Phantom Artifact
# Keeps phantom-artifact.duckdns.org pointing to Render's IP
#
# Usage: 
#   ./duckdns-update.sh                    # one-time update
#   crontab: */30 * * * * /path/to/duckdns-update.sh >> /var/log/duckdns.log 2>&1

DUCK_TOKEN="c3b8d190-a81e-45ee-b28b-6d08fa591101"
DUCK_DOMAIN="phantom-artifact"
RENDER_HOST="phantom-artifact.onrender.com"
LOG_PREFIX="[$(date -u '+%Y-%m-%d %H:%M:%S UTC')]"

# Resolve Render's current IP
RENDER_IP=$(dig +short "$RENDER_HOST" A | grep -E '^[0-9]' | head -1)

if [ -z "$RENDER_IP" ]; then
    echo "$LOG_PREFIX ERROR: Could not resolve $RENDER_HOST"
    exit 1
fi

# Get current Duck DNS IP
CURRENT_IP=$(dig +short "${DUCK_DOMAIN}.duckdns.org" A)

if [ "$CURRENT_IP" = "$RENDER_IP" ]; then
    echo "$LOG_PREFIX OK: IP unchanged ($CURRENT_IP)"
    exit 0
fi

# Update Duck DNS
RESULT=$(curl -s "https://www.duckdns.org/update?domains=${DUCK_DOMAIN}&token=${DUCK_TOKEN}&ip=${RENDER_IP}")

if [ "$RESULT" = "OK" ]; then
    echo "$LOG_PREFIX UPDATED: $CURRENT_IP -> $RENDER_IP"
else
    echo "$LOG_PREFIX ERROR: Duck DNS returned '$RESULT'"
    exit 1
fi
