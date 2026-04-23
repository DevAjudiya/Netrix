#!/usr/bin/env bash
# Netrix — start all services via Docker Compose
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Stopping any existing Netrix containers..."
docker compose down --remove-orphans 2>/dev/null || true

echo "[*] Building and starting Netrix (Docker Compose)..."
docker compose up --build -d

echo ""
echo "[*] Waiting for services to be healthy..."
timeout=120
elapsed=0
while [ $elapsed -lt $timeout ]; do
    backend_health=$(docker inspect --format='{{.State.Health.Status}}' netrix-backend 2>/dev/null || echo "starting")
    if [ "$backend_health" = "healthy" ]; then
        break
    fi
    sleep 3
    elapsed=$((elapsed + 3))
    echo "    ... $elapsed s (backend: $backend_health)"
done

echo ""
echo "Netrix is running:"
echo "  Web UI  → http://localhost:3000"
echo "  API     → http://localhost:8000"
echo "  API docs→ http://localhost:8000/docs"
echo ""
echo "Admin login: admin / Admin@Netrix2026!"
echo ""
echo "Useful commands:"
echo "  Logs (all)    : docker compose logs -f"
echo "  Logs (backend): docker compose logs -f netrix-backend"
echo "  Stop          : docker compose down"
echo "  Restart       : bash start.sh"
