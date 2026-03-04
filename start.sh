#!/bin/bash
set -e

echo "Building MCP sandbox image..."
docker compose build mcp-sandbox

echo "Starting all services..."
docker compose up -d --build

echo "Waiting for PostgreSQL..."
until docker compose exec postgres pg_isready -U postgres > /dev/null 2>&1; do
    sleep 1
done

echo "Running database migrations..."
docker compose exec backend alembic upgrade head

echo ""
echo "MCP Security Scanner is running!"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000"
echo "  API docs: http://localhost:8000/docs"
