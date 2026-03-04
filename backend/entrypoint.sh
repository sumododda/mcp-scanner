#!/bin/sh
set -e

echo "Initializing database schema..."
python -m mcp_scanner.init_db

# Start the application
exec "$@"
