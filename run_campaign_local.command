#!/usr/bin/env bash

set -e

# Go to project directory
cd /Users/adamklein/Documents/Restaurant-website || exit 1

# Activate virtualenv
source .venv/bin/activate

# Start Flask in the background
/Users/adamklein/Documents/Restaurant-website/.venv/bin/python -m flask run --host 127.0.0.1 --port 8080 &
FLASK_PID=$!

echo "Starting Flask (PID: $FLASK_PID) on http://127.0.0.1:8080 ..."
echo "Waiting for server to become available..."

# Health check loop (max ~30 seconds)
MAX_ATTEMPTS=30
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    if curl -sSf http://127.0.0.1:8080 > /dev/null 2>&1; then
        echo "✅ Server is up!"
        break
    else
        echo "  Attempt $ATTEMPT/$MAX_ATTEMPTS: not up yet..."
        sleep 1
    fi
    ATTEMPT=$((ATTEMPT + 1))
done

if [ $ATTEMPT -gt $MAX_ATTEMPTS ]; then
    echo "❌ Server did not start within $MAX_ATTEMPTS seconds."
    echo "Check the logs above for errors."
else
    # Only open the browser if we confirmed it's up
    open http://localhost:8080
    echo "🌐 Browser opened to http://localhost:8080"
fi

# Bring Terminal to the front (optional)
osascript -e 'tell application "Terminal" to activate'

# Keep Terminal open and attached to Flask logs
wait $FLASK_PID
