#!/usr/bin/env bash
set -euo pipefail
export FLASK_APP=app.py
export FLASK_ENV=development
python3 -m flask run --host 127.0.0.1 --port 8080