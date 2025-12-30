#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
APP_DIR="$ROOT_DIR/macos/Casa del Pollo Launcher.app"
RESOURCE_SCRIPT="$APP_DIR/Contents/Resources/run_campaign_local.command"
MACOS_LAUNCHER="$APP_DIR/Contents/MacOS/launcher"

if [ ! -d "$APP_DIR" ]; then
    echo "App bundle not found at $APP_DIR" >&2
    exit 1
fi

cp "$ROOT_DIR/run_campaign_local.command" "$RESOURCE_SCRIPT"
chmod +x "$RESOURCE_SCRIPT"
chmod +x "$MACOS_LAUNCHER"

echo "Updated app bundle with the latest run_campaign_local.command"
