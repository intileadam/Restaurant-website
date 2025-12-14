#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Casa del Pollo Campaign Runner"
REPO_NAME="Restaurant-website"
DEFAULT_HOST="${FLASK_HOST:-127.0.0.1}"
DEFAULT_PORT="${FLASK_PORT:-8080}"
CONFIG_DIR="$HOME/Library/Application Support/CasaDelPolloCampaign"
CONFIG_FILE="$CONFIG_DIR/repo_path.txt"
STATUS_URL="http://$DEFAULT_HOST:$DEFAULT_PORT"
BROWSER_URL="http://localhost:$DEFAULT_PORT"
SERVER_PID_FILE="$CONFIG_DIR/flask.pid"
STATE_DIR=""
REQ_HASH_FILE=""
LOG_FILE=""

log() {
    printf '[%s] %s\n' "$APP_NAME" "$1"
}

fatal() {
    printf '[%s] ❌ %s\n' "$APP_NAME" "$1" >&2
    exit 1
}

ensure_state_dir() {
    local primary="$HOME/Library/Application Support/CasaDelPolloCampaign"
    local fallback="${TMPDIR:-/tmp}/CasaDelPolloCampaign"
    local candidate=""

    for candidate in "$primary" "$fallback"; do
        if mkdir -p "$candidate" >/dev/null 2>&1; then
            if touch "$candidate/.write_test" >/dev/null 2>&1; then
                rm -f "$candidate/.write_test" >/dev/null 2>&1 || true
                STATE_DIR="$candidate"
                CONFIG_DIR="$STATE_DIR"
                CONFIG_FILE="$STATE_DIR/repo_path.txt"
                SERVER_PID_FILE="$STATE_DIR/flask.pid"
                if [ "$candidate" = "$fallback" ]; then
                    log "Using temporary state folder $STATE_DIR (primary location is not writable)."
                fi
                return
            fi
        fi
    done

    fatal "Unable to create a writable folder for Casa del Pollo state files."
}

stop_pid() {
    local pid="$1"
    if [ -z "$pid" ]; then
        rm -f "$SERVER_PID_FILE" >/dev/null 2>&1 || true
        return
    fi

    if kill -0 "$pid" >/dev/null 2>&1; then
        log "Stopping Flask (PID: $pid)..."
        kill "$pid" >/dev/null 2>&1 || true
        local waited=0
        while kill -0 "$pid" >/dev/null 2>&1 && [ $waited -lt 40 ]; do
            sleep 0.25
            waited=$((waited + 1))
        done
        if kill -0 "$pid" >/dev/null 2>&1; then
            log "Forcing Flask to exit..."
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
    fi

    rm -f "$SERVER_PID_FILE" >/dev/null 2>&1 || true
}

# Resolve the real path to this script so we know where it originally lived.
SCRIPT_PATH="${BASH_SOURCE[0]}"
if [[ "$SCRIPT_PATH" != /* ]]; then
    SCRIPT_PATH="$PWD/$SCRIPT_PATH"
fi

while [ -L "$SCRIPT_PATH" ]; do
    LINK_TARGET="$(readlink "$SCRIPT_PATH")"
    if [[ "$LINK_TARGET" == /* ]]; then
        SCRIPT_PATH="$LINK_TARGET"
    else
        SCRIPT_PATH="$(dirname "$SCRIPT_PATH")/$LINK_TARGET"
    fi
done

SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd -P)"

is_repo_dir() {
    local dir="$1"
    [ -d "$dir" ] && [ -f "$dir/app.py" ] && [ -f "$dir/requirements.txt" ]
}

try_repo_dir() {
    local candidate="$1"
    if [ -z "$candidate" ]; then
        return 1
    fi

    case "$candidate" in
        "~"*) candidate="$HOME${candidate:1}" ;;
    esac

    if is_repo_dir "$candidate"; then
        REPO_DIR="$(cd "$candidate" && pwd -P)"
        return 0
    fi
    return 1
}

prompt_for_repo() {
    local selected=""
    if command -v osascript >/dev/null 2>&1; then
        selected="$(osascript <<'APPLESCRIPT'
            with timeout of 300 seconds
                try
                    set chosenFolder to choose folder with prompt "Select the Restaurant-website folder (the one containing app.py)."
                    POSIX path of chosenFolder
                on error number -128
                    return ""
                end try
            end timeout
APPLESCRIPT
)"
        selected="${selected//$'\r'/}"
        selected="${selected//$'\n'/}"
    fi

    printf '%s' "$selected"
}

ensure_state_dir

REQ_HASH_FILE="$STATE_DIR/requirements.sha256"

LOG_FILE="$STATE_DIR/launcher.log"
if ! touch "$LOG_FILE" >/dev/null 2>&1; then
    fatal "Unable to write to $LOG_FILE."
fi

# Mirror stdout/stderr to the log file so Finder launches leave breadcrumbs.
exec >> >(tee -a "$LOG_FILE")
exec 2>&1

log "------------------------------------------------------------"
log "Launcher started at $(date)"

handle_existing_instance() {
    if [ ! -f "$SERVER_PID_FILE" ]; then
        return
    fi

    local running_pid=""
    if ! read -r running_pid < "$SERVER_PID_FILE"; then
        return
    fi

    if [ -z "$running_pid" ]; then
        rm -f "$SERVER_PID_FILE" >/dev/null 2>&1 || true
        return
    fi

    if ! kill -0 "$running_pid" >/dev/null 2>&1; then
        rm -f "$SERVER_PID_FILE" >/dev/null 2>&1 || true
        return
    fi

    log "A Casa del Pollo server is already running (PID: $running_pid)."

    local choice=""
    if command -v osascript >/dev/null 2>&1; then
        choice="$(osascript <<APPLESCRIPT
with timeout of 300 seconds
    set dialogText to "Casa del Pollo is already running in the background (PID ${running_pid}). What would you like to do?"
    try
        set optionsList to {"Stop Server", "Restart", "Open Dashboard", "Cancel"}
        set chosenItems to choose from list optionsList with prompt dialogText default items {"Stop Server"}
        if chosenItems is false then
            return "Cancel"
        else
            return item 1 of chosenItems
        end if
    on error number -128
        return "Cancel"
    end try
end timeout
APPLESCRIPT
)"
        choice="${choice//$'\r'/}"
        choice="${choice//$'\n'/}"
    fi

    if [ -z "$choice" ]; then
        echo "Options:"
        echo "  [S] Stop the running server and exit"
        echo "  [R] Restart it"
        echo "  [O] Leave it running and open $BROWSER_URL"
        echo "  [C] Cancel (do nothing)"
        if ! read -r -p "Choose S/R/O/C (default S): " choice < /dev/tty 2>/dev/null; then
            choice="S"
        fi
    fi

    case "$choice" in
        "Restart"|"R"|"r")
            stop_pid "$running_pid"
            log "Server stopped. Starting fresh..."
            return
            ;;
        "Open Dashboard"|"O"|"o")
            if command -v open >/dev/null 2>&1; then
                open "$BROWSER_URL"
            else
                log "Please open $BROWSER_URL manually."
            fi
            exit 0
            ;;
        "Cancel"|"C"|"c")
            log "Leaving the current server running."
            exit 0
            ;;
        *)
            stop_pid "$running_pid"
            log "Server stopped."
            exit 0
            ;;
    esac
}

REPO_DIR=""

handle_existing_instance

if try_repo_dir "$SCRIPT_DIR"; then
    :
elif [ -f "$CONFIG_FILE" ]; then
    if read -r stored_path < "$CONFIG_FILE"; then
        try_repo_dir "$stored_path" || true
    fi
fi

if [ -z "$REPO_DIR" ]; then
    for candidate in \
        "$SCRIPT_DIR/$REPO_NAME" \
        "$(dirname "$SCRIPT_DIR")/$REPO_NAME" \
        "$HOME/Desktop/$REPO_NAME" \
        "$HOME/Documents/$REPO_NAME" \
        "$HOME/Downloads/$REPO_NAME"; do
        if try_repo_dir "$candidate"; then
            break
        fi
    done
fi

if [ -z "$REPO_DIR" ]; then
    log "Could not automatically find the project. Please choose the Restaurant-website folder."
    selection="$(prompt_for_repo)"
    if [ -z "$selection" ]; then
        if [ -t 0 ]; then
            read -r -p "Path to the Restaurant-website folder: " selection
        else
            if command -v osascript >/dev/null 2>&1; then
                osascript <<'APPLESCRIPT' >/dev/null 2>&1 || true
                    display alert "Casa del Pollo Launcher" message "We couldn't access the Restaurant-website folder. Please click Allow if macOS prompts for Desktop/Documents access and try again." buttons {"OK"} default button "OK"
APPLESCRIPT
            fi
            fatal "No project folder selected. Relaunch and allow access when prompted."
        fi
    fi

    if ! try_repo_dir "$selection"; then
        fatal "The selected folder does not look like the Restaurant-website repo."
    fi
fi

if ! printf '%s\n' "$REPO_DIR" > "$CONFIG_FILE"; then
    log "Warning: couldn't save your project location. You'll be asked again next time."
fi

log "Using project folder: $REPO_DIR"
cd "$REPO_DIR"

if ! command -v python3 >/dev/null 2>&1; then
    fatal "python3 is required. Install it from https://www.python.org/downloads/."
fi

PYTHON3="$(command -v python3)"
VENV_DIR="$REPO_DIR/.venv"
PY_BIN="$VENV_DIR/bin/python"

if [ ! -d "$VENV_DIR" ]; then
    log "Creating virtual environment (first run)..."
    "$PYTHON3" -m venv "$VENV_DIR"
fi

REQ_FILE="$REPO_DIR/requirements.txt"
CURRENT_HASH=""
if [ -f "$REQ_FILE" ]; then
    CURRENT_HASH="$(REQ_FILE="$REQ_FILE" "$PY_BIN" - <<'PY'
import hashlib, pathlib, os
path = pathlib.Path(os.environ["REQ_FILE"])
print(hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "")
PY
)"
fi

INSTALLED_HASH=""
if [ -f "$REQ_HASH_FILE" ]; then
    read -r INSTALLED_HASH < "$REQ_HASH_FILE"
fi

if [ -n "$CURRENT_HASH" ] && [ "$CURRENT_HASH" = "$INSTALLED_HASH" ]; then
    log "Python dependencies already satisfied."
else
    log "Installing Python dependencies (this may take a minute)..."
    if ! "$PY_BIN" -m pip install --upgrade pip >/dev/null 2>&1; then
        log "pip upgrade skipped (likely offline). Continuing with the existing version."
    fi
    "$PY_BIN" -m pip install -r "$REQ_FILE"
    if [ -n "$CURRENT_HASH" ]; then
        printf '%s\n' "$CURRENT_HASH" > "$REQ_HASH_FILE"
    fi
fi

export FLASK_APP=app.py

FLASK_PID=""
cleanup() {
    if [ -n "${FLASK_PID:-}" ]; then
        echo
        stop_pid "$FLASK_PID"
    else
        rm -f "$SERVER_PID_FILE" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

log "Starting Flask on $STATUS_URL ..."
"$PY_BIN" -m flask run --host "$DEFAULT_HOST" --port "$DEFAULT_PORT" &
FLASK_PID=$!
if ! printf '%s\n' "$FLASK_PID" > "$SERVER_PID_FILE"; then
    fatal "Unable to write $SERVER_PID_FILE."
fi

log "Waiting for the server to come online..."
MAX_ATTEMPTS=30
ATTEMPT=1
if command -v curl >/dev/null 2>&1; then
    while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
        if curl -sSf "$STATUS_URL" >/dev/null 2>&1; then
            log "Server is up!"
            break
        else
            log "  Attempt $ATTEMPT/$MAX_ATTEMPTS: still starting..."
            sleep 1
        fi
        ATTEMPT=$((ATTEMPT + 1))
    done
else
    log "curl not found; waiting 5 seconds before opening the browser."
    sleep 5
fi

if [ $ATTEMPT -gt $MAX_ATTEMPTS ]; then
    fatal "Flask did not start within $MAX_ATTEMPTS seconds. Check the logs above for details."
fi

if command -v open >/dev/null 2>&1; then
    open "$BROWSER_URL"
    log "Browser opened to $BROWSER_URL"
else
    log "Please open $BROWSER_URL in your browser."
fi

log "Keep this Terminal window open to watch live logs."
log "Press Ctrl+C or close this window when you're done and we'll shut Flask down."
log "Need to stop it later without Terminal? Double-click this launcher again and choose \"Stop Server\"."

wait "$FLASK_PID"
