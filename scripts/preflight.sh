#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

have_failures=0

warn() {
  printf '%s\n' "$*" >&2
}

fail() {
  warn "ERROR: $*"
  have_failures=1
}

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  env_paths=(
    ".env"
    "apps/campaign_console/.env"
    "apps/unsubscribe_service/.env"
    "apps/website/.env"
  )
  for path in "${env_paths[@]}"; do
    if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
      fail "$path is tracked by git; remove it and rotate secrets (see DEPLOY_NOTES_DREAMHOST.md)."
    fi
  done
else
  warn "Skipping git checks (not in a git worktree)."
fi

SCANNER="rg"
if ! command -v "$SCANNER" >/dev/null 2>&1; then
  SCANNER="grep"
fi

secret_patterns=(
  "EMAIL_PASSWORD"
  "DB_PASS"
  "DB_PASSWORD"
  "RECAPTCHA_SECRET_KEY"
  "APP_SECRET_KEY"
  "LOG_STREAM_TOKEN_SECRET"
  "BEGIN PRIVATE KEY"
)

placeholder_markers=(
  "replace"
  "example"
  "sample"
  "changeme"
  "rotate"
  "your_"
  "your "
  "<"
  "dummy"
  "os.getenv"
  "envvalue"
)

scan_secrets() {
  local -a matches=()
  if [[ "$SCANNER" == "rg" ]]; then
    while IFS= read -r line; do
      matches+=("$line")
    done < <(
      rg --no-heading --line-number --color=never \
        --glob '!.env.example' \
        --glob '!**/*.example' \
        --glob '!**/*.sample' \
        --glob '!**/README*' \
        --regexp "^[[:space:]]*(?:export[[:space:]]+)?(EMAIL_PASSWORD|DB_PASS|DB_PASSWORD|RECAPTCHA_SECRET_KEY|APP_SECRET_KEY|LOG_STREAM_TOKEN_SECRET)[[:space:]]*=[[:space:]]*['\"A-Za-z0-9]"
    )
    while IFS= read -r line; do
      matches+=("$line")
    done < <(rg --no-heading --line-number --color=never "BEGIN PRIVATE KEY")
  else
    while IFS= read -r pattern; do
      while IFS= read -r line; do
        matches+=("$line")
      done < <(grep -RIn --exclude='*.example' -- "$pattern" || true)
    done < <(printf '%s\n' "${secret_patterns[@]}")
  fi

  for entry in "${matches[@]}"; do
    [[ -z "$entry" ]] && continue
    IFS=: read -r file line text <<<"$entry"
    lowercase_text="$(printf '%s' "$text" | tr '[:upper:]' '[:lower:]')"
    value="${text#*=}"
    value_trimmed="$(printf '%s' "$value" | sed -e 's/^[[:space:]]*//')"
    if [[ "$file" == *.py && "$value_trimmed" != \'* && "$value_trimmed" != \"* ]]; then
      continue
    fi
    skip=0
    for marker in "${placeholder_markers[@]}"; do
      if [[ "$lowercase_text" == *"$marker"* ]]; then
        skip=1
        break
      fi
    done
    if [[ "$file" == *".example" || "$file" == "scripts/preflight.sh" ]]; then
      skip=1
    fi
    if [[ $skip -eq 1 ]]; then
      continue
    fi
    fail "Potential secret detected in $file:$line — inspect and remove sensitive value."
  done
}

scan_secrets

if find "$ROOT_DIR/apps/unsubscribe_service" -maxdepth 2 -type f -name '*.log' -print -quit | grep -q .; then
  fail "Log files detected inside apps/unsubscribe_service/; move logs outside the docroot."
fi

if [[ $have_failures -ne 0 ]]; then
  warn ""
  warn "Preflight failed. Resolve the issues above, rotate affected secrets, then re-run scripts/preflight.sh."
  exit 1
fi

echo "Preflight passed — no tracked .env, no obvious secrets, and no stray logs."
