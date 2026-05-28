#!/usr/bin/env bash
# Start every service in Procfile.dev. Prefers overmind, falls back to
# foreman, finally falls back to a tmux script the operator can attach to.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p data/sessions

# Ensure infra is up before we start the services.
docker compose ps --status running --quiet postgres >/dev/null 2>&1 || {
  echo "→ docker compose stack not running; starting it..."
  docker compose up -d
}

if command -v overmind >/dev/null 2>&1; then
  echo "→ using overmind"
  exec overmind start -f Procfile.dev
fi

if command -v foreman >/dev/null 2>&1; then
  echo "→ using foreman"
  exec foreman start -f Procfile.dev
fi

if command -v tmux >/dev/null 2>&1; then
  echo "→ overmind / foreman not found, falling back to tmux"
  SESSION="xgg"
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  tmux new-session -d -s "$SESSION" -n visual-match \
    "cd services/visual-match && uvicorn app.main:app --host 0.0.0.0 --port 8003 --reload"
  tmux new-window  -t "$SESSION" -n sandbox \
    "cd services/sandbox-render && uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload"
  tmux new-window  -t "$SESSION" -n verdict \
    "cd services/verdict-api && go run ./cmd/verdict-api"
  tmux new-window  -t "$SESSION" -n portal-api \
    "cd services/portal-api && go run ./cmd/portal-api"
  tmux new-window  -t "$SESSION" -n resolver \
    "cd services/resolver && go run ./cmd/resolver"
  tmux new-window  -t "$SESSION" -n ct-monitor \
    "cd services/ct-monitor && go run ./cmd/ct-monitor"
  tmux new-window  -t "$SESSION" -n portal \
    "cd apps/portal && npm run dev"
  echo "✓ tmux session 'xgg' created. Attach with: tmux attach -t xgg"
  exit 0
fi

cat <<EOF
✗ No process manager found.
  Install one of:
    brew install overmind      (recommended)
    gem install foreman
    apt install tmux
  Then re-run \`make dev-up\`.
EOF
exit 1
