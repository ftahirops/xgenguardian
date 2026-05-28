// sessionlog.go — append every verdict as one JSON line to
// data/sessions/<UTC-date>.jsonl.
//
// Enabled when env SESSION_LOG_DIR is set. Designed for internal-testing:
// the operator finishes a session and ships the .jsonl file as an artifact
// with their BUGS.md entries.
//
// Format (one JSON object per line):
//   {"ts":"2026-05-14T17:33:02Z","url":"https://...","domain":"...",
//    "verdict":"BLOCK","confidence":0.97,"visual_top_brand":"paypal",
//    "visual_top_score":0.96,"signals":[{"name":"...","weight":...,"detail":"..."}],
//    "client_id":"resolver","evidence_id":""}
//
// Writes are buffered per-process and flushed on every event (small volume
// during internal testing; no need for batching).

package httpgw

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type sessionLogger struct {
	dir   string
	mu    sync.Mutex
	day   string
	file  *os.File
}

var globalSessionLog *sessionLogger

// EnableSessionLog turns the JSONL log on if SESSION_LOG_DIR env is set.
// Call once during verdict-api startup.
func EnableSessionLog() {
	dir := os.Getenv("SESSION_LOG_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warn().Err(err).Str("dir", dir).Msg("session log: mkdir failed")
		return
	}
	globalSessionLog = &sessionLogger{dir: dir}
	log.Info().Str("dir", dir).Msg("session JSONL log enabled")
}

func writeSessionLog(event map[string]any) {
	sl := globalSessionLog
	if sl == nil {
		return
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()

	day := time.Now().UTC().Format("2006-01-02")
	if sl.file == nil || sl.day != day {
		if sl.file != nil {
			_ = sl.file.Close()
		}
		path := filepath.Join(sl.dir, day+".jsonl")
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("session log: open failed")
			return
		}
		sl.file = f
		sl.day = day
	}

	b, err := json.Marshal(event)
	if err != nil {
		return
	}
	if _, err := sl.file.Write(append(b, '\n')); err != nil {
		log.Warn().Err(err).Msg("session log: write failed")
	}
}
