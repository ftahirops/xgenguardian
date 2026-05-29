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
//
// Size cap: when a day-file exceeds 100 MB it is rotated to .1, .2 etc.
// (oldest generation dropped once more than maxGenerations exist).
//
// Retention: files older than SESSION_LOG_RETENTION_DAYS (default 14) are
// deleted on startup and every hour thereafter.

package httpgw

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	sessionLogMaxBytes    = 100 * 1024 * 1024 // 100 MB per-file cap before rotation
	sessionLogMaxGens     = 5                  // keep up to .1 .2 .3 .4 .5 for a given day
	sessionLogDefaultDays = 14
)

type sessionLogger struct {
	dir       string
	mu        sync.Mutex
	day       string
	file      *os.File
	bytesWritten int64
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
	sl := &sessionLogger{dir: dir}
	globalSessionLog = sl
	log.Info().Str("dir", dir).Msg("session JSONL log enabled")

	// Initial retention sweep, then every hour.
	go func() {
		sl.deleteOldFiles()
		for range time.Tick(time.Hour) {
			sl.deleteOldFiles()
		}
	}()
}

// retentionDays returns the configured retention window, defaulting to 14 days.
func retentionDays() int {
	if v := os.Getenv("SESSION_LOG_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return sessionLogDefaultDays
}

// deleteOldFiles removes .jsonl files (and their rotated siblings) whose
// date prefix is older than retentionDays().
func (sl *sessionLogger) deleteOldFiles() {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays())
	entries, err := os.ReadDir(sl.dir)
	if err != nil {
		log.Warn().Err(err).Str("dir", sl.dir).Msg("session log: readdir failed during retention")
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Accept both "2006-01-02.jsonl" and "2006-01-02.jsonl.N" (rotated).
		base := strings.TrimSuffix(name, filepath.Ext(name))
		if strings.HasSuffix(base, ".jsonl") {
			base = strings.TrimSuffix(base, ".jsonl")
		}
		t, err := time.Parse("2006-01-02", base)
		if err != nil {
			continue // not a date-named file; ignore
		}
		if t.Before(cutoff) {
			p := filepath.Join(sl.dir, name)
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				log.Warn().Err(err).Str("path", p).Msg("session log: retention remove failed")
			}
		}
	}
}

// rotateCurrent renames the current open file to .1, bumping existing
// generations up. The oldest generation beyond maxGenerations is deleted.
// Must be called with sl.mu held.
func (sl *sessionLogger) rotateCurrent(dayPath string) {
	if sl.file != nil {
		_ = sl.file.Close()
		sl.file = nil
	}
	// Shift existing .1 → .2 → … → .N; delete anything above maxGenerations.
	for gen := sessionLogMaxGens; gen >= 1; gen-- {
		old := fmt.Sprintf("%s.%d", dayPath, gen)
		if gen == sessionLogMaxGens {
			_ = os.Remove(old)
			continue
		}
		newer := fmt.Sprintf("%s.%d", dayPath, gen+1)
		_ = os.Rename(old, newer)
	}
	// Rename the active file to .1.
	_ = os.Rename(dayPath, dayPath+".1")
	sl.bytesWritten = 0
}

func writeSessionLog(event map[string]any) {
	sl := globalSessionLog
	if sl == nil {
		return
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()

	day := time.Now().UTC().Format("2006-01-02")
	dayPath := filepath.Join(sl.dir, day+".jsonl")

	// Day boundary: close old file and reset byte counter.
	if sl.file != nil && sl.day != day {
		_ = sl.file.Close()
		sl.file = nil
		sl.bytesWritten = 0
	}

	// Size cap: rotate before writing if current file already exceeds the cap.
	if sl.file != nil && sl.bytesWritten >= sessionLogMaxBytes {
		sl.rotateCurrent(dayPath)
	}

	// Open (or re-open after rotation).
	if sl.file == nil {
		f, err := os.OpenFile(dayPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Warn().Err(err).Str("path", dayPath).Msg("session log: open failed")
			return
		}
		// Sync byte counter with existing file size (resuming across restarts).
		if fi, err := f.Stat(); err == nil {
			sl.bytesWritten = fi.Size()
		}
		sl.file = f
		sl.day = day
	}

	b, err := json.Marshal(event)
	if err != nil {
		return
	}
	line := append(b, '\n')
	n, err := sl.file.Write(line)
	if err != nil {
		log.Warn().Err(err).Msg("session log: write failed")
		return
	}
	sl.bytesWritten += int64(n)
}
