// stream.go — Server-Sent Events feed of every verdict.
//
// The live activity feed (portal /live) subscribes to /v1/stream and renders
// each verdict as it's decided. The verdict-api publishes to a Redis pub/sub
// channel "xgg:verdicts" after every CheckURL; this SSE handler subscribes
// and pipes events to connected browsers.
//
// Why Redis pub/sub instead of in-process channels: lets multiple verdict-api
// replicas share the same feed without sticky load balancing.

package httpgw

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const verdictChannel = "xgg:verdicts"

// PublishVerdict pushes a verdict event to the Redis channel. Called from
// runPipeline after every check; errors are logged but not surfaced (the
// stream is best-effort).
func PublishVerdict(ctx context.Context, rdb *redis.Client, evt map[string]any) {
	b, err := json.Marshal(evt)
	if err != nil {
		return
	}
	if err := rdb.Publish(ctx, verdictChannel, b).Err(); err != nil {
		log.Warn().Err(err).Msg("publish verdict")
	}
}

// stream handles GET /v1/stream. Holds the connection open and writes
// one `data: {json}\n\n` line per verdict event.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "text/event-stream")
	w.Header().Set("cache-control", "no-cache")
	w.Header().Set("connection", "keep-alive")
	w.Header().Set("x-accel-buffering", "no")
	w.Header().Set("access-control-allow-origin", "*")

	ctx := r.Context()
	sub := s.Rdb.Subscribe(ctx, verdictChannel)
	defer sub.Close()
	ch := sub.Channel()

	// Send a hello so the client sees the connection is live.
	_, _ = w.Write([]byte("event: hello\ndata: {\"ok\":true}\n\n"))
	flusher.Flush()

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write([]byte("data: " + msg.Payload + "\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
