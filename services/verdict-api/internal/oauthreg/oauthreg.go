// Package oauthreg — OAuth client_id reputation lookup.
//
// Identifies OAuth-consent-phishing attempts: a real Microsoft/Google login
// is shown but the consent screen requests sensitive permissions for an
// unknown/unverified client_id. We block these as
// OAUTH_UNKNOWN_CLIENT_ID even though the host domain is canonical.
//
// Recognises three providers' consent URLs by hostname + path pattern. Each
// provider exposes the client_id in a known query parameter. The registry
// is hydrated from Postgres at startup and refreshed every 10 minutes.
package oauthreg

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

type TrustLevel string

const (
	TrustVerified   TrustLevel = "verified"
	TrustKnown      TrustLevel = "known"
	TrustUnverified TrustLevel = "unverified"
	TrustMalicious  TrustLevel = "malicious"
)

// Decision is what the caller acts on. unknown == registry has no entry.
type Decision struct {
	Provider   string     // "microsoft" | "google" | "github" | ""
	ClientID   string
	Known      bool
	AppName    string
	TrustLevel TrustLevel
	Scopes     []string // scopes requested in the URL
	// Suspicious is true when scopes look high-impact (Mail.ReadWrite,
	// Files.ReadWrite.All, etc.). Caller uses this AND !Known to elevate
	// the verdict.
	SuspiciousScopes bool
}

// Cache is the in-memory registry of known good client_ids.
type Cache struct {
	pg     *pgxpool.Pool
	mu     sync.RWMutex
	byKey  map[string]entry // (provider+":"+client_id) → entry
	loaded time.Time
}

type entry struct {
	AppName    string
	TrustLevel TrustLevel
}

// New constructs a cache (empty until Start runs).
func New(pg *pgxpool.Pool) *Cache {
	return &Cache{pg: pg, byKey: map[string]entry{}}
}

// Start fetches the registry once, then refreshes every `interval`.
// Returns after first load (or its error).
func (c *Cache) Start(ctx context.Context, interval time.Duration) error {
	if err := c.refresh(ctx); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.refresh(ctx); err != nil {
					log.Warn().Err(err).Msg("oauthreg refresh")
				}
			}
		}
	}()
	return nil
}

func (c *Cache) refresh(ctx context.Context) error {
	rows, err := c.pg.Query(ctx, `
		SELECT provider, client_id, app_name, trust_level
		FROM oauth_clients
	`)
	if err != nil {
		return err
	}
	defer rows.Close()
	byKey := map[string]entry{}
	for rows.Next() {
		var p, cid, name, tl string
		if err := rows.Scan(&p, &cid, &name, &tl); err == nil {
			byKey[strings.ToLower(p)+":"+cid] = entry{AppName: name, TrustLevel: TrustLevel(tl)}
		}
	}
	c.mu.Lock()
	c.byKey = byKey
	c.loaded = time.Now()
	c.mu.Unlock()
	log.Info().Int("oauth_clients", len(byKey)).Msg("oauth registry hydrated")
	return nil
}

// Inspect parses a URL and, if it matches a known OAuth consent endpoint,
// returns a Decision. Returns nil for non-OAuth URLs.
//
// This is the entry point pipeline.go calls before fusion: when the URL is
// an OAuth consent screen the caller can decide independently of fusion.
func (c *Cache) Inspect(rawurl string) *Decision {
	u, err := url.Parse(rawurl)
	if err != nil || u.Host == "" {
		return nil
	}
	host := strings.ToLower(u.Host)
	path := u.Path

	provider, clientIDParam := matchProvider(host, path)
	if provider == "" {
		return nil
	}

	q := u.Query()
	clientID := q.Get(clientIDParam)
	if clientID == "" {
		return nil
	}
	scopes := scopeList(q.Get("scope"))

	c.mu.RLock()
	e, ok := c.byKey[provider+":"+clientID]
	c.mu.RUnlock()

	return &Decision{
		Provider:         provider,
		ClientID:         clientID,
		Known:            ok,
		AppName:          e.AppName,
		TrustLevel:       e.TrustLevel,
		Scopes:           scopes,
		SuspiciousScopes: anySensitiveScope(scopes),
	}
}

// matchProvider returns (providerName, clientIDQueryParamName) when host+path
// match a known consent endpoint. Empty provider → not an OAuth consent URL.
func matchProvider(host, path string) (string, string) {
	switch {
	case strings.HasSuffix(host, "login.microsoftonline.com") &&
		(strings.Contains(path, "/oauth2/v2.0/authorize") || strings.Contains(path, "/oauth2/authorize") || strings.Contains(path, "/adminconsent")):
		return "microsoft", "client_id"
	case host == "accounts.google.com" &&
		(strings.HasPrefix(path, "/o/oauth2/") || strings.HasPrefix(path, "/signin/oauth")):
		return "google", "client_id"
	case host == "github.com" && strings.HasPrefix(path, "/login/oauth/authorize"):
		return "github", "client_id"
	case host == "slack.com" && strings.HasPrefix(path, "/oauth/v2/authorize"):
		return "slack", "client_id"
	}
	return "", ""
}

// scopeList splits the `scope` query param. Microsoft / Google use
// space-separated; some providers use comma. We handle both.
func scopeList(raw string) []string {
	if raw == "" {
		return nil
	}
	// Some clients double-encode the space; URL parsing already decoded
	// %20 → space. Trim and split on whitespace and commas.
	var out []string
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == ',' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// anySensitiveScope returns true when at least one scope is in a curated
// "powerful" set. Covers Microsoft Graph + Google APIs scope strings.
func anySensitiveScope(scopes []string) bool {
	for _, s := range scopes {
		lc := strings.ToLower(s)
		switch {
		// --- Microsoft Graph ---
		case strings.Contains(lc, "mail.readwrite"),
			strings.Contains(lc, "mail.send"),
			strings.Contains(lc, "files.readwrite"),
			strings.Contains(lc, "sites.readwrite"),
			strings.Contains(lc, "directory.readwrite"),
			strings.Contains(lc, "user.readwrite.all"),
			strings.Contains(lc, "files.read.all"),
			strings.Contains(lc, "mail.read"),
			strings.Contains(lc, "chat.read"),
			strings.Contains(lc, "chat.readwrite"),
			strings.Contains(lc, "team.readwrite"),
		// --- Google ---
			strings.Contains(lc, "gmail.modify"),
			strings.Contains(lc, "gmail.send"),
			strings.Contains(lc, "gmail.compose"),
			strings.Contains(lc, "gmail.readonly"),
			strings.Contains(lc, "drive.file"),
			strings.Contains(lc, "drive"),
			strings.Contains(lc, "calendar"),
			strings.Contains(lc, "contacts"),
			strings.Contains(lc, "spreadsheets"),
			strings.Contains(lc, "cloud-platform"),
		// --- GitHub (Wave 3 corpus driven) ---
		// repo            full repo read/write — credential exfil-tier
		// admin:org       org-level admin (membership, repos, teams)
		// admin:repo_hook web-hook management — code injection vector
		// admin:enterprise/admin:gpg_key/admin:public_key
		// gist            full gist read/write
		// delete_repo     irreversible
		// notifications   email-style abuse
			lc == "repo",
			strings.HasPrefix(lc, "repo:"),
			strings.HasPrefix(lc, "admin:"),
			lc == "gist",
			lc == "delete_repo",
			lc == "notifications",
			strings.HasPrefix(lc, "write:"),
			strings.HasPrefix(lc, "workflow"),
		// --- Slack ---
			strings.Contains(lc, "chat:write"),
			strings.Contains(lc, "channels:history"),
			strings.Contains(lc, "groups:history"),
			strings.Contains(lc, "im:history"),
			strings.Contains(lc, "files:read"),
			strings.Contains(lc, "users.profile:write"),
		// --- Atlassian ---
			strings.Contains(lc, "write:jira-work"),
			strings.Contains(lc, "manage:jira-project"),
			strings.Contains(lc, "manage:jira-configuration"),
			strings.Contains(lc, "write:confluence-content"),
		// --- AWS / Azure / GCP (high-risk service scopes) ---
			strings.Contains(lc, "management.azure.com"),
			strings.Contains(lc, "analysis.windows.net"):
			return true
		}
	}
	return false
}
