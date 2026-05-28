// Package ttl computes per-grade and per-page-class TTLs and decay rules
// (UNIFIED-PLAN.md §4.2).
//
// Hard rules:
//   - Sensitive page classes (login/payment/oauth/admin/download) have caps
//     that override grade TTL.
//   - Paranoid (Executive Mode) users get tighter decay: A+ stays A+ for
//     30d (not 45), A stays A for 14d (not 30).
package ttl

import "time"

// Grade strings — same set verdict-api/internal/strictness uses. Duplicated
// here to avoid a cross-service dependency; if they diverge, CI will catch.
type Grade string

const (
	APlus Grade = "A+"
	A     Grade = "A"
	B     Grade = "B"
	C     Grade = "C"
	D     Grade = "D"
	F     Grade = "F"
	FPlus Grade = "F+"
)

// PageClass — denormalized from urls.page_class.
type PageClass string

const (
	Generic  PageClass = "generic"
	Login    PageClass = "login"
	Payment  PageClass = "payment"
	OAuth    PageClass = "oauth"
	Admin    PageClass = "admin"
	Download PageClass = "download"
)

// For returns the next re-scan TTL for a (grade, page_class) pair.
// Paranoid (true) applies the tightened decay schedule.
func For(g Grade, pc PageClass, paranoid bool) time.Duration {
	base := baseFor(g, paranoid)
	cap := classCap(pc)
	if cap > 0 && cap < base {
		return cap
	}
	return base
}

// baseFor implements the grade-only TTL matrix.
func baseFor(g Grade, paranoid bool) time.Duration {
	day := 24 * time.Hour
	switch g {
	case APlus:
		if paranoid {
			return 30 * day
		}
		return 38 * day // midpoint of 30-45 d range
	case A:
		if paranoid {
			return 14 * day
		}
		return 30 * day
	case B:
		return 24 * time.Hour
	case C:
		return 6 * time.Hour
	case D:
		return 30 * time.Minute
	case F:
		return 12 * time.Hour
	case FPlus:
		return 14 * day // midpoint of 7-30 d
	}
	return 24 * time.Hour
}

// classCap returns the maximum TTL allowed for a sensitive page class.
// 0 = no cap (generic pages use the grade TTL).
func classCap(pc PageClass) time.Duration {
	day := 24 * time.Hour
	switch pc {
	case Login, Payment, OAuth, Admin:
		return 7 * day
	case Download:
		return 6 * time.Hour
	}
	return 0
}

// IsSensitive reports whether the page class gets a TTL cap.
func IsSensitive(pc PageClass) bool {
	return classCap(pc) > 0
}
