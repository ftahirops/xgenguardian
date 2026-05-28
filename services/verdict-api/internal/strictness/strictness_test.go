package strictness

import (
	"testing"
	"time"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestApply_NormalMode_PassesThrough(t *testing.T) {
	for _, raw := range []Verdict{Allow, Warn, Block, Isolate} {
		got := Apply(
			Inputs{RawVerdict: raw, Grade: GradeC},
			Policy{Paranoid: false, Now: now},
		)
		if got.Verdict != raw {
			t.Errorf("normal mode raw=%s grade=C: got %s, want %s", raw, got.Verdict, raw)
		}
		if got.StrictnessApplied {
			t.Errorf("normal mode should never mark StrictnessApplied")
		}
	}
}

func TestApply_Paranoid_GradeTable(t *testing.T) {
	cases := []struct {
		grade Grade
		raw   Verdict
		want  Verdict
		flag  bool
	}{
		{GradeAPlus, Allow, Allow, false},
		{GradeA, Allow, Allow, false},
		{GradeB, Allow, Isolate, true},
		{GradeC, Warn, Isolate, true},
		{GradeC, Allow, Isolate, true},
		{GradeD, Isolate, Isolate, false},
		{GradeD, Warn, Isolate, true},
		{GradeF, Allow, Block, true},
		{GradeFPlus, Warn, Block, true},
		{"", Allow, Isolate, true},
		{"", Warn, Isolate, true},
	}
	for _, c := range cases {
		got := Apply(
			Inputs{RawVerdict: c.raw, Grade: c.grade},
			Policy{Paranoid: true, Now: now},
		)
		if got.Verdict != c.want || got.StrictnessApplied != c.flag {
			t.Errorf("grade=%q raw=%s: got (%s, applied=%v), want (%s, applied=%v)",
				c.grade, c.raw, got.Verdict, got.StrictnessApplied, c.want, c.flag)
		}
	}
}

func TestApply_BlockNeverDowngraded(t *testing.T) {
	// Detection wins over strictness in both directions.
	got := Apply(
		Inputs{RawVerdict: Block, Grade: GradeAPlus},
		Policy{Paranoid: true, Now: now},
	)
	if got.Verdict != Block {
		t.Errorf("BLOCK from fusion on A+ page must stay BLOCK, got %s", got.Verdict)
	}
}

func TestApply_Override_BypassesStrictness(t *testing.T) {
	got := Apply(
		Inputs{RawVerdict: Allow, Grade: GradeC, FromOverride: true},
		Policy{Paranoid: true, Now: now},
	)
	if got.Verdict != Allow {
		t.Errorf("override should pass through; got %s", got.Verdict)
	}
	if got.StrictnessApplied {
		t.Errorf("override should not flag StrictnessApplied")
	}
}

func TestApply_SensitivePageClass_NotElevated(t *testing.T) {
	// Login/payment/oauth/admin/download/consent: fusion + TTL caps handle.
	// Strictness must not double-up.
	for _, class := range []string{"login", "payment", "oauth", "admin", "download", "consent"} {
		got := Apply(
			Inputs{RawVerdict: Allow, Grade: GradeC, PageClass: class},
			Policy{Paranoid: true, Now: now},
		)
		if got.Verdict != Allow {
			t.Errorf("paranoid + class=%q: got %s, want pass-through Allow", class, got.Verdict)
		}
	}
}

func TestApply_Warmup_GradeBStaysAllow(t *testing.T) {
	enabled := now.Add(-1 * time.Hour) // within warmup
	got := Apply(
		Inputs{RawVerdict: Allow, Grade: GradeB},
		Policy{Paranoid: true, EnabledAt: enabled, Now: now},
	)
	if got.Verdict != Allow {
		t.Errorf("warmup: B should still be Allow, got %s", got.Verdict)
	}
}

func TestApply_Warmup_ExpiredKicksInStrictness(t *testing.T) {
	enabled := now.Add(-25 * time.Hour) // past warmup
	got := Apply(
		Inputs{RawVerdict: Allow, Grade: GradeB},
		Policy{Paranoid: true, EnabledAt: enabled, Now: now},
	)
	if got.Verdict != Isolate {
		t.Errorf("post-warmup: B should ISOLATE, got %s", got.Verdict)
	}
	if !got.StrictnessApplied {
		t.Errorf("post-warmup elevation should set StrictnessApplied")
	}
}

func TestApply_Warmup_DoesNotProtectUnknownOrLowerGrades(t *testing.T) {
	// Warmup grace is only for grade B. Unknown/C/D still get ISOLATE.
	enabled := now.Add(-1 * time.Hour)
	for _, g := range []Grade{"", GradeC, GradeD} {
		got := Apply(
			Inputs{RawVerdict: Allow, Grade: g},
			Policy{Paranoid: true, EnabledAt: enabled, Now: now},
		)
		if got.Verdict != Isolate {
			t.Errorf("warmup grade=%q: got %s, want Isolate", g, got.Verdict)
		}
	}
}

func TestApply_AlreadyStrictRawNotDowngraded(t *testing.T) {
	// Fusion returned ISOLATE on a B page in paranoid; floor is also ISOLATE.
	// elevate() should leave it alone and NOT flag as strictness-applied.
	got := Apply(
		Inputs{RawVerdict: Isolate, Grade: GradeB},
		Policy{Paranoid: true, Now: now},
	)
	if got.Verdict != Isolate {
		t.Errorf("raw Isolate on B paranoid: got %s, want Isolate", got.Verdict)
	}
	if got.StrictnessApplied {
		t.Errorf("no elevation needed, should not flag StrictnessApplied")
	}
}
