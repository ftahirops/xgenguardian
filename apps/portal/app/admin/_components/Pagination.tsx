"use client";

// Numbered pagination: « ‹ 1 … 6 7 [8] 9 10 … 36 › »
// Always shows first + last, the current page, and ±2 on each side.
// Ellipsis when there are gaps.

type Props = {
  page: number;          // 1-indexed
  totalPages: number;
  onPage: (page: number) => void;
  disabled?: boolean;
};

export default function Pagination({ page, totalPages, onPage, disabled }: Props) {
  if (totalPages <= 1) return null;

  const pages = buildPageList(page, totalPages);

  const click = (p: number) => {
    if (disabled || p === page || p < 1 || p > totalPages) return;
    onPage(p);
  };

  return (
    <nav style={{ display: "flex", gap: 4, alignItems: "center", flexWrap: "wrap", justifyContent: "center", marginTop: 16 }}>
      <Btn disabled={disabled || page === 1} onClick={() => click(1)} title="First">«</Btn>
      <Btn disabled={disabled || page === 1} onClick={() => click(page - 1)} title="Previous">‹</Btn>

      {pages.map((p, i) =>
        p === "…" ? (
          <span key={`gap-${i}`} style={{ ...numStyle, cursor: "default", opacity: 0.5, border: "1px solid transparent" }}>…</span>
        ) : (
          <button
            key={p}
            onClick={() => click(p)}
            disabled={disabled || p === page}
            style={{
              ...numStyle,
              background: p === page ? "#4f7cff" : "#11141d",
              color: p === page ? "white" : "#cfd4dd",
              borderColor: p === page ? "#4f7cff" : "#2a3142",
              fontWeight: p === page ? 700 : 500,
            }}
          >
            {p}
          </button>
        ),
      )}

      <Btn disabled={disabled || page === totalPages} onClick={() => click(page + 1)} title="Next">›</Btn>
      <Btn disabled={disabled || page === totalPages} onClick={() => click(totalPages)} title="Last">»</Btn>

      <span style={{ marginLeft: 12, opacity: 0.55, fontSize: 12 }}>
        Page {page} of {totalPages}
      </span>
    </nav>
  );
}

function Btn({
  children, onClick, disabled, title,
}: { children: React.ReactNode; onClick: () => void; disabled?: boolean; title?: string }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={{
        ...numStyle,
        background: "#11141d",
        color: disabled ? "#4a5266" : "#cfd4dd",
        cursor: disabled ? "default" : "pointer",
      }}
    >
      {children}
    </button>
  );
}

const numStyle: React.CSSProperties = {
  minWidth: 36,
  padding: "6px 10px",
  border: "1px solid #2a3142",
  borderRadius: 6,
  fontSize: 13,
  textAlign: "center",
  fontFamily: "ui-monospace, Menlo, monospace",
  cursor: "pointer",
  userSelect: "none",
};

// buildPageList — pure helper.
// Shows: 1, …, page-2, page-1, page, page+1, page+2, …, totalPages
// with ellipses replaced by the literal string "…".
// For small total counts (<=9 pages) shows everything.
function buildPageList(page: number, totalPages: number): (number | "…")[] {
  if (totalPages <= 9) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }
  const out: (number | "…")[] = [];
  const window = 2; // pages on each side of current
  const left = Math.max(2, page - window);
  const right = Math.min(totalPages - 1, page + window);

  out.push(1);
  if (left > 2) out.push("…");
  for (let p = left; p <= right; p++) out.push(p);
  if (right < totalPages - 1) out.push("…");
  out.push(totalPages);
  return out;
}
