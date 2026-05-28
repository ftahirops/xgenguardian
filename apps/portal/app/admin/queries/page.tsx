"use client";

import { useCallback, useEffect, useState } from "react";
import Pagination from "../_components/Pagination";

type Q = {
  ts: string;
  domain: string;
  qtype: string;
  client_ip: string;
  verdict: string;
  cache_hit: boolean;
  sinkhole: boolean;
  duration_ms: number;
  client_id: string;
};

type Resp = { rows: Q[]; total: number; offset: number; limit: number };

const PAGE_SIZE = 20;

export default function Queries() {
  const [rows, setRows] = useState<Q[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [verdict, setVerdict] = useState("");

  const fetchPage = useCallback(
    async (p: number) => {
      setLoading(true);
      setErr(null);
      try {
        const params = new URLSearchParams({
          limit: String(PAGE_SIZE),
          offset: String((p - 1) * PAGE_SIZE),
        });
        if (q) params.set("q", q);
        if (verdict) params.set("verdict", verdict);
        const r = await fetch(`/admin/api/queries?${params}`, { cache: "no-store" });
        if (r.status === 401) {
          location.href = "/admin/login";
          return;
        }
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = (await r.json()) as Resp;
        setTotal(data.total);
        setRows(data.rows);
        setPage(p);
        window.scrollTo({ top: 0, behavior: "smooth" });
      } catch (e: any) {
        setErr(String(e.message ?? e));
      } finally {
        setLoading(false);
      }
    },
    [q, verdict],
  );

  // Reload from page 1 on filter change.
  useEffect(() => {
    fetchPage(1);
  }, [fetchPage]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>DNS queries</h1>

      <form onSubmit={(e) => e.preventDefault()} style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input
          name="q"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="search domain…"
          style={inp}
        />
        <select
          name="verdict"
          value={verdict}
          onChange={(e) => setVerdict(e.target.value)}
          style={inp}
        >
          <option value="">all verdicts</option>
          <option value="clean">clean</option>
          <option value="block">block</option>
          <option value="warn">warn</option>
          <option value="analyzing">analyzing</option>
          <option value="unknown">unknown</option>
        </select>
      </form>

      <p style={{ opacity: 0.6, fontSize: 13 }}>
        {total.toLocaleString()} total {q || verdict ? "(filtered)" : ""} ·{" "}
        showing {rows.length} on this page
        {loading && <span style={{ marginLeft: 8 }}>· loading…</span>}
        {err && <span style={{ color: "#ff6b6b", marginLeft: 8 }}>· {err}</span>}
      </p>

      <table style={tbl}>
        <thead>
          <tr>
            <th style={th}>Time</th>
            <th style={th}>Source IP</th>
            <th style={th}>Domain</th>
            <th style={th}>Type</th>
            <th style={th}>Verdict</th>
            <th style={th}>Cache</th>
            <th style={th}>Sinkhole</th>
            <th style={{ ...th, textAlign: "right" }}>ms</th>
            <th style={th}>Via</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.ts}-${i}`} style={{ background: i % 2 ? "transparent" : "#0e1219" }}>
              <td style={tdMono}>{new Date(r.ts).toLocaleString()}</td>
              <td style={tdMono}>{r.client_ip || <span style={{ opacity: 0.4 }}>—</span>}</td>
              <td style={tdMono}><code>{r.domain}</code></td>
              <td style={tdMono}>{r.qtype}</td>
              <td style={td}><span style={pill(r.verdict)}>{r.verdict}</span></td>
              <td style={td}>{r.cache_hit ? "✓" : ""}</td>
              <td style={td}>{r.sinkhole ? "✓" : ""}</td>
              <td style={{ ...tdMono, textAlign: "right" }}>{r.duration_ms}</td>
              <td style={td}>{r.client_id}</td>
            </tr>
          ))}
          {rows.length === 0 && !loading && (
            <tr><td colSpan={9} style={{ ...td, opacity: 0.5 }}><em>No matching queries.</em></td></tr>
          )}
        </tbody>
      </table>

      <Pagination
        page={page}
        totalPages={totalPages}
        disabled={loading}
        onPage={(p) => fetchPage(p)}
      />
    </div>
  );
}

const inp: React.CSSProperties = {
  padding: "8px 12px", background: "#11141d", color: "inherit",
  border: "1px solid #2a3142", borderRadius: 6, fontSize: 14,
};
const tbl: React.CSSProperties = { width: "100%", borderCollapse: "collapse", fontSize: 13 };
const th: React.CSSProperties = { textAlign: "left", padding: "8px 12px", borderBottom: "1px solid #2a3142", color: "#9aa3b2" };
const td: React.CSSProperties = { padding: "6px 12px", borderBottom: "1px solid #1a1f2c" };
const tdMono: React.CSSProperties = { ...td, fontFamily: "ui-monospace, Menlo, monospace", fontSize: 12 };

function pill(v: string): React.CSSProperties {
  const color =
    v === "block"    ? "#ff6b6b" :
    v === "warn"     ? "#faad14" :
    v === "clean"    ? "#52c41a" :
    v === "analyzing"? "#5e8bff" : "#888";
  return {
    display: "inline-block", padding: "1px 8px", borderRadius: 999,
    background: color + "22", color, fontSize: 11, fontWeight: 700, letterSpacing: 0.3,
  };
}
