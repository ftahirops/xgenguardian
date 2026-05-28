"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import Pagination from "../_components/Pagination";

type V = {
  evidence_id: string;
  visual_top_brand: string;
  visual_top_score: number;
  created_at: string;
  url_hash: string;
};

type Resp = { rows: V[]; total: number; offset: number; limit: number };
const PAGE_SIZE = 20;

export default function Verdicts() {
  const [rows, setRows] = useState<V[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [brand, setBrand] = useState("");

  const fetchPage = useCallback(
    async (p: number) => {
      setLoading(true); setErr(null);
      try {
        const params = new URLSearchParams({
          limit: String(PAGE_SIZE),
          offset: String((p - 1) * PAGE_SIZE),
        });
        if (brand) params.set("brand", brand);
        const r = await fetch(`/admin/api/verdicts?${params}`, { cache: "no-store" });
        if (r.status === 401) { location.href = "/admin/login"; return; }
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
    [brand],
  );

  useEffect(() => { fetchPage(1); }, [fetchPage]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>URL verdicts</h1>

      <form onSubmit={(e) => e.preventDefault()} style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input
          value={brand}
          onChange={(e) => setBrand(e.target.value)}
          placeholder="filter by impersonated brand…"
          style={inp}
        />
      </form>

      <p style={{ opacity: 0.6, fontSize: 13 }}>
        {total.toLocaleString()} total {brand ? "(filtered)" : ""} ·{" "}
        showing {rows.length} on this page
        {loading && <span style={{ marginLeft: 8 }}>· loading…</span>}
        {err && <span style={{ color: "#ff6b6b", marginLeft: 8 }}>· {err}</span>}
      </p>

      <table style={tbl}>
        <thead>
          <tr>
            <th style={th}>Time</th>
            <th style={th}>Top-brand match</th>
            <th style={{ ...th, textAlign: "right" }}>Score</th>
            <th style={th}>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.evidence_id}>
              <td style={tdMono}>{new Date(r.created_at).toLocaleString()}</td>
              <td style={td}>{r.visual_top_brand || <span style={{ opacity: 0.4 }}>—</span>}</td>
              <td style={{ ...tdMono, textAlign: "right" }}>
                {r.visual_top_score ? (r.visual_top_score * 100).toFixed(0) + "%" : ""}
              </td>
              <td style={td}>
                <Link href={`/report/${r.evidence_id}`} target="_blank" style={{ color: "#5e8bff" }}>
                  {r.evidence_id.slice(0, 8)} →
                </Link>
              </td>
            </tr>
          ))}
          {rows.length === 0 && !loading && (
            <tr><td colSpan={4} style={{ ...td, opacity: 0.5 }}><em>No verdicts yet.</em></td></tr>
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
  border: "1px solid #2a3142", borderRadius: 6, fontSize: 14, width: 320,
};
const tbl: React.CSSProperties = { width: "100%", borderCollapse: "collapse", fontSize: 13 };
const th: React.CSSProperties = { textAlign: "left", padding: "8px 12px", borderBottom: "1px solid #2a3142", color: "#9aa3b2" };
const td: React.CSSProperties = { padding: "6px 12px", borderBottom: "1px solid #1a1f2c" };
const tdMono: React.CSSProperties = { ...td, fontFamily: "ui-monospace, Menlo, monospace", fontSize: 12 };
