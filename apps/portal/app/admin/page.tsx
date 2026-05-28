import { redirect } from "next/navigation";
import { adminFetch, readPasswordFromCookie } from "./lib";

export const dynamic = "force-dynamic";

export default async function AdminHome() {
  if (!(await readPasswordFromCookie())) redirect("/admin/login");
  const { ok, data } = await adminFetch("/v1/admin/stats");
  if (!ok) redirect("/admin/login");

  const stats = data as {
    dns_total_24h: number;
    dns_blocked_24h: number;
    dns_cache_hits_24h: number;
    verdicts_24h: number;
    brands: number;
    hour_buckets: { hour: string; total: number; blocked: number }[];
    top_blocked: { domain: string; hits: number }[];
  };

  const total = stats.dns_total_24h || 0;
  const blocked = stats.dns_blocked_24h || 0;
  const blockRate = total ? (blocked / total) * 100 : 0;
  const cacheRate = total ? (stats.dns_cache_hits_24h / total) * 100 : 0;

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Overview · last 24 h</h1>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginTop: 18 }}>
        <Stat label="DNS queries"    value={total.toLocaleString()} />
        <Stat label="Blocked"        value={`${blocked.toLocaleString()} (${blockRate.toFixed(1)}%)`} color="#ff6b6b" />
        <Stat label="Cache hits"     value={`${stats.dns_cache_hits_24h.toLocaleString()} (${cacheRate.toFixed(0)}%)`} color="#52c41a" />
        <Stat label="URL verdicts"   value={stats.verdicts_24h.toLocaleString()} />
        <Stat label="Brands seeded"  value={stats.brands.toLocaleString()} />
      </div>

      <h2 style={{ marginTop: 36 }}>Hour buckets</h2>
      <SparkBars data={stats.hour_buckets || []} />

      <h2 style={{ marginTop: 36 }}>Top blocked domains (24 h)</h2>
      <table style={tbl}>
        <thead>
          <tr><th style={th}>Domain</th><th style={{ ...th, textAlign: "right" }}>Hits</th></tr>
        </thead>
        <tbody>
          {(stats.top_blocked || []).map((r) => (
            <tr key={r.domain}>
              <td style={td}><code>{r.domain}</code></td>
              <td style={{ ...td, textAlign: "right" }}>{r.hits}</td>
            </tr>
          ))}
          {(!stats.top_blocked || stats.top_blocked.length === 0) && (
            <tr><td style={td} colSpan={2}><em style={{ opacity: 0.5 }}>No blocks yet.</em></td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ padding: 16, background: "#11141c", border: "1px solid #2a3142", borderRadius: 8 }}>
      <div style={{ fontSize: 11, opacity: 0.6, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4, color: color ?? "inherit" }}>{value}</div>
    </div>
  );
}

function SparkBars({ data }: { data: { hour: string; total: number; blocked: number }[] }) {
  if (data.length === 0) return <p style={{ opacity: 0.5 }}>No data.</p>;
  const max = Math.max(...data.map((d) => d.total));
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 120 }}>
      {data.map((d) => {
        const totalH = max ? (d.total / max) * 120 : 0;
        const blockedH = max ? (d.blocked / max) * 120 : 0;
        return (
          <div key={d.hour} title={`${d.hour}: ${d.total} total, ${d.blocked} blocked`}
               style={{ flex: 1, position: "relative", height: 120 }}>
            <div style={{ position: "absolute", bottom: 0, width: "100%", height: totalH, background: "#2a3142" }} />
            <div style={{ position: "absolute", bottom: 0, width: "100%", height: blockedH, background: "#ff6b6b" }} />
          </div>
        );
      })}
    </div>
  );
}

const tbl: React.CSSProperties = { width: "100%", borderCollapse: "collapse", fontSize: 14 };
const th: React.CSSProperties = { textAlign: "left", padding: "10px 14px", borderBottom: "1px solid #2a3142", color: "#9aa3b2", fontWeight: 600 };
const td: React.CSSProperties = { padding: "8px 14px", borderBottom: "1px solid #1a1f2c" };
