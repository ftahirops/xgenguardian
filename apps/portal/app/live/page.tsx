"use client";

import { useEffect, useState } from "react";

type Event = {
  url: string;
  domain: string;
  verdict: "CLEAN" | "WARN" | "BLOCK" | "ANALYZING" | "UNKNOWN";
  confidence?: number;
  visual_top_brand?: string;
  visual_top_score?: number;
  signals?: { name: string; weight: number; detail: string }[];
  client_id?: string;
  client_ip?: string;
  scanned_at: string;
};

// Same-origin proxy — portal forwards to verdict-api on the server side,
// so the browser never needs to know which port verdict-api binds to.
const STREAM_URL = "/api/stream";

export default function Live() {
  const [events, setEvents] = useState<Event[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const es = new EventSource(STREAM_URL);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (m) => {
      try {
        const e = JSON.parse(m.data) as Event;
        setEvents((prev) => [e, ...prev].slice(0, 200));
      } catch {}
    };
    return () => es.close();
  }, []);

  const counts = events.reduce(
    (acc, e) => {
      acc[e.verdict] = (acc[e.verdict] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  return (
    <div>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ margin: 0 }}>Live activity</h1>
          <p style={{ margin: "4px 0 0", opacity: 0.6, fontSize: 13 }}>
            Every verdict, as it happens.
          </p>
        </div>
        <span
          style={{
            padding: "4px 12px",
            borderRadius: 999,
            background: connected ? "#0d2a13" : "#3a1014",
            color: connected ? "#52c41a" : "#ff6b6b",
            fontSize: 12,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: 0.5,
          }}
        >
          {connected ? "connected" : "disconnected"}
        </span>
      </header>

      <div style={{ display: "flex", gap: 12, marginTop: 18, flexWrap: "wrap" }}>
        <Counter label="CLEAN"     n={counts.CLEAN ?? 0}     color="#52c41a" />
        <Counter label="WARN"      n={counts.WARN ?? 0}      color="#faad14" />
        <Counter label="BLOCK"     n={counts.BLOCK ?? 0}     color="#ff4d4f" />
        <Counter label="UNKNOWN"   n={counts.UNKNOWN ?? 0}   color="#888" />
        <Counter label="ANALYZING" n={counts.ANALYZING ?? 0} color="#5e8bff" />
      </div>

      <div style={{ marginTop: 24 }}>
        {events.length === 0 && (
          <p style={{ opacity: 0.5 }}>
            Waiting for traffic. Set your device&apos;s DNS server to{" "}
            <code>135.181.79.27</code> and open any website.
          </p>
        )}
        {events.map((e, i) => (
          <Row key={`${e.scanned_at}-${i}`} e={e} />
        ))}
      </div>
    </div>
  );
}

function Counter({ label, n, color }: { label: string; n: number; color: string }) {
  return (
    <div
      style={{
        padding: "10px 16px",
        background: "#11141c",
        border: "1px solid #2a3142",
        borderRadius: 8,
        minWidth: 110,
      }}
    >
      <div style={{ fontSize: 11, opacity: 0.7, letterSpacing: 0.5, textTransform: "uppercase", color }}>
        {label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 700 }}>{n}</div>
    </div>
  );
}

function Row({ e }: { e: Event }) {
  const color =
    e.verdict === "BLOCK" ? "#ff4d4f" :
    e.verdict === "WARN"  ? "#faad14" :
    e.verdict === "CLEAN" ? "#52c41a" : "#888";

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "90px 1fr 110px",
        gap: 12,
        padding: "10px 14px",
        borderBottom: "1px solid #1a1f2c",
        alignItems: "center",
        fontSize: 14,
      }}
    >
      <span
        style={{
          display: "inline-block",
          padding: "2px 10px",
          borderRadius: 999,
          background: color + "22",
          color,
          fontWeight: 700,
          fontSize: 11,
          letterSpacing: 0.5,
          textAlign: "center",
        }}
      >
        {e.verdict}
      </span>
      <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        <div style={{ fontFamily: "ui-monospace, Menlo, monospace" }}>
          {e.url || e.domain}
          {e.client_ip && (
            <span style={{ opacity: 0.5, marginLeft: 10, fontSize: 12 }}>
              from <code>{e.client_ip}</code>
            </span>
          )}
        </div>
        {e.visual_top_brand && (
          <div style={{ opacity: 0.6, fontSize: 12 }}>
            ↳ visual: {e.visual_top_brand} {(e.visual_top_score! * 100).toFixed(0)}%
          </div>
        )}
        {e.signals && e.signals.length > 0 && (
          <div style={{ opacity: 0.55, fontSize: 12 }}>
            {e.signals.slice(0, 3).map((s) => s.name).join(" · ")}
          </div>
        )}
      </div>
      <div style={{ textAlign: "right", opacity: 0.55, fontSize: 12, fontFamily: "ui-monospace, monospace" }}>
        {new Date(e.scanned_at).toLocaleTimeString()}
      </div>
    </div>
  );
}
