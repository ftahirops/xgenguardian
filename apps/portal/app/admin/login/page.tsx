"use client";

import { useState } from "react";

export default function Login() {
  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      const r = await fetch("/admin/api/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: pw }),
      });
      if (!r.ok) throw new Error((await r.text()) || "wrong password");
      location.href = "/admin";
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 360, margin: "120px auto", padding: 24 }}>
      <h1 style={{ marginBottom: 8 }}>Admin</h1>
      <p style={{ opacity: 0.6, marginTop: 0 }}>One password. No accounts.</p>
      <form onSubmit={submit} style={{ marginTop: 24 }}>
        <input
          type="password"
          autoFocus
          required
          placeholder="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          style={{
            width: "100%", padding: "12px 14px", boxSizing: "border-box",
            background: "#11141d", color: "inherit",
            border: "1px solid #2a3142", borderRadius: 8, fontSize: 16,
          }}
        />
        <button
          disabled={busy}
          style={{
            marginTop: 12, width: "100%", padding: "12px 14px",
            background: "#4f7cff", border: "none", borderRadius: 8,
            color: "white", fontWeight: 600, cursor: "pointer",
          }}
        >
          {busy ? "Checking…" : "Enter"}
        </button>
        {err && <p style={{ color: "#ff6b6b", marginTop: 12 }}>{err}</p>}
      </form>
    </div>
  );
}
