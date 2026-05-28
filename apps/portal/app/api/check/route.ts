import { NextRequest, NextResponse } from "next/server";

const VERDICT_API = process.env.VERDICT_API_URL ?? "http://localhost:18080";

export async function POST(req: NextRequest) {
  const { url } = await req.json();
  if (!url) return NextResponse.json({ error: "url required" }, { status: 400 });

  // The portal proxies to verdict-api's HTTP gateway. Phase-1 stub:
  // until the real gateway exists, return a synthetic verdict so the UI is testable.
  try {
    const r = await fetch(`${VERDICT_API}/v1/check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!r.ok) throw new Error(`upstream ${r.status}`);
    return NextResponse.json(await r.json());
  } catch (e) {
    return NextResponse.json(
      {
        verdict: "ANALYZING",
        confidence: 0.0,
        signals: [{ name: "stub", weight: 0, detail: "verdict-api not reachable; portal stub" }],
        llm_explanation:
          "verdict-api is not yet wired. This is a portal-side stub response so the UI can be developed independently.",
      },
      { status: 200 },
    );
  }
}
