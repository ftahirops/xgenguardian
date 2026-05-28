// Same-origin SSE proxy: the browser hits /api/stream on the portal, the
// portal opens an SSE connection to verdict-api on the server's loopback and
// forwards events. Avoids the browser ever needing to know the verdict-api
// port or CORS rules.

import { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const VERDICT_API =
  process.env.VERDICT_API_URL ?? "http://127.0.0.1:18080";

export async function GET(req: NextRequest) {
  const upstream = await fetch(`${VERDICT_API}/v1/stream`, {
    cache: "no-store",
    // Forward client abort so verdict-api can drop its subscriber.
    signal: req.signal,
  });
  if (!upstream.ok || !upstream.body) {
    return new Response("upstream unavailable", { status: 502 });
  }

  return new Response(upstream.body, {
    status: 200,
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      "connection": "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
