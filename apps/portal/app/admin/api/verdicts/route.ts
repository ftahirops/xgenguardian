// Cookie-auth proxy for /v1/admin/verdicts. See queries/route.ts.

import { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";

export const dynamic = "force-dynamic";
const PORTAL_API = process.env.PORTAL_API_URL ?? "http://127.0.0.1:18081";

export async function GET(req: NextRequest) {
  const pw = (await cookies()).get("xgg_admin")?.value;
  if (!pw) return NextResponse.json({ error: "unauth" }, { status: 401 });

  const url = new URL(req.url);
  const upstream = new URL("/v1/admin/verdicts", PORTAL_API);
  for (const [k, v] of url.searchParams) upstream.searchParams.set(k, v);

  const r = await fetch(upstream, {
    headers: { authorization: "Basic " + Buffer.from(`admin:${pw}`).toString("base64") },
    cache: "no-store",
  });
  if (!r.ok) return NextResponse.json({ error: `upstream ${r.status}` }, { status: r.status });
  return new NextResponse(r.body, {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
