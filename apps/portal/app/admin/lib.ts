// Tiny admin-side helpers. The portal sets a cookie `xgg_admin=<password>`
// after the operator submits the login form; every fetch to portal-api
// reuses that cookie via the Authorization header on the server side.

import { cookies } from "next/headers";

export const PORTAL_API =
  process.env.PORTAL_API_URL ?? "http://localhost:18081";

export async function readPasswordFromCookie(): Promise<string | null> {
  // Next 15: cookies() returns a Promise<ReadonlyRequestCookies>.
  const store = await cookies();
  const v = store.get("xgg_admin")?.value;
  return v && v.length > 0 ? v : null;
}

export async function adminFetch(path: string, init?: RequestInit) {
  const pw = await readPasswordFromCookie();
  if (!pw) return { ok: false, status: 401, data: null as any };
  const headers = new Headers(init?.headers);
  headers.set("authorization", "Basic " + Buffer.from(`admin:${pw}`).toString("base64"));
  const res = await fetch(`${PORTAL_API}${path}`, { ...init, headers, cache: "no-store" });
  if (!res.ok) return { ok: false, status: res.status, data: null as any };
  return { ok: true, status: 200, data: await res.json() };
}
