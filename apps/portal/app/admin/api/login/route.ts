import { NextRequest, NextResponse } from "next/server";

const PORTAL_API = process.env.PORTAL_API_URL ?? "http://localhost:18081";

// Verifies the operator's password by calling /v1/admin/stats with HTTP
// Basic. On success, sets an HttpOnly cookie holding the password (yes —
// this is a single-operator system, no accounts; the cookie *is* the
// session). Operator should set ADMIN_COOKIE_SECURE=1 in production.

export async function POST(req: NextRequest) {
  const { password } = await req.json();
  if (!password) return new NextResponse("password required", { status: 400 });

  const r = await fetch(`${PORTAL_API}/v1/admin/stats`, {
    headers: {
      authorization: "Basic " + Buffer.from(`admin:${password}`).toString("base64"),
    },
    cache: "no-store",
  });
  if (!r.ok) {
    return new NextResponse("incorrect password", { status: 401 });
  }
  const res = new NextResponse("ok");
  res.cookies.set("xgg_admin", password, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 12,
    secure: process.env.ADMIN_COOKIE_SECURE === "1",
  });
  return res;
}

export async function DELETE() {
  const res = new NextResponse("logged out");
  res.cookies.delete("xgg_admin");
  return res;
}
