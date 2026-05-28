import { NextResponse } from "next/server";

// POST /admin/api/logout — clears cookie, sends back to /admin/login.
export async function POST() {
  const res = NextResponse.redirect(
    new URL("/admin/login", process.env.NEXT_PUBLIC_BASE_URL ?? "http://localhost:13000"),
    303,
  );
  res.cookies.delete("xgg_admin");
  return res;
}
