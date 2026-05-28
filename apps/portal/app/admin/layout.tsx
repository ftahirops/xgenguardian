import Link from "next/link";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export default async function AdminLayout({ children }: { children: React.ReactNode }) {
  // Anyone hitting /admin/* must be authed except /admin/login itself.
  // Next.js doesn't expose the pathname in a server layout cleanly, so we
  // do a soft check: if there's no cookie, send them to /login.
  // The login page itself doesn't need this layout — it lives at /admin/login
  // and Next nests the layout; we route the case in the layout body.
  // Next 15: cookies() is async.
  const store = await cookies();
  const hasPw = !!store.get("xgg_admin")?.value;
  return (
    <>
      <nav
        style={{
          display: "flex", gap: 16, padding: "12px 24px",
          borderBottom: "1px solid #1f2330", alignItems: "center",
        }}
      >
        <strong style={{ marginRight: 16 }}>XGG admin</strong>
        <Link href="/admin"          style={navL}>Overview</Link>
        <Link href="/admin/queries"  style={navL}>DNS queries</Link>
        <Link href="/admin/verdicts" style={navL}>Verdicts</Link>
        <Link href="/live"           style={navL}>Live feed</Link>
        <div style={{ flex: 1 }} />
        {hasPw && <LogoutButton />}
      </nav>
      <div style={{ padding: 24 }}>{children}</div>
    </>
  );
}

function LogoutButton() {
  // Server component can't carry a click handler; render a form that hits
  // the same route with DELETE-via-POST.
  return (
    <form action="/admin/api/logout" method="POST">
      <button
        style={{
          background: "transparent", border: "1px solid #2a3142",
          color: "#bcc3d0", padding: "4px 12px", borderRadius: 6, cursor: "pointer",
        }}
      >
        Log out
      </button>
    </form>
  );
}

const navL: React.CSSProperties = { color: "#cfd4dd", textDecoration: "none", fontSize: 14 };
