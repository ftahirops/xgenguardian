# XGenGuardian — Windows Client

A tray app that points your Windows DNS at the XGenGuardian resolver
(via the native Windows 11 DoH stack — no kernel driver, no TLS interception),
shows live activity in an embedded WebView2 window, and cleanly restores
your DNS on exit.

## Why .NET 8 (not .NET Framework)?

.NET 8 is the current cross-platform .NET. It builds **a single self-contained
EXE that runs on any Windows 10/11 machine without a runtime install**. Old
.NET Framework is Windows-only, pre-installed on Win 10/11, and ~30 MB
smaller — but slower to develop on, no AOT, and Microsoft has end-of-lifed
the major version.

If you need a Framework build (e.g. for Win 7 or constrained images), the
same source compiles against `net48` with a few using-statement tweaks.

## Build

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
cd apps\windows-client
.\build.ps1
```

Output: `bin\Release\net8.0-windows\win-x64\publish\XGenGuardian.exe`
(~60 MB self-contained, ~3 MB framework-dependent).

## Run

```powershell
.\bin\Release\net8.0-windows\win-x64\publish\XGenGuardian.exe
```

On first run, the app prompts for UAC to configure Windows DoH. After that,
the tray icon shows `XGenGuardian — protected`.

Default endpoints (overridable via env):

| Env | Default |
|---|---|
| `XGG_DOH` | `https://dns.xgenguardian.com/dns-query` |
| `XGG_RESOLVER_IP` | `127.0.0.1` (local internal testing) |
| `XGG_VERDICT_API` | `http://localhost:18080` |
| `XGG_PORTAL_URL` | `http://localhost:13000` |

For **internal testing** against your local stack, also set:

```powershell
$env:XGG_DOH = "https://dns.local.test:8543/dns-query"
$env:XGG_RESOLVER_IP = "127.0.0.1"
```

Then trust the dev CA: open `tls\ca.pem` and import into **Trusted Root
Certification Authorities** under `certmgr.msc`.

## Tray menu

- **Open live activity** — opens the embedded /live feed.
- **Check a URL…** — opens the public Transparency Portal in your default
  browser.
- **Configure DNS** — re-applies the DoH configuration.
- **Restore DNS** — reverts to your previous resolver. Also done
  automatically on Quit.
- **Quit** — shut down the tray app and restore DNS.

## What it does NOT do

- Does not install a kernel driver.
- Does not run a local HTTPS-intercepting proxy.
- Does not install a root CA (it uses *your* trust store for the DoH endpoint,
  which is signed by a real CA in production).
- Does not see HTTPS content. The DoH layer only carries DNS queries.

For full content visibility (Phase-5 endpoint mode), you'll want the Win
endpoint kernel-driver build — separate project, separate trust posture.

## Uninstall

The app holds no installer or registry state. Quit the tray app (which
restores DNS) and delete the EXE.
