// XGenGuardian — Windows tray client.
//
// Lightweight (no kernel driver, no TLS interception). Configures Windows 11
// native DNS-over-HTTPS to point at the XGenGuardian resolver, shows a tray
// icon with live status, opens the activity feed in WebView2 on click, and
// restores the original DNS configuration on exit.
//
// .NET 8 / Windows Forms. Single-file self-contained publish target so end
// users get one EXE, no .NET runtime install needed.

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace XGenGuardian;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        // Single-instance guard.
        using var _ = new Mutex(true, "Global\\XGenGuardian.Tray", out var first);
        if (!first) return;

        var ctx = new TrayContext();
        Application.Run(ctx);
    }
}
