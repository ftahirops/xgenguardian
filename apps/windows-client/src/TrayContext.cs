// TrayContext — application controller. Owns the tray icon, the DNS
// configuration lifecycle, the live-feed window, and a periodic
// health-poll timer.

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace XGenGuardian;

public sealed class TrayContext : ApplicationContext
{
    private readonly NotifyIcon _icon;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(3) };
    private LiveFeedForm? _liveForm;
    private bool _dnsConfigured;

    public TrayContext()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open live activity", null, (_, _) => OpenLive());
        menu.Items.Add("Check a URL…",       null, (_, _) => OpenCheck());
        menu.Items.Add("-");
        menu.Items.Add("Configure DNS",      null, async (_, _) => await ApplyDns());
        menu.Items.Add("Restore DNS",        null, async (_, _) => await RestoreDns());
        menu.Items.Add("-");
        menu.Items.Add("Quit",               null, (_, _) => Quit());

        _icon = new NotifyIcon
        {
            Visible = true,
            Icon = LoadIcon(),
            Text = "XGenGuardian",
            ContextMenuStrip = menu,
        };
        _icon.DoubleClick += (_, _) => OpenLive();

        _timer = new System.Windows.Forms.Timer { Interval = 5000 };
        _timer.Tick += async (_, _) => await PollHealth();
        _timer.Start();

        // Best-effort DNS configuration on first run. Operator can disable via tray menu.
        _ = ApplyDns();
    }

    // ─── DNS configuration ──────────────────────────────────────
    //
    // Windows 11 has native DoH support via `Add-DnsClientDohServerAddress`
    // and `Set-DnsClientServerAddress`. We avoid installing a local DNS
    // proxy or driver — everything goes through PowerShell.

    private async Task ApplyDns()
    {
        var endpoint = AppSettings.DohEndpoint;
        var resolverIp = AppSettings.ResolverIp; // local for dev, anycast for prod

        var ps = $@"
            $ErrorActionPreference = 'Stop'
            $iface = Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and $_.Virtual -eq $false }} | Select-Object -First 1
            if (-not $iface) {{ Write-Error 'no active adapter'; exit 2 }}
            try {{ Remove-DnsClientDohServerAddress -ServerAddress '{resolverIp}' -ErrorAction SilentlyContinue }} catch {{}}
            Add-DnsClientDohServerAddress -ServerAddress '{resolverIp}' -DohTemplate '{endpoint}' -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
            Set-DnsClientServerAddress -InterfaceIndex $iface.ifIndex -ServerAddresses ('{resolverIp}') | Out-Null
            Clear-DnsClientCache
            Write-Host 'OK'
        ";
        await RunPowerShellElevated(ps, "configure DNS");
        _dnsConfigured = true;
        ShowBalloon("DNS configured", "All DNS now flows through XGenGuardian.");
    }

    private async Task RestoreDns()
    {
        var ps = @"
            $iface = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false } | Select-Object -First 1
            if ($iface) { Set-DnsClientServerAddress -InterfaceIndex $iface.ifIndex -ResetServerAddresses | Out-Null }
            Clear-DnsClientCache
            Write-Host 'OK'
        ";
        await RunPowerShellElevated(ps, "restore DNS");
        _dnsConfigured = false;
        ShowBalloon("DNS restored", "Back to your previous resolver.");
    }

    private static async Task RunPowerShellElevated(string script, string description)
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"xgg-{Guid.NewGuid():N}.ps1");
        await File.WriteAllTextAsync(tmp, script);
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -ExecutionPolicy Bypass -File \"{tmp}\"")
            {
                UseShellExecute = true,
                Verb = "runas", // UAC prompt
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using var p = Process.Start(psi);
            if (p == null) throw new InvalidOperationException("failed to spawn powershell");
            await p.WaitForExitAsync();
            if (p.ExitCode != 0) throw new Exception($"powershell exit {p.ExitCode} ({description})");
        }
        finally
        {
            try { File.Delete(tmp); } catch { }
        }
    }

    // ─── UI ────────────────────────────────────────────────────────

    private void OpenLive()
    {
        if (_liveForm == null || _liveForm.IsDisposed)
        {
            _liveForm = new LiveFeedForm(AppSettings.PortalUrl + "/live");
        }
        _liveForm.Show();
        _liveForm.BringToFront();
        _liveForm.Activate();
    }

    private void OpenCheck()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = AppSettings.PortalUrl,
            UseShellExecute = true,
        });
    }

    private void Quit()
    {
        _timer.Stop();
        _icon.Visible = false;
        if (_dnsConfigured)
        {
            try { RestoreDns().GetAwaiter().GetResult(); } catch { }
        }
        Application.Exit();
    }

    private void ShowBalloon(string title, string body)
    {
        _icon.BalloonTipTitle = title;
        _icon.BalloonTipText = body;
        _icon.ShowBalloonTip(2500);
    }

    private static System.Drawing.Icon LoadIcon()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "icon.ico");
            if (File.Exists(path)) return new System.Drawing.Icon(path);
        }
        catch { }
        return System.Drawing.SystemIcons.Shield;
    }

    // ─── Health polling ────────────────────────────────────────────

    private async Task PollHealth()
    {
        try
        {
            using var resp = await _http.GetAsync(AppSettings.VerdictApi + "/healthz");
            _icon.Text = resp.IsSuccessStatusCode
                ? "XGenGuardian — protected"
                : "XGenGuardian — degraded";
        }
        catch
        {
            _icon.Text = "XGenGuardian — backend unreachable";
        }
    }
}
