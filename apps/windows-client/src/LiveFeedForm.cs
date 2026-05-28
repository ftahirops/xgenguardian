// LiveFeedForm — a thin Form hosting a WebView2 pointed at the local
// portal's /live page. Keeps everything in one app; no separate browser.

using System;
using System.Windows.Forms;
using Microsoft.Web.WebView2.WinForms;

namespace XGenGuardian;

public sealed class LiveFeedForm : Form
{
    private readonly WebView2 _web;

    public LiveFeedForm(string url)
    {
        Text = "XGenGuardian — Live activity";
        Width = 980;
        Height = 720;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new System.Drawing.Size(640, 420);

        _web = new WebView2 { Dock = DockStyle.Fill };
        Controls.Add(_web);

        Load += async (_, _) =>
        {
            await _web.EnsureCoreWebView2Async();
            _web.Source = new Uri(url);
        };
    }
}
