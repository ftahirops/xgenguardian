// AppSettings — configuration with simple env-var overrides.
// In production we'd back this with a JSON file under %APPDATA%\XGenGuardian\.

namespace XGenGuardian;

public static class AppSettings
{
    public static string DohEndpoint =>
        System.Environment.GetEnvironmentVariable("XGG_DOH")
        ?? "https://dns.xgenguardian.com/dns-query";

    public static string ResolverIp =>
        System.Environment.GetEnvironmentVariable("XGG_RESOLVER_IP")
        ?? "127.0.0.1"; // for local internal testing; in prod this is anycast

    public static string VerdictApi =>
        System.Environment.GetEnvironmentVariable("XGG_VERDICT_API")
        ?? "http://localhost:18080";

    public static string PortalUrl =>
        System.Environment.GetEnvironmentVariable("XGG_PORTAL_URL")
        ?? "http://localhost:13000";
}
