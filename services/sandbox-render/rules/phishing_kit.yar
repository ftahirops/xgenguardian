// XGenGuardian — generic phishing-kit fingerprints.
//
// Phishing kits ship with telltale boilerplate: anti-debugging, victim-
// telemetry exfil, and brand-pretender assets fetched from cdn-jsdelivr or
// raw github. Each rule on its own would false-positive; we require multiple
// signals.

rule xgg_phishing_kit_anti_debug
{
    meta:
        author      = "XGenGuardian"
        description = "Anti-debugging / anti-bot patterns common to credential phishing kits"
        severity    = "medium"
        reason_code = "LOGIN_FORM_ON_UNAPPROVED_DOMAIN"
        rule_version = "1"

    strings:
        // Right-click / shortcut blockers (common phishing-kit boilerplate).
        $no_rclick   = /document\.addEventListener\s*\(\s*['"]contextmenu['"]/
        $no_keys     = /e\.key(Code)?\s*===?\s*(123|U|S|I|J|C)/ nocase
        // Bot/headless detection in the page itself.
        $no_webdriver = /navigator\.webdriver/
        $no_phantom   = "_phantom" ascii
        // Victim telemetry collection: usually IP-lookup + UA capture before
        // showing the credential form.
        $ip_lookup1 = "ipify.org" nocase
        $ip_lookup2 = "ipinfo.io" nocase
        $ip_lookup3 = "ipapi.co" nocase
        $ua_collect = "navigator.userAgent" ascii

    condition:
        ($no_rclick or $no_keys)
        and ($no_webdriver or $no_phantom)
        and 1 of ($ip_lookup*)
        and $ua_collect
}

rule xgg_phishing_kit_telegram_exfil
{
    meta:
        author      = "XGenGuardian"
        description = "Credential exfiltration via Telegram Bot API — a phishing-kit staple"
        severity    = "critical"
        reason_code = "KNOWN_PHISH_URL_MATCH"
        rule_version = "1"

    strings:
        $tg_api1 = "api.telegram.org/bot" ascii nocase
        $tg_send = /sendMessage\?chat_id=-?\d+/
        $tg_token = /bot\d{8,}:[A-Za-z0-9_-]{30,}/

    condition:
        $tg_api1 and ($tg_send or $tg_token)
}
