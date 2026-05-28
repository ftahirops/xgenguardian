// XGenGuardian — Magecart / e-commerce card-skimmer pattern detection.
//
// Skimmers attach to checkout pages (typically Shopify, WooCommerce, Magento)
// and exfiltrate payment-card data via `fetch()` / image beacons to attacker
// domains. We catch the *combination* of:
//   - field selectors targeting card-number / CVV / expiry inputs, AND
//   - silent exfil to a cross-origin endpoint (fetch / Image src / WebSocket).
//
// Pure-event listeners on payment fields are common in legitimate analytics;
// the cross-origin exfil is the bright-line discriminator.

rule xgg_magecart_card_field_listener
{
    meta:
        author      = "XGenGuardian"
        description = "Listener on payment-card form fields combined with silent exfiltration"
        severity    = "high"
        reason_code = "FORM_POSTS_TO_UNRELATED_DOMAIN"
        rule_version = "1"

    strings:
        $sel_cardnum1 = /input\[\s*name\s*=\s*["']?(cc_?num|card[_-]?number|cardno)/ nocase
        $sel_cardnum2 = "ccNumber" ascii nocase
        $sel_cvv      = /input\[\s*name\s*=\s*["']?(cvv|cvc|csc|securitycode)/ nocase
        $sel_expiry   = /input\[\s*name\s*=\s*["']?(exp(iry|date|month|year)?)/ nocase

        $keydown      = ".addEventListener('keydown'" ascii
        $keyup        = ".addEventListener('keyup'" ascii
        $blur         = ".addEventListener('blur'" ascii
        $input_listen = ".addEventListener('input'" ascii

        $fetch_exfil  = /fetch\s*\(\s*["'`]https?:\/\/[^"'`]+["'`]/
        $beacon_img   = /new\s+Image\s*\(\s*\)\s*\.src\s*=\s*["'`]https?:\/\//
        $websocket    = /new\s+WebSocket\s*\(\s*["'`]wss?:\/\//

    condition:
        2 of ($sel_*)
        and 1 of ($keydown, $keyup, $blur, $input_listen)
        and 1 of ($fetch_exfil, $beacon_img, $websocket)
}

rule xgg_magecart_known_skimmer_strings
{
    meta:
        author      = "XGenGuardian"
        description = "Strings characteristic of known Magecart skimmer families (community-documented IOCs)"
        severity    = "high"
        reason_code = "FORM_POSTS_TO_UNRELATED_DOMAIN"
        rule_version = "1"

    strings:
        // Generic obfuscated-skimmer markers that recur across families.
        $magecart_check = "checkout" ascii nocase
        $btoa_payload   = /btoa\s*\(\s*JSON\.stringify\s*\(/
        $send_beacon    = "navigator.sendBeacon(" ascii
        // Common card-data field bundling pattern.
        $bundle1        = /JSON\.stringify\s*\(\s*\{[^}]*(cardnumber|ccnum)/ nocase
        $bundle2        = /name\s*:\s*card.{0,20}cvv\s*:/ nocase

    condition:
        $magecart_check
        and ($btoa_payload or $send_beacon)
        and 1 of ($bundle*)
}
