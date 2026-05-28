// XGenGuardian — HTML-smuggling pattern detection.
//
// HTML smuggling reassembles a downloadable payload entirely client-side
// (Blob/Uint8Array → URL.createObjectURL → programmatic anchor-click) so the
// network sees only innocuous traffic. We catch the three primitives
// together — the combination is rare on legitimate sites and ubiquitous on
// smuggling kits (Nobelium, Qakbot, Pikabot variants).

rule xgg_html_smuggling
{
    meta:
        author      = "XGenGuardian"
        description = "Blob + createObjectURL + programmatic anchor-click reconstructs a payload"
        severity    = "high"
        reason_code = "HTML_SMUGGLING_PATTERN"
        rule_version = "1"

    strings:
        $blob1            = "new Blob(" ascii
        $blob2            = /new\s+Blob\s*\(\s*\[/
        $create_object_url = "URL.createObjectURL" ascii
        $anchor_click_1    = /\.click\(\s*\)/
        $anchor_click_2    = "HTMLAnchorElement.prototype.click" ascii
        // Big base64 blob — payload often ships as an embedded base64 string.
        // YARA-friendly form: long run of base64-class chars (200+ in a row
        // is rare on legit pages, common on smuggling kits where the encoded
        // payload is at minimum a few hundred bytes).
        $big_base64 = /[A-Za-z0-9+]{200}/

    condition:
        1 of ($blob*)
        and $create_object_url
        and 1 of ($anchor_click_*)
        and $big_base64
}
