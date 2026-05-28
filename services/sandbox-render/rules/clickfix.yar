// XGenGuardian — ClickFix / paste-to-run pattern detection.
//
// ClickFix attacks instruct the victim (via on-page text) to:
//   1. press Win+R or open PowerShell,
//   2. paste a command the page just put on their clipboard,
//   3. press Enter.
//
// We catch two halves and require BOTH: the social-engineering instruction
// AND the cmd/powershell payload syntax. Either alone is a false-positive
// hazard (tutorials, docs).

rule xgg_clickfix_instructions
{
    meta:
        author      = "XGenGuardian"
        description = "ClickFix social-engineering text instructing the user to run a pasted command"
        severity    = "high"
        reason_code = "CLICKFIX_INSTRUCTION_PATTERN"
        rule_version = "1"

    strings:
        $plus_r     = /[\(]?Win(dows)?[\)]?\s*\+\s*R/ nocase
        $powershell = "PowerShell" nocase
        $verify_human = "verify you are human" nocase
        $not_a_robot = "not a robot" nocase
        $paste       = /paste|press\s+ctrl\s*\+\s*v/ nocase

    condition:
        // Need at least one "run terminal" cue, one "paste" cue, and a
        // captcha-disguise cue.
        ($plus_r or $powershell)
        and $paste
        and (1 of ($verify_human, $not_a_robot))
}

rule xgg_clickfix_payload_in_clipboard
{
    meta:
        author      = "XGenGuardian"
        description = "ClickFix payload commonly placed on the clipboard via JS"
        severity    = "high"
        reason_code = "CLIPBOARD_HIJACK_ATTEMPT"
        rule_version = "1"

    strings:
        $clip_write_1 = "navigator.clipboard.writeText" ascii
        $clip_write_2 = "document.execCommand('copy')" ascii
        // Permissive payload patterns: powershell anywhere near EncodedCommand
        // (single dash or flag chain), plus a couple of common cmd variants.
        $cmd_payload  = /powershell[^"'<>]{0,80}EncodedCommand/ nocase
        $cmd_payload2 = /mshta\s+http/ nocase
        $cmd_payload3 = /cmd(\.exe)?\s+\/c\s+/ nocase
        $cmd_payload4 = /iex\s*\(/ nocase
        $cmd_payload5 = /Invoke-WebRequest/ nocase

    condition:
        1 of ($clip_write_*) and 1 of ($cmd_payload*)
}
