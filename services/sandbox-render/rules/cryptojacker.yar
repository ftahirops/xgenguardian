// XGenGuardian — in-browser cryptojacker detection.
//
// Catches both the post-CoinHive miner libraries that descended from it and
// generic wasm-mining patterns. Two separate rules so analysts can tell
// whether the page is using a known-bad library vs. a custom miner.

rule xgg_cryptojacker_known_libs
{
    meta:
        author      = "XGenGuardian"
        description = "Known browser-miner library or pool reference"
        severity    = "medium"
        reason_code = "MINER_POOL_CONTACT"
        rule_version = "1"

    strings:
        $coinhive_1   = "coinhive.com" ascii nocase
        $coinhive_2   = "coin-hive.com" ascii nocase
        $cryptoloot_1 = "crypto-loot.com" ascii nocase
        $cryptoloot_2 = "webmine.cz" ascii nocase
        $jsecoin      = "jsecoin.com" ascii nocase
        $minero_in    = "minero.cc" ascii nocase
        $coinimp      = "coinimp.com" ascii nocase
        $coinhave     = "coinhave.com" ascii nocase
        $deepminer    = "deepMiner" ascii
        $wasminer     = "WASMineLib" ascii

    condition:
        any of them
}

rule xgg_cryptojacker_wasm_miner_pattern
{
    meta:
        author      = "XGenGuardian"
        description = "WASM module load combined with crypto-miner constants"
        severity    = "medium"
        reason_code = "MINER_POOL_CONTACT"
        rule_version = "1"

    strings:
        $wasm_load  = "WebAssembly.instantiate" ascii
        $wasm_load2 = "WebAssembly.instantiateStreaming" ascii
        $cryptonight = "cryptonight" nocase
        $monero      = "monero" nocase
        $rx_pool     = /pool[._-](monerohash|nanopool|minexmr|nanopool|supportxmr)/ nocase
        $stratum     = "stratum+tcp" ascii nocase
        $threads_var = /threads\s*[:=]\s*[1-9]/ nocase ascii

    condition:
        1 of ($wasm_load*)
        and 1 of ($cryptonight, $monero, $rx_pool, $stratum)
        and $threads_var
}
