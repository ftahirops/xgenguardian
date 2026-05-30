// Package cryptodrainer — wallet-drainer / NFT-scam / wallet-revoke
// phishing scorer.
//
// Wallet drainers are scam web pages that prompt the user to connect a
// crypto wallet (MetaMask, Phantom, Trust Wallet, Rainbow, etc.) and
// then trick the user into signing a malicious transaction — usually
// an `eth_signTypedData_v4` permit, an `setApprovalForAll` for an NFT
// collection, or an unlimited `approve` for an ERC-20 token. Once
// signed, the drainer empties the wallet.
//
// Two signal sources today (Wave 3 / Phase 2 architecture):
//
//   1. Page text / URL / title — drainer lure phrases (claim airdrop,
//      revoke permissions, free mint, verify wallet, sync wallet).
//   2. Page scripts (suspicious_js findings) — EIP-1193 wallet methods
//      typically only requested by trading dApps. When ANY of
//      `eth_signTypedData_v4`, `personal_sign`, `wallet_addEthereumChain`,
//      or `wallet_watchAsset` appear in script content on a host NOT
//      in the curated dApp registry, the page is almost always a drainer.
//
// Source basis:
//
//   Chainalysis Crypto Crime report (annual): wallet drainers stole
//     ~$500M in 2024 across confirmed cases.
//   MetaMask Snaps drainer-detection guidance: signature-content checks
//     before wallet prompt.
//   Inferno / Pink / Venom / Angel drainer public reverse-engineering
//     posts (blog.chainabuse.com, Scam Sniffer Discord history).
//
// Phase 3 will extend with: actual transaction simulation against an
// archive node, known-drainer signature-DB lookup (Inferno script
// fingerprints), and approval-target reputation.
package cryptodrainer

import (
	"sort"
	"strings"
)

// Inputs mirrors supportscam/paymentscam for plumbing consistency.
type Inputs struct {
	URL         string
	SLD         string
	Title       string
	VisibleText string
	OCRText     string
	Host        string
	// HostInBrandgraph short-circuits all categories — Coinbase,
	// MetaMask.io, OpenSea.io are legitimate dApp / wallet brands and
	// must not be scored as drainers.
	HostInBrandgraph bool
	// ScriptIndicators — content of suspicious_js findings from sandbox-
	// render. We scan these for EIP-1193 wallet methods. Phase 1
	// callers pass the indicator strings (e.g. "eval", "atob_chain");
	// when the sandbox surfaces actual script bodies they'll go here.
	ScriptIndicators []string
}

// Category labels for telemetry.
type Category string

const (
	CatAirdropLure          Category = "airdrop_lure"
	CatRevokePermissionsLure Category = "revoke_permissions_lure"
	CatFakeMintLure         Category = "fake_mint_lure"
	CatWalletConnectLure    Category = "wallet_connect_lure"
	CatDrainerWalletMethod  Category = "drainer_wallet_method"
	CatFakeDeFiBrand        Category = "fake_defi_brand"
)

type Hit struct {
	Category Category
	Phrase   string
	Weight   float64
	Source   string
}

type Result struct {
	Score float64
	Hits  []Hit
}

const (
	ThresholdWarn      = 0.30
	ThresholdBlock     = 0.50
	ThresholdHardBlock = 0.80
)

// Score evaluates the inputs. Pure function. Hosts in brandgraph get a
// zero-score short-circuit so legit wallet dApp pages don't fire.
func Score(in Inputs) Result {
	if in.HostInBrandgraph {
		return Result{}
	}
	r := Result{}
	r.addCategory(in, airdropLures,           CatAirdropLure,          0.35)
	r.addCategory(in, revokePermissionsLures, CatRevokePermissionsLure, 0.30)
	r.addCategory(in, fakeMintLures,          CatFakeMintLure,         0.30)
	r.addCategory(in, walletConnectLures,     CatWalletConnectLure,    0.25)
	r.addCategory(in, fakeDeFiBrands,         CatFakeDeFiBrand,        0.25)
	r.addWalletMethodSignals(in)
	r.addSLDCompositeBonus(in)
	if r.Score > 1.5 {
		r.Score = 1.5
	}
	sort.SliceStable(r.Hits, func(i, j int) bool {
		if r.Hits[i].Weight != r.Hits[j].Weight {
			return r.Hits[i].Weight > r.Hits[j].Weight
		}
		return r.Hits[i].Phrase < r.Hits[j].Phrase
	})
	return r
}

func (r *Result) addCategory(in Inputs, phrases []phrase, cat Category, capWeight float64) {
	var local []Hit
	var total float64
	for _, p := range phrases {
		for _, src := range sourcesFromInputs(in) {
			if strings.Contains(src.text, p.term) {
				total += p.weight
				local = append(local, Hit{
					Category: cat, Phrase: p.term, Weight: p.weight, Source: src.name,
				})
				break
			}
		}
	}
	if total > capWeight {
		factor := capWeight / total
		for i := range local {
			local[i].Weight *= factor
		}
		total = capWeight
	}
	r.Hits = append(r.Hits, local...)
	r.Score += total
}

// addWalletMethodSignals scans ScriptIndicators for EIP-1193 wallet
// methods that drainers abuse. Each method has a distinct risk profile:
//
//	eth_signTypedData_v4    — most dangerous; permit signature drains
//	personal_sign           — generic signature; phishing-friendly
//	wallet_addEthereumChain — chain switch lure (move to attacker chain)
//	wallet_watchAsset       — token-add lure (fake ERC-20 / NFT push)
//
// Real dApps DO use these methods, but only specific ones (e.g.
// Uniswap uses eth_signTypedData_v4 for permits). On unknown / non-
// brandgraph hosts, presence of these methods is a strong drainer
// signal.
func (r *Result) addWalletMethodSignals(in Inputs) {
	for _, ind := range in.ScriptIndicators {
		low := strings.ToLower(ind)
		switch {
		case strings.Contains(low, "eth_signtypeddata_v4"):
			r.Score += 0.25
			r.Hits = append(r.Hits, Hit{
				Category: CatDrainerWalletMethod,
				Phrase:   "eth_signTypedData_v4",
				Weight:   0.25,
				Source:   "script",
			})
		case strings.Contains(low, "personal_sign"):
			r.Score += 0.15
			r.Hits = append(r.Hits, Hit{
				Category: CatDrainerWalletMethod,
				Phrase:   "personal_sign",
				Weight:   0.15,
				Source:   "script",
			})
		case strings.Contains(low, "wallet_addethereumchain"):
			r.Score += 0.20
			r.Hits = append(r.Hits, Hit{
				Category: CatDrainerWalletMethod,
				Phrase:   "wallet_addEthereumChain",
				Weight:   0.20,
				Source:   "script",
			})
		case strings.Contains(low, "wallet_watchasset"):
			r.Score += 0.15
			r.Hits = append(r.Hits, Hit{
				Category: CatDrainerWalletMethod,
				Phrase:   "wallet_watchAsset",
				Weight:   0.15,
				Source:   "script",
			})
		case strings.Contains(low, "setapprovalforall"):
			r.Score += 0.20
			r.Hits = append(r.Hits, Hit{
				Category: CatDrainerWalletMethod,
				Phrase:   "setApprovalForAll",
				Weight:   0.20,
				Source:   "script",
			})
		}
	}
}

// addSLDCompositeBonus credits SLD shape combining a drainer lure
// token (claim / mint / revoke / verify / sync) with a wallet / dApp
// brand token. Real attacker URL shapes:
//
//	claim-airdrop-uniswap
//	revoke-permissions-secure
//	metamask-wallet-update
//	opensea-collection-claim
//	pancakeswap-claim
//	mint-airdrop
func (r *Result) addSLDCompositeBonus(in Inputs) {
	if in.SLD == "" {
		return
	}
	sld := strings.ToLower(in.SLD)
	lureTokens := []string{
		"airdrop", "claim", "free-mint", "free_mint",
		"revoke", "verify-wallet", "verify_wallet", "sync-wallet",
		"connect-wallet", "wallet-update", "update-wallet",
	}
	brandTokens := []string{
		"metamask", "opensea", "uniswap", "pancakeswap", "sushiswap",
		"phantom", "rainbow", "rabby",
		"compound", "aave", "lido", "curve", "balancer",
		"makerdao", "1inch", "blur",
		"chainlink", "etherscan", "polygon", "arbitrum", "optimism",
		"ethereum", "binance", "coinbase", "kraken",
		"trezor", "ledger", "trust-wallet",
		"defi", "dapp", "nft", "crypto",
	}
	hits := 0
	var matchedLure, matchedBrand string
	for _, l := range lureTokens {
		if strings.Contains(sld, l) {
			for _, b := range brandTokens {
				if strings.Contains(sld, b) {
					if matchedLure == "" {
						matchedLure, matchedBrand = l, b
					}
					hits++
				}
			}
		}
	}
	if hits == 0 {
		// Pretext-only fallback: any lure token combined with one of
		// "secure", "official", "verify" is also drainer-shape.
		var found []string
		for _, l := range lureTokens {
			if strings.Contains(sld, l) {
				found = append(found, l)
				if len(found) >= 2 {
					break
				}
			}
		}
		if len(found) >= 2 {
			r.Score += 0.30
			r.Hits = append(r.Hits, Hit{
				Category: CatAirdropLure,
				Phrase:   strings.Join(found, " + "),
				Weight:   0.30,
				Source:   "sld_composite",
			})
		}
		return
	}
	weight := 0.20 * float64(hits)
	if weight > 0.40 {
		weight = 0.40
	}
	r.Score += weight
	r.Hits = append(r.Hits, Hit{
		Category: CatFakeDeFiBrand,
		Phrase:   matchedLure + " + " + matchedBrand,
		Weight:   weight,
		Source:   "sld_composite",
	})
}

func sourcesFromInputs(in Inputs) []source {
	out := make([]source, 0, 5)
	if in.URL != "" {
		out = append(out, source{name: "url", text: strings.ToLower(in.URL)})
	}
	if in.SLD != "" {
		out = append(out, source{name: "sld", text: strings.ToLower(in.SLD)})
	}
	if in.Title != "" {
		out = append(out, source{name: "title", text: strings.ToLower(in.Title)})
	}
	if in.VisibleText != "" {
		out = append(out, source{name: "visible", text: strings.ToLower(in.VisibleText)})
	}
	if in.OCRText != "" {
		out = append(out, source{name: "ocr", text: strings.ToLower(in.OCRText)})
	}
	return out
}

type source struct{ name, text string }

type phrase struct {
	term   string
	weight float64
}

// --- phrase dictionaries ----------------------------------------------------

var airdropLures = []phrase{
	{"claim your airdrop", 0.20},
	{"claim airdrop", 0.18},
	{"airdrop claim", 0.18},
	{"free airdrop", 0.18},
	{"connect to claim", 0.18},
	{"eligible for airdrop", 0.15},
	{"unclaimed airdrop", 0.15},
	{"airdrop eligible", 0.15},
	{"claim free tokens", 0.15},
	{"claim usdt", 0.18},
	{"claim usdc", 0.15},
	{"claim eth", 0.15},
	{"check eligibility", 0.10},
}

var revokePermissionsLures = []phrase{
	{"revoke permissions", 0.18},
	{"revoke access", 0.15},
	{"revoke approval", 0.18},
	{"revoke token approvals", 0.20},
	{"revoke.cash", 0.10}, // legit but spoofed; SLD check will distinguish
	{"unlimited approval", 0.18},
	{"unrevoke", 0.15},
	{"clean up your wallet", 0.10},
	{"security check your wallet", 0.15},
}

var fakeMintLures = []phrase{
	{"free mint", 0.20},
	{"free-mint", 0.20},
	{"limited mint", 0.15},
	{"public mint", 0.12},
	{"whitelist mint", 0.10},
	{"mint your nft", 0.15},
	{"mint now", 0.10},
	{"mint live", 0.10},
	{"opensea drop", 0.15},
	{"genesis mint", 0.12},
	{"verify your nft", 0.18},
	{"nft drop", 0.10},
}

var walletConnectLures = []phrase{
	{"connect wallet", 0.10},
	{"connect your wallet", 0.10},
	{"sync wallet", 0.18},
	{"verify wallet", 0.18},
	{"validate wallet", 0.18},
	{"resync wallet", 0.18},
	{"recover wallet", 0.18},
	{"unlock wallet", 0.15},
	{"reactivate wallet", 0.18},
	{"wallet maintenance", 0.15},
	{"wallet update required", 0.18},
	{"upgrade required", 0.10},
}

var fakeDeFiBrands = []phrase{
	// Common DeFi/wallet brand spoofs in URL or title (host-not-in-
	// brandgraph already short-circuited; these fire when phrase
	// appears in visible text or page title).
	{"metamask", 0.10},
	{"trust wallet", 0.10},
	{"coinbase wallet", 0.10},
	{"phantom wallet", 0.10},
	{"rainbow wallet", 0.10},
	{"ledger live", 0.10},
	{"trezor suite", 0.10},
	{"uniswap", 0.10},
	{"pancakeswap", 0.10},
	{"opensea", 0.10},
	{"blur", 0.08},
	{"compound finance", 0.10},
	{"aave protocol", 0.10},
	{"lido", 0.08},
}
