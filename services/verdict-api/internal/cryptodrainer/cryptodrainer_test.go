package cryptodrainer

import (
	"strings"
	"testing"
)

// --- Smoke-corpus failing case ---

func TestScore_SmokeCorpus_FakeOpenSea(t *testing.T) {
	// Smoke URL: opensea-collection-claim.example/mint
	r := Score(Inputs{
		URL: "https://opensea-collection-claim.example/mint",
		SLD: "opensea-collection-claim",
	})
	if r.Score < ThresholdWarn {
		t.Errorf("opensea-collection-claim SLD must WARN; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
	}
}

func TestScore_SmokeCorpus_ClaimAirdropUniswap(t *testing.T) {
	r := Score(Inputs{
		URL: "https://claim-airdrop-uniswap.example/wallet",
		SLD: "claim-airdrop-uniswap",
	})
	if r.Score < ThresholdWarn {
		t.Errorf("claim-airdrop-uniswap must WARN; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
	}
}

// --- Per-category baselines ---

func TestScore_AirdropLure(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Claim your airdrop now. Eligible for airdrop of 1000 tokens.",
	})
	if !hasCategory(r.Hits, CatAirdropLure) {
		t.Errorf("expected airdrop-lure hits")
	}
}

func TestScore_RevokePermissionsLure(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Revoke unlimited approval. Clean up your wallet permissions immediately.",
	})
	if !hasCategory(r.Hits, CatRevokePermissionsLure) {
		t.Errorf("expected revoke-lure hits")
	}
}

func TestScore_WalletConnectLure(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Connect your wallet to verify wallet update required for maintenance.",
	})
	if !hasCategory(r.Hits, CatWalletConnectLure) {
		t.Errorf("expected wallet-connect-lure hits")
	}
}

func TestScore_FakeMintLure(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Free mint live now. Mint your NFT to verify your NFT eligibility.",
	})
	if !hasCategory(r.Hits, CatFakeMintLure) {
		t.Errorf("expected fake-mint hits")
	}
}

// --- Wallet method signals from script indicators ---

func TestScore_WalletMethod_EthSignTypedData_V4(t *testing.T) {
	r := Score(Inputs{
		URL:              "https://drain.example/",
		ScriptIndicators: []string{"eth_signTypedData_v4"},
	})
	if !hasCategory(r.Hits, CatDrainerWalletMethod) {
		t.Errorf("expected drainer-wallet-method hit on eth_signTypedData_v4")
	}
	if r.Score < 0.25 {
		t.Errorf("eth_signTypedData_v4 should contribute >= 0.25; got %.3f", r.Score)
	}
}

func TestScore_WalletMethod_SetApprovalForAll(t *testing.T) {
	r := Score(Inputs{
		ScriptIndicators: []string{"setApprovalForAll"},
	})
	if !hasCategory(r.Hits, CatDrainerWalletMethod) {
		t.Errorf("expected hit on setApprovalForAll")
	}
}

// --- HostInBrandgraph escape ---

func TestScore_LegitDApp_HostInBrandgraph_Zero(t *testing.T) {
	r := Score(Inputs{
		URL:              "https://app.uniswap.org/swap",
		VisibleText:      "Connect your wallet to swap tokens. Approval required.",
		Host:             "app.uniswap.org",
		HostInBrandgraph: true,
	})
	if r.Score != 0 {
		t.Errorf("brandgraph-trusted dApp must score 0; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
	}
}

// --- SLD composite catches host-shape attackers ---

func TestScore_SLDComposite_BrandPlusLure(t *testing.T) {
	r := Score(Inputs{
		URL: "https://metamask-wallet-update.example/sync",
		SLD: "metamask-wallet-update",
	})
	if r.Score < ThresholdWarn {
		t.Errorf("metamask-wallet-update SLD composite must WARN; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
	}
}

func TestScore_SLDComposite_TwoLureTokens(t *testing.T) {
	r := Score(Inputs{
		URL: "https://claim-airdrop-verify.example/",
		SLD: "claim-airdrop-verify",
	})
	// "claim" + "airdrop" → two lure tokens; verify is not in
	// lureTokens. With current set: "claim" + "airdrop" present →
	// two-pretext fallback should fire.
	if r.Score < ThresholdWarn {
		t.Errorf("two-lure SLD must WARN; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
	}
}

// --- Composite scam crosses HardBlock ---

func TestScore_Composite_CrossesHardBlock(t *testing.T) {
	r := Score(Inputs{
		URL: "https://claim-airdrop-metamask.example/connect",
		SLD: "claim-airdrop-metamask",
		VisibleText: "Connect wallet to claim your airdrop. " +
			"Free mint live now. Sync wallet to verify your NFT. " +
			"Revoke unlimited approval to claim free tokens.",
		ScriptIndicators: []string{"eth_signTypedData_v4", "setApprovalForAll"},
	})
	if r.Score < ThresholdHardBlock {
		t.Errorf("composite drainer must cross HardBlock %.2f; got %.3f. Hits: %s",
			ThresholdHardBlock, r.Score, summarise(r.Hits))
	}
}

// --- Cap prevents single-category runaway ---

func TestScore_AirdropRepeated_Capped(t *testing.T) {
	r := Score(Inputs{
		VisibleText: strings.Repeat("Claim your airdrop. ", 50),
	})
	var cat float64
	for _, h := range r.Hits {
		if h.Category == CatAirdropLure {
			cat += h.Weight
		}
	}
	if cat > 0.35+1e-9 {
		t.Errorf("airdrop cap violated: got %.3f want <= 0.35", cat)
	}
}

// --- Benign content does NOT fire ---

func TestScore_BenignArticleAboutDrainers(t *testing.T) {
	// An article educating users about wallet drainers should NOT score.
	// Host is brandgraph-trusted (assumed news site).
	r := Score(Inputs{
		URL:   "https://example-blog.com/what-is-a-wallet-drainer",
		Title: "What is a wallet drainer?",
		VisibleText: "Wallet drainer scams trick users into connecting their wallet " +
			"and signing a malicious transaction. Read on to learn how to spot them.",
		Host:             "example-blog.com",
		HostInBrandgraph: true,
	})
	if r.Score != 0 {
		t.Errorf("benign article on brandgraph host must score 0; got %.3f", r.Score)
	}
}

// --- helpers ---

func hasCategory(hits []Hit, cat Category) bool {
	for _, h := range hits {
		if h.Category == cat {
			return true
		}
	}
	return false
}

func summarise(hits []Hit) string {
	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		parts = append(parts, string(h.Category)+":"+h.Phrase)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
