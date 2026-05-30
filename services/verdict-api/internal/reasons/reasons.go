// Package reasons defines the codified verdict-reason taxonomy.
//
// Every BLOCK, WARN, and ISOLATE must attach one or more reasons. The portal
// and the extension's blocked/warn/isolate interstitials render the human
// template; analytics splits true-positive metrics from friction metrics by
// looking at the code. See docs/UNIFIED-PLAN.md §5.4.
//
// Adding a new reason: append a `Code` constant, register its template in
// `templates`, and (if appropriate) add it to the analytics-relevant sets at
// the bottom of this file.
package reasons

// Code is the stable wire identifier. Never rename — analytics depend on it.
type Code string

const (
	// Detection-driven blocks: a real malicious signal.
	KnownPhishURLMatch                Code = "KNOWN_PHISH_URL_MATCH"
	KnownMalwareDomainMatch           Code = "KNOWN_MALWARE_DOMAIN_MATCH"
	BrandClaimDomainMismatch          Code = "BRAND_CLAIM_DOMAIN_MISMATCH" // legacy aggregate; prefer the orthogonal codes below
	FaviconBrandMismatch              Code = "FAVICON_BRAND_MISMATCH"
	TitleFaviconBrandImpersonation    Code = "TITLE_FAVICON_BRAND_IMPERSONATION"
	LoginFormOnUnapprovedDomain       Code = "LOGIN_FORM_ON_UNAPPROVED_DOMAIN"
	FormPostsToUnrelatedDomain        Code = "FORM_POSTS_TO_UNRELATED_DOMAIN"
	SuspiciousRedirectChain           Code = "SUSPICIOUS_REDIRECT_CHAIN"
	HomoglyphOfProtectedBrand         Code = "HOMOGLYPH_OF_PROTECTED_BRAND"
	DomainAgeUnderThreshold           Code = "DOMAIN_AGE_UNDER_THRESHOLD"
	CertDriftOnTrustedPage            Code = "CERT_DRIFT_ON_TRUSTED_PAGE"
	ScriptOriginDriftOnTrustedPage    Code = "SCRIPT_ORIGIN_DRIFT_ON_TRUSTED_PAGE"
	FormActionDriftOnTrustedPage      Code = "FORM_ACTION_DRIFT_ON_TRUSTED_PAGE"
	MaliciousDownloadTrigger          Code = "MALICIOUS_DOWNLOAD_TRIGGER"
	RiskyDownloadLinked               Code = "RISKY_DOWNLOAD_LINKED"
	RawIPHost                         Code = "RAW_IP_HOST"
	RandomHostname                    Code = "RANDOM_HOSTNAME"
	FreshDomain                       Code = "FRESH_DOMAIN"
	VendorDNSConsensusBlock           Code = "VENDOR_DNS_CONSENSUS_BLOCK"
	VendorDNSSingleHit                Code = "VENDOR_DNS_SINGLE_HIT"
	UltraNotCleared                   Code = "ULTRA_NOT_CLEARED"
	UltraCleared                      Code = "ULTRA_CLEARED"
	MalwareRawIPBinaryDrop            Code = "MALWARE_RAW_IP_BINARY_DROP"
	// Shell-command IOCs found in docs-style pages (Straiker "Fake Claude
	// Code" 2026-05-27 attack class). The page itself is the weapon — text
	// in a <pre> block that user copy-pastes into a terminal.
	MaliciousInstallCommand           Code = "MALICIOUS_INSTALL_COMMAND"
	SuspiciousInstallCommand          Code = "SUSPICIOUS_INSTALL_COMMAND"
	OfficialInstallMatch              Code = "OFFICIAL_INSTALL_MATCH"

	// --- New orthogonal taxonomy per the four-question model (dev spec) ---
	// Each maps to a specific stage failure in the policy engine.
	//
	// Stage B: Replica Engine
	VisualReplicaHigh                 Code = "VISUAL_REPLICA_HIGH"
	// Stage C: Identity Binding — three explicit subtypes, never lumped
	IdentityMismatchDomain            Code = "IDENTITY_MISMATCH_DOMAIN"
	IdentityMismatchASN               Code = "IDENTITY_MISMATCH_ASN"
	IdentityMismatchCert              Code = "IDENTITY_MISMATCH_CERT"
	IdentityMismatchScriptOrigin      Code = "IDENTITY_MISMATCH_SCRIPT_ORIGIN"
	// Stage D: Credential Sink Trust
	CredentialSinkCrossOrigin         Code = "CREDENTIAL_SINK_CROSS_ORIGIN"
	CredentialSinkUntrustedEndpoint   Code = "CREDENTIAL_SINK_UNTRUSTED_ENDPOINT"
	CredentialSinkPreSubmitCapture    Code = "CREDENTIAL_SINK_PRE_SUBMIT_CAPTURE"
	CredentialSinkMultiDestination    Code = "CREDENTIAL_SINK_MULTI_DESTINATION"
	CredentialSinkHiddenMirror        Code = "CREDENTIAL_SINK_HIDDEN_MIRROR"
	// Stage E: Anti-Cloaking
	// (CloakingDivergence already exists below, keep it)
	// Stage F: Path-level reputation
	PathDriftOnTrustedDomain          Code = "PATH_DRIFT_ON_TRUSTED_DOMAIN"
	// Stage F: OAuth (orthogonal name vs the legacy one below)
	OAuthUnverifiedHighScopeApp       Code = "OAUTH_UNVERIFIED_HIGH_SCOPE_APP"
	// Failure modes
	SensitivePageVerificationUnavailable Code = "SENSITIVE_PAGE_VERIFICATION_UNAVAILABLE"

	// Behavioral abuse (Phase 2 §5.2).
	PopupStormDetected                Code = "POPUP_STORM_DETECTED"
	AlertLoopDetected                 Code = "ALERT_LOOP_DETECTED"
	FullscreenTrapDetected            Code = "FULLSCREEN_TRAP_DETECTED"
	BeforeUnloadAbuse                 Code = "BEFOREUNLOAD_ABUSE"
	ClipboardHijackAttempt            Code = "CLIPBOARD_HIJACK_ATTEMPT"
	AutoDownloadTrigger               Code = "AUTO_DOWNLOAD_TRIGGER"
	FakeSupportScareware              Code = "FAKE_SUPPORT_SCAREWARE"

	// Popup lineage (§3).
	BlockedOpenerLineage              Code = "BLOCKED_OPENER_LINEAGE"
	UnknownTargetFromSuspiciousOpener Code = "UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER"

	// External corroborators.
	ExternalFeedHit                   Code = "EXTERNAL_FEED_HIT"
	GoogleWebRiskUnsafe               Code = "GOOGLE_WEB_RISK_UNSAFE"
	VirusTotalPositive                Code = "VIRUSTOTAL_POSITIVE"

	// Policy-driven (NOT detection — never inflate true-positive metrics).
	BlockedByStrictnessPolicy         Code = "BLOCKED_BY_STRICTNESS_POLICY" // Executive Mode
	BlockedByTenantOverride           Code = "BLOCKED_BY_TENANT_OVERRIDE"
	AllowedByTenantOverride           Code = "ALLOWED_BY_TENANT_OVERRIDE"
	IsolatedSensitivePageClass        Code = "ISOLATED_SENSITIVE_PAGE_CLASS"

	// Phase 6: deep DOM evidence from sandbox-render's DOM inventory.
	HiddenMaliciousLink               Code = "HIDDEN_MALICIOUS_LINK"
	SuspiciousDownloadOffered         Code = "SUSPICIOUS_DOWNLOAD_OFFERED"
	ObfuscatedJSDetected              Code = "OBFUSCATED_JS_DETECTED"
	HiddenIframeCrossOrigin           Code = "HIDDEN_IFRAME_CROSS_ORIGIN"
	OverlayClickjack                  Code = "OVERLAY_CLICKJACK"
	LinkedPageBlocked                 Code = "LINKED_PAGE_BLOCKED"
	LinkedPageIsolated                Code = "LINKED_PAGE_ISOLATED"

	// Reserved for future detectors (templates registered so portal does not 404).
	YaraSignatureMatch                Code = "YARA_SIGNATURE_MATCH"
	SubdomainTakeoverRisk             Code = "SUBDOMAIN_TAKEOVER_RISK"
	CloakingDivergence                Code = "CLOAKING_DIVERGENCE"
	OAuthUnknownClientID              Code = "OAUTH_UNKNOWN_CLIENT_ID"
	HTMLSmugglingPattern              Code = "HTML_SMUGGLING_PATTERN"
	DGAClassifierHit                  Code = "DGA_CLASSIFIER_HIT"
	MinerPoolContact                  Code = "MINER_POOL_CONTACT"

	// Phase B: connection identity codes. Emitted by internal/connid when
	// the browser's actual remote IP is compared against the XGG resolver
	// ledger, CDN/ASN expectations, and TLS identity.
	UserDNSPathMatch              Code = "USER_DNS_PATH_MATCH"
	UserDNSPathMismatch           Code = "USER_DNS_PATH_MISMATCH"
	CDNASNMatch                   Code = "CDN_ASN_MATCH"
	CDNASNMismatch                Code = "CDN_ASN_MISMATCH"
	PublicDomainPrivateIP         Code = "PUBLIC_DOMAIN_PRIVATE_IP"
	TLSIdentityMismatch           Code = "TLS_IDENTITY_MISMATCH"
	ExpectedResolverBypassed      Code = "EXPECTED_RESOLVER_BYPASSED"
	LocalResolverHijackSuspected  Code = "LOCAL_RESOLVER_HIJACK_SUSPECTED"

	// Phase E — soft DNS divergence. The browser's observed connection IP
	// for this domain disagrees with the resolver ledger's answer set, but
	// the IP is publicly routable (not the hard PUBLIC_DOMAIN_PRIVATE_IP
	// case). Common on multi-CDN sites and split-horizon DNS, so this is
	// advisory/scored — suppressed on highly-trusted hosts.
	DNSDivergenceSoft             Code = "DNS_DIVERGENCE_SOFT"

	// Health-gate / degraded-mode. The engine asked for Tier-2 sandbox
	// evidence on this URL but the sandbox call failed, timed out, or
	// the service was unavailable. This is "missing proof," not "clean."
	// On sensitive page classes (login/payment/oauth/install) the
	// decision kernel escalates to ISOLATE rather than silently
	// ALLOW-ing without the evidence that would normally fire the
	// page-content rules. Closes the silent-fake-safety bug class.
	Tier2DataUnavailable          Code = "TIER2_DATA_UNAVAILABLE"

	// Support-scam / fake-helpdesk scorer (Wave 3 Phase 1).
	// Emitted by internal/supportscam when the per-category score
	// crosses ThresholdWarn / ThresholdBlock. Sources today: URL +
	// SLD + page title. Phase 2 adds visible DOM text; Phase 3 adds
	// OCR. Pairs FTC/FBI/Microsoft scam guidance into one signal.
	SupportScamLanguage           Code = "SUPPORT_SCAM_LANGUAGE"
	FakeSecurityWarning           Code = "FAKE_SECURITY_WARNING"
	RemoteToolLure                Code = "REMOTE_TOOL_LURE"
	GiftCardPaymentDemand         Code = "GIFT_CARD_PAYMENT_DEMAND"
	FakeTechSupportBrand          Code = "FAKE_TECH_SUPPORT_BRAND"
	GovImpersonation              Code = "GOV_IMPERSONATION"
)

// Template is the human-readable form rendered in interstitials and the portal.
// %s in templates is replaced with details from the Signal.
type Template struct {
	Title    string
	Body     string
	Severity Severity // affects how the interstitial styles itself
}

type Severity int

const (
	SeverityLow      Severity = iota // informational
	SeverityMedium                   // warn-worthy
	SeverityHigh                     // typical block
	SeverityCritical                 // confirmed malicious
)

var templates = map[Code]Template{
	KnownPhishURLMatch: {
		Title: "Confirmed phishing URL",
		Body:  "This exact URL is on a threat-intelligence feed of confirmed phishing pages.",
		Severity: SeverityCritical,
	},
	KnownMalwareDomainMatch: {
		Title: "Confirmed malware domain",
		Body:  "This domain is on a threat-intelligence feed of confirmed malware-distribution hosts.",
		Severity: SeverityCritical,
	},
	BrandClaimDomainMismatch: {
		Title: "Page impersonates %s",
		Body:  "The page visually matches %s but the domain is not owned by %s.",
		Severity: SeverityCritical,
	},
	FaviconBrandMismatch: {
		Title: "Favicon impersonates %s",
		Body:  "The page favicon matches %s on a domain not owned by %s.",
		Severity: SeverityHigh,
	},
	TitleFaviconBrandImpersonation: {
		Title: "Brand impersonation by title + favicon",
		Body:  "Both the page title and favicon imitate %s on a non-canonical domain.",
		Severity: SeverityHigh,
	},
	LoginFormOnUnapprovedDomain: {
		Title: "Login form on unverified domain",
		Body:  "This page collects credentials but is not on an approved domain for the brand it claims.",
		Severity: SeverityHigh,
	},
	FormPostsToUnrelatedDomain: {
		Title: "Credentials posted to a third-party domain",
		Body:  "The password form on this page submits to %s, which is unrelated to the page's own domain.",
		Severity: SeverityHigh,
	},
	SuspiciousRedirectChain: {
		Title: "Suspicious redirect chain",
		Body:  "This URL redirected through %d hops before reaching its destination.",
		Severity: SeverityMedium,
	},
	HomoglyphOfProtectedBrand: {
		Title: "Lookalike domain",
		Body:  "This domain visually imitates %s using character substitution.",
		Severity: SeverityHigh,
	},
	DomainAgeUnderThreshold: {
		Title: "Domain registered recently",
		Body:  "This domain was registered %s ago. New domains are often used for one-shot phishing.",
		Severity: SeverityMedium,
	},
	CertDriftOnTrustedPage: {
		Title: "Certificate changed unexpectedly",
		Body:  "The TLS certificate for this page changed since the last successful scan.",
		Severity: SeverityMedium,
	},
	ScriptOriginDriftOnTrustedPage: {
		Title: "Script sources changed",
		Body:  "This previously-trusted page now loads scripts from origins it did not use before.",
		Severity: SeverityMedium,
	},
	FormActionDriftOnTrustedPage: {
		Title: "Form target changed",
		Body:  "The form on this page now submits to a different endpoint than it did before.",
		Severity: SeverityMedium,
	},
	MaliciousDownloadTrigger: {
		Title: "Malicious download detected",
		Body:  "This page attempted to start a download that matches known-malicious indicators.",
		Severity: SeverityCritical,
	},
	RiskyDownloadLinked: {
		Title: "Risky download linked",
		Body:  "This page links to %d executable or archive download(s) that could not be verified safe.",
		Severity: SeverityMedium,
	},
	RawIPHost: {
		Title: "URL points at a raw IP address",
		Body:  "Legitimate websites use domain names, not raw IPs. This URL hits an IP directly.",
		Severity: SeverityMedium,
	},
	RandomHostname: {
		Title: "Hostname looks randomly generated",
		Body:  "The hostname has low vowel ratio, long consonant runs, and/or no repeating bigrams — patterns typical of phishing kits and short-lived attack infrastructure.",
		Severity: SeverityMedium,
	},
	FreshDomain: {
		Title: "Domain was registered recently",
		Body:  "This domain was registered in the last few weeks. Real phishing campaigns burn through fresh, just-registered domains; legitimate sites with sensitive flows almost always have established registration history.",
		Severity: SeverityHigh,
	},
	VendorDNSConsensusBlock: {
		Title: "Multiple security DNS providers block this domain",
		Body:  "Independent protective-DNS providers (Cloudflare, Quad9, AdGuard, OpenDNS, CleanBrowsing) maintain separate threat lists. When two or more agree to block a domain, it is near-certainly malicious — multiple security teams have independently confirmed the threat.",
		Severity: SeverityCritical,
	},
	VendorDNSSingleHit: {
		Title: "One security DNS provider blocks this domain",
		Body:  "A single protective-DNS provider has this domain on their blocklist. Treating as advisory until corroborated by another signal.",
		Severity: SeverityMedium,
	},
	UltraNotCleared: {
		Title: "Ultra mode: page not fully cleared",
		Body:  "Ultra mode requires every verification gate to affirmatively pass before allowing a page. This page failed or could not verify one or more gates — opening in isolation as a precaution. See the verification checklist above to see which gates didn't pass.",
		Severity: SeverityMedium,
	},
	UltraCleared: {
		Title: "Ultra mode: page passed full clearance",
		Body:  "Every verification gate affirmatively passed. Page allowed normally.",
		Severity: SeverityLow,
	},
	MalwareRawIPBinaryDrop: {
		Title: "Suspected botnet binary drop",
		Body:  "URL points at a raw IP and the path looks like an architecture-specific binary (Mirai-style malware pattern).",
		Severity: SeverityCritical,
	},
	MaliciousInstallCommand: {
		Title: "Page hides a malicious install command",
		Body:  "This page displays a shell command containing a known-malicious pattern (rundll32 over UNC, mshta + remote HTA, PowerShell IEX cradle, or similar).",
		Severity: SeverityCritical,
	},
	SuspiciousInstallCommand: {
		Title: "Page shows a suspicious install command",
		Body:  "This page displays a shell command with multiple red flags commonly used by malware-staging chains (e.g. base64-piped-to-shell, bare '&' separator, raw GitHub installer).",
		Severity: SeverityHigh,
	},
	OfficialInstallMatch: {
		Title: "Recognized official install command",
		Body:  "This page is on a registered vendor host and publishes a command that exactly matches the vendor's canonical install template.",
		Severity: SeverityLow,
	},
	PopupStormDetected: {
		Title: "Popup storm",
		Body:  "This page tried to open multiple windows or tabs without user interaction.",
		Severity: SeverityHigh,
	},
	AlertLoopDetected: {
		Title: "Modal-dialog loop",
		Body:  "This page repeatedly triggers alert or confirm dialogs to trap the user.",
		Severity: SeverityHigh,
	},
	FullscreenTrapDetected: {
		Title: "Fullscreen trap",
		Body:  "This page forced fullscreen without a user gesture — a common scareware pattern.",
		Severity: SeverityHigh,
	},
	BeforeUnloadAbuse: {
		Title: "beforeunload trap",
		Body:  "This page blocks navigation away from itself, a common scam pattern.",
		Severity: SeverityMedium,
	},
	ClipboardHijackAttempt: {
		Title: "Clipboard tampering",
		Body:  "This page wrote to the user's clipboard without consent, a common ClickFix pattern.",
		Severity: SeverityHigh,
	},
	AutoDownloadTrigger: {
		Title: "Drive-by download",
		Body:  "This page started a download with no user click.",
		Severity: SeverityHigh,
	},
	FakeSupportScareware: {
		Title: "Fake tech-support page",
		Body:  "This page shows multiple scareware patterns: popups, alerts, fullscreen, fake virus warnings.",
		Severity: SeverityCritical,
	},
	BlockedOpenerLineage: {
		Title: "Opened by a blocked page",
		Body:  "The page that tried to open this URL has already been blocked by XGenGuardian.",
		Severity: SeverityHigh,
	},
	UnknownTargetFromSuspiciousOpener: {
		Title: "Unknown target from suspicious page",
		Body:  "A suspicious page tried to open this never-before-seen URL. Opened in isolation for safety.",
		Severity: SeverityMedium,
	},
	ExternalFeedHit: {
		Title: "External threat-intelligence hit",
		Body:  "External feed %s flags this URL or domain.",
		Severity: SeverityHigh,
	},
	GoogleWebRiskUnsafe: {
		Title: "Google Web Risk: unsafe",
		Body:  "Google Web Risk reports this URL as unsafe.",
		Severity: SeverityHigh,
	},
	VirusTotalPositive: {
		Title: "VirusTotal detections",
		Body:  "%d antivirus engines on VirusTotal flag this URL or file.",
		Severity: SeverityHigh,
	},
	BlockedByStrictnessPolicy: {
		Title: "Blocked by Executive Mode",
		Body:  "This URL did not meet your Executive Mode trust threshold (grade %s).",
		Severity: SeverityLow,
	},
	BlockedByTenantOverride: {
		Title: "Blocked by organization policy",
		Body:  "Your organization has explicitly blocked this URL or domain.",
		Severity: SeverityLow,
	},
	AllowedByTenantOverride: {
		Title: "Allowed by organization policy",
		Body:  "Your organization has explicitly allowed this URL or domain.",
		Severity: SeverityLow,
	},
	IsolatedSensitivePageClass: {
		Title: "Sensitive page opened in isolation",
		Body:  "Login, payment, and OAuth pages on unverified domains are opened in isolation by default.",
		Severity: SeverityLow,
	},
	YaraSignatureMatch: {
		Title: "YARA signature match: %s",
		Body:  "The page or downloaded file matches the %s signature.",
		Severity: SeverityHigh,
	},
	SubdomainTakeoverRisk: {
		Title: "Possible subdomain takeover",
		Body:  "This subdomain's CNAME target appears to be unclaimed and may be hijacked.",
		Severity: SeverityHigh,
	},
	CloakingDivergence: {
		Title: "Server-side cloaking",
		Body:  "The page serves different content to different network locations — a cloaking pattern.",
		Severity: SeverityHigh,
	},
	OAuthUnknownClientID: {
		Title: "Unknown OAuth application",
		Body:  "This OAuth consent screen requests sensitive permissions for an unknown application.",
		Severity: SeverityHigh,
	},
	HTMLSmugglingPattern: {
		Title: "HTML smuggling",
		Body:  "This page reassembles a downloadable payload entirely client-side, an evasion pattern.",
		Severity: SeverityHigh,
	},
	DGAClassifierHit: {
		Title: "Algorithmically-generated domain",
		Body:  "This domain matches the pattern of malware command-and-control domain generation.",
		Severity: SeverityMedium,
	},
	MinerPoolContact: {
		Title: "Cryptocurrency miner",
		Body:  "This page contacts a known cryptocurrency-mining pool.",
		Severity: SeverityMedium,
	},

	// --- New orthogonal taxonomy ---
	VisualReplicaHigh: {
		Title:    "Page visually replicates %s",
		Body:     "The page is a near-pixel-perfect replica of %s's %s flow. Visual similarity alone is not malicious — the verdict also depends on whether the page is hosted on %s's real infrastructure and whether credentials would go to %s's real endpoints.",
		Severity: SeverityLow,
	},
	IdentityMismatchDomain: {
		Title:    "Domain is not owned by %s",
		Body:     "This domain is not in %s's published canonical-domain list.",
		Severity: SeverityHigh,
	},
	IdentityMismatchASN: {
		Title:    "Hosting ASN is not used by %s",
		Body:     "The hosting network (AS%d) is not one %s legitimately uses.",
		Severity: SeverityMedium,
	},
	IdentityMismatchCert: {
		Title:    "TLS certificate issuer is not used by %s",
		Body:     "The TLS issuer (%s) is not one %s legitimately uses.",
		Severity: SeverityMedium,
	},
	IdentityMismatchScriptOrigin: {
		Title:    "Page loads scripts from origins %s does not use",
		Body:     "Scripts on this page come from origins not in %s's published allow-list.",
		Severity: SeverityMedium,
	},
	CredentialSinkCrossOrigin: {
		Title:    "Credentials would be sent to a different domain",
		Body:     "Form, fetch, or beacon on this page sends credentials to %s, which is not the page's own origin.",
		Severity: SeverityCritical,
	},
	CredentialSinkUntrustedEndpoint: {
		Title:    "Credentials would be sent to an untrusted endpoint",
		Body:     "The endpoint %s is not on the brand's allowed form-action / API list.",
		Severity: SeverityCritical,
	},
	CredentialSinkPreSubmitCapture: {
		Title:    "Page captures input before submit",
		Body:     "A keystroke listener on the password or OTP field sends data to %s as you type — before you press Submit.",
		Severity: SeverityCritical,
	},
	CredentialSinkMultiDestination: {
		Title:    "Credentials would be sent to multiple destinations",
		Body:     "Submitting the form on this page would mirror your credentials to %d different endpoints.",
		Severity: SeverityHigh,
	},
	CredentialSinkHiddenMirror: {
		Title:    "Hidden form fields replicate your input",
		Body:     "The page contains hidden inputs that capture and forward your credentials separately from the visible form.",
		Severity: SeverityCritical,
	},
	PathDriftOnTrustedDomain: {
		Title:    "Previously-trusted site hosts an unexpected sensitive page",
		Body:     "This domain has been clean for a long time but this exact path is brand new and hosts a login/payment/OAuth flow that the rest of the site does not.",
		Severity: SeverityHigh,
	},
	OAuthUnverifiedHighScopeApp: {
		Title:    "Unverified app requesting sensitive permissions",
		Body:     "The OAuth application '%s' (client_id %s) is not a verified publisher and is requesting %s. Granting access would let it act with those permissions on your account.",
		Severity: SeverityHigh,
	},
	SensitivePageVerificationUnavailable: {
		Title:    "Could not verify a sensitive page",
		Body:     "This is a login, payment, or OAuth page and the verification service is unavailable. Opening it in isolation as a safety default.",
		Severity: SeverityLow,
	},

	// Phase 6: deep DOM evidence
	HiddenMaliciousLink: {
		Title:    "Hidden anchors linking off-page",
		Body:     "This page contains hidden anchors (display:none, off-screen, or 1px overlay) pointing to external destinations — a common cloaking technique used to hide malicious redirects.",
		Severity: SeverityMedium,
	},
	SuspiciousDownloadOffered: {
		Title:    "Suspicious download offered",
		Body:     "This page links to an executable, installer, or archive download. On a sensitive page (login/payment/OAuth) this is a high-risk pattern.",
		Severity: SeverityHigh,
	},
	ObfuscatedJSDetected: {
		Title:    "Obfuscated JavaScript detected",
		Body:     "This page contains JavaScript with multiple obfuscation indicators (eval, atob chains, high-entropy strings). Obfuscated code is used to hide malicious behaviour from security scanners.",
		Severity: SeverityMedium,
	},
	HiddenIframeCrossOrigin: {
		Title:    "Hidden cross-origin iframe",
		Body:     "This page embeds a hidden iframe from a different origin. Hidden cross-origin iframes are used to silently load malicious content, exfiltrate data, or stage credential theft.",
		Severity: SeverityMedium,
	},
	DNSDivergenceSoft: {
		Title:    "DNS answers disagree across paths",
		Body:     "The IP the browser connected to does not match the answer set our protective resolver saw for this domain. On most sites this is harmless multi-CDN behaviour, but on an untrusted, unknown host it can indicate split-resolver tampering.",
		Severity: SeverityLow,
	},
	Tier2DataUnavailable: {
		Title:    "Deep-scan unavailable",
		Body:     "The page-content sandbox was unavailable when this URL was checked, so the engine could not verify the page DOM, forms, or scripts. On sensitive pages this is treated as missing proof, not as a clean signal.",
		Severity: SeverityMedium,
	},
	SupportScamLanguage: {
		Title:    "Tech-support scam patterns detected",
		Body:     "This URL or page contains language consistent with fake-helpdesk scams (FTC/FBI/Microsoft pattern). Real support never calls you unexpectedly, demands payment in gift cards, or asks you to install remote-access tools.",
		Severity: SeverityHigh,
	},
	FakeSecurityWarning: {
		Title:    "Fake security warning",
		Body:     "The page imitates a security alert (\"your computer is infected\", \"virus detected\") on an unrelated host. Real Microsoft / Apple / Norton / McAfee warnings never instruct you to call a phone number from a webpage.",
		Severity: SeverityHigh,
	},
	RemoteToolLure: {
		Title:    "Remote-access tool installation requested",
		Body:     "The page asks you to install AnyDesk / TeamViewer / Quick Assist / RustDesk / similar remote-access software. This is the first step in the FBI Phantom Hacker pattern — once the attacker connects, your data is at risk.",
		Severity: SeverityCritical,
	},
	GiftCardPaymentDemand: {
		Title:    "Gift-card or wire-payment demand",
		Body:     "The page demands payment via gift card, Western Union, MoneyGram, wire transfer, or cryptocurrency. FTC: legitimate businesses never ask for gift-card payment. This is a scam-only payment pattern.",
		Severity: SeverityCritical,
	},
	FakeTechSupportBrand: {
		Title:    "Impersonates a tech-support brand",
		Body:     "The page claims to be Microsoft / Apple / Norton / McAfee / Google support, but the hosting domain isn't owned by that brand. Real support pages live on the brand's own canonical domain.",
		Severity: SeverityHigh,
	},
	GovImpersonation: {
		Title:    "Impersonates a government agency",
		Body:     "The page references the IRS / SSA / Medicare / HMRC / similar government agency in a context consistent with a scam (refund claim, arrest warrant, unpaid taxes). Government agencies do not contact citizens by random webpage popup.",
		Severity: SeverityHigh,
	},
	OverlayClickjack: {
		Title:    "Clickjacking overlay detected",
		Body:     "This page has a full-viewport transparent overlay that captures clicks — a classic clickjacking pattern used to trick users into interacting with hidden elements.",
		Severity: SeverityHigh,
	},
	LinkedPageBlocked: {
		Title:    "Linked page is blocked",
		Body:     "A page linked from this URL returned a BLOCK verdict during deep-scan.",
		Severity: SeverityHigh,
	},
	LinkedPageIsolated: {
		Title:    "Linked page is isolated",
		Body:     "A page linked from this URL returned an ISOLATE verdict during deep-scan.",
		Severity: SeverityMedium,
	},

	UserDNSPathMatch: {
		Title:    "Browser DNS path matches XGenGuardian resolver",
		Body:     "The IP your browser connected to was one of the IPs the XGenGuardian resolver recently returned for this domain. The DNS path is consistent.",
		Severity: SeverityLow,
	},
	UserDNSPathMismatch: {
		Title:    "Browser DNS path diverges from XGenGuardian resolver",
		Body:     "Your browser reached an IP the XGenGuardian resolver did not recently return for this domain. This can happen with VPN DNS, browser DoH, captive portals, or local DNS hijack.",
		Severity: SeverityMedium,
	},
	CDNASNMatch: {
		Title:    "Browser remote ASN matches expected CDN",
		Body:     "The autonomous system serving this connection matches the known CDN/infrastructure set for this domain.",
		Severity: SeverityLow,
	},
	CDNASNMismatch: {
		Title:    "Browser remote ASN does not match expected infrastructure",
		Body:     "The autonomous system serving this connection is not among the expected ASNs for this domain. May indicate DNS hijack, MITM, or a malicious resolver.",
		Severity: SeverityHigh,
	},
	PublicDomainPrivateIP: {
		Title:    "Public domain resolved to a private IP",
		Body:     "This is a public domain but the browser connected to a private/loopback/link-local IP. This is a classic DNS rebinding / hosts-file hijack indicator and is treated as a hard block.",
		Severity: SeverityCritical,
	},
	TLSIdentityMismatch: {
		Title:    "TLS certificate identity does not match host",
		Body:     "The TLS certificate served on this connection is not valid for the requested host. The connection cannot be trusted for any sensitive action.",
		Severity: SeverityCritical,
	},
	ExpectedResolverBypassed: {
		Title:    "Expected resolver was bypassed",
		Body:     "The browser appears to have bypassed the XGenGuardian resolver (for example via browser DoH or a system VPN), so DNS-time protections did not apply to this connection.",
		Severity: SeverityMedium,
	},
	LocalResolverHijackSuspected: {
		Title:    "Local resolver hijack suspected",
		Body:     "The IP the browser reached, the XGenGuardian resolver answer, and the backend trusted resolvers disagree in a pattern consistent with local DNS hijack (router compromise, malicious ISP resolver, or hosts-file tampering).",
		Severity: SeverityHigh,
	},
}

// Render returns the template for a code, or a fallback for unknown codes.
// Callers substitute %s args themselves (we keep this package free of fmt to
// minimize binary bloat in resolver paths).
func Render(c Code) Template {
	if t, ok := templates[c]; ok {
		return t
	}
	return Template{
		Title:    string(c),
		Body:     "An unspecified risk signal triggered this decision.",
		Severity: SeverityMedium,
	}
}

// IsKnown returns true if the code has a registered template. Useful for
// CI checks that every emitted code is canonized.
func IsKnown(c Code) bool {
	_, ok := templates[c]
	return ok
}

// policyCodes are reasons that don't represent a real malicious signal. They
// must not inflate true-positive metrics in analytics or the eval harness.
var policyCodes = map[Code]struct{}{
	BlockedByStrictnessPolicy:  {},
	BlockedByTenantOverride:    {},
	AllowedByTenantOverride:    {},
	IsolatedSensitivePageClass: {},
}

// IsPolicy reports whether the code is policy-driven (vs. detection-driven).
// Dashboards should split these on every chart.
func IsPolicy(c Code) bool {
	_, ok := policyCodes[c]
	return ok
}

// All returns every registered code. Stable order not guaranteed.
func All() []Code {
	out := make([]Code, 0, len(templates))
	for c := range templates {
		out = append(out, c)
	}
	return out
}
