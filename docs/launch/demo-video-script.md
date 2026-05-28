# Demo Video — 90 Seconds

**Target length:** 90 seconds.
**Format:** screen recording with voiceover. No talking head. No music.
**Resolution:** 1920×1080 minimum; export 720p + 1080p.
**Captions:** burned-in, sans-serif, high-contrast.
**Hosted on:** YouTube (unlisted until launch), Vimeo backup, embedded on landing.

The single goal: show the moment where XGenGuardian catches a phishing site that Google Safe Browsing and VirusTotal both call clean.

---

## Storyboard

| Time | Visual | Voiceover |
|---|---|---|
| 0:00–0:05 | Black screen with text: "Modern phishing kits live 4 to 6 hours." | (silence — let the line land) |
| 0:05–0:10 | Same screen: "By the time the blocklists update, the victims are gone." | (silence) |
| 0:10–0:15 | Cut to PhishTank live submissions page; cursor copies a fresh URL. | "Here's a phishing site submitted to PhishTank 14 hours ago." |
| 0:15–0:22 | Browser tab; paste URL into report.xgenguardian.com. Hit Enter. Page shows "Analyzing this site for your safety… (3s)". | "I paste it into XGenGuardian." |
| 0:22–0:30 | Result lands: red BLOCK badge, 0.97 confidence. Side-by-side screenshots: real PayPal login vs. phishing page. | "It looks like PayPal. It isn't on PayPal's infrastructure. We blocked it." |
| 0:30–0:45 | Scroll to evidence section. Highlight each row in turn: "Domain age 14h", "TLS cert 6h", "Form posts to evil-collect.tk", "Visual similarity 0.96". | "Domain registered 14 hours ago. TLS cert issued 6 hours ago. The login form posts your credentials to a different domain entirely. Visual similarity to PayPal: 96 percent." |
| 0:45–0:55 | Click LLM explanation. Show a clean 3-sentence paragraph. | "Here's why, in plain English. Every block comes with this." |
| 0:55–1:10 | Cut to a new tab. Run a live API check against Google Safe Browsing for the same URL → "clean". VirusTotal → "0 / 70". Microsoft SmartScreen → "no detections". Each marked with a green check on the right side. | "Same URL right now. Google Safe Browsing: clean. VirusTotal: zero of seventy. SmartScreen: clean. They'll catch up — hours from now." |
| 1:10–1:20 | Back to xgenguardian.com landing. Cursor highlights the "Get started — free" button. | "One DNS setting. No client install. No TLS interception. Free." |
| 1:20–1:30 | Final card: logo + "XGenGuardian — The phishing your DNS missed. Caught." + URL. | "XGenGuardian dot com. Try it with your own URL." |

---

## Tone

- Calm, factual, no hype. The data carries the punch.
- Don't say "AI" once in the script. The visual+LLM result speaks for itself.
- Don't trash competitors by name in the voiceover. Show, don't slam.
- Pacing: no transition lasts longer than 0.3s. The audience will rewatch if they want.

## Recording Notes

- Use a fresh browser profile with cache cleared. Real network.
- Record in a region the sandbox has confirmed unmasked rendering for the chosen test URL.
- Have **3 backup phishing URLs** in case one is taken down between recording and editing.
- The PayPal screenshot in the side-by-side must be from the registry's stored canonical screenshot, not a fresh fetch (consistency).
- The GSB/VT/SmartScreen check is a tiny script in `tools/launch-demo/`; pre-record its terminal output if API latency varies.

## Editing Notes

- Frame rate 30fps; no motion smoothing.
- Cursor highlight color: #5e8bff (matches brand).
- Always show the URL bar; viewers will pause to verify.
- Final card stays on screen for at least 5 seconds.

## Distribution

- Embed on landing hero (autoplay muted, controls visible).
- YouTube upload: title "Catching a phishing site that Google Safe Browsing missed (XGenGuardian demo)". Tags: phishing, dns, security, opensource.
- Embed in HN post (as link), X thread tweet 1, Reddit posts.
- Link in every "what does this do" support reply for the first month.
