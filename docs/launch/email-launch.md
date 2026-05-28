# Email — Waitlist Launch Announcement

**Send at:** T-0, 06:00 Eastern (3 hours before HN).
**From:** founder@xgenguardian.com (real personal address; reply-to monitored).
**To:** waitlist + design partners.
**Plain text. No images. No tracking pixels. Send it from a personal mailbox.**

---

**Subject:** XGenGuardian is live.

---

Hi {{ first_name }},

XGenGuardian is live as of this morning. You signed up for the waitlist a while ago; this is the email I promised.

Three things you can do in the next ten minutes:

1. **Try it without committing anything.** Paste any URL — your bank's, a suspicious email link, whatever — into https://report.xgenguardian.com . You'll get a sandboxed screenshot, a visual-similarity score against the brand it claims to be, and a plain-English explanation. Free, no signup.

2. **Switch your DNS.** If you like what you see, point your device or router at our DoH endpoint: https://dns.xgenguardian.com/dns-query . Setup instructions for every OS are at https://xgenguardian.com/setup .

3. **Tell me what's wrong.** I'd much rather hear the criticism now than read it on Hacker News in three hours. Reply to this email directly.

The full architecture document is at https://xgenguardian.com/architecture if you want the 50-page version. It includes the things we deliberately don't do.

If you're an early design partner, your Plus tier is free for 12 months — no further action needed; it's already applied to your account.

Thanks for being patient. The product is better because you waited.

— [name]
Founder, XGenGuardian

---

## Variants

### For paying design partners

Replace paragraph 3 with:
> Your account is already on Plus, free for 12 months as agreed. If you'd like an org-level admin console, I can grant you Business-tier access until the end of the year — just reply yes.

### For waitlist signups who haven't engaged in 90+ days

Add at the top:
> You may not remember signing up — that was [estimated date]. If you'd like to be removed from this list, just hit reply and say so.

---

## Operational notes

- Send via Postmark or AWS SES with a dedicated subdomain (no shared-IP services).
- Throttle to 50/sec to avoid being flagged.
- Monitor reply-to address for the first 4 hours; reply within 30 minutes during launch window.
- Track only delivery and bounces. No open or click tracking — we're a privacy product.
