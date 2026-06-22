# 🔍 Case Study: Real-World Email Analysis with PhishGuard

## Target Email

| Field | Value |
|-------|-------|
| **Subject** | Your Moonbounce Home is Ready! |
| **Sender** | Moonbounce `<team@getmoonbounce.com>` |
| **Received** | June 22, 2026 |
| **Gmail Classification** | 🚨 Spam |
| **PhishGuard Risk Score** | **100 / 100** |
| **Verdict** | 🚨 HIGH RISK — LIKELY PHISHING |

---

## What the Email Claimed

The email posed as a service notification from "Moonbounce Homes," a link-in-bio page builder. It invited the recipient to visit `https://moonbounce.gg` and build a profile page. The message used friendly, casual language designed to appear legitimate and encourage a click.

---

## What PhishGuard Found

**Severity Breakdown:** 🔴 HIGH: 7 | 🟡 MEDIUM: 12 | 🔵 LOW: 2

### Header Findings
- Sender routed through `sendibm3.com` — a third-party email delivery service commonly abused for spam campaigns
- Multiple suspicious relay hops detected in `Received` headers
- No DKIM signature present — sender authenticity could not be verified
- SPF record absent from headers

### URL Findings
PhishGuard extracted and analyzed all embedded links. Key findings:

| URL | Status | Reason |
|-----|--------|--------|
| `https://994mt.img.ag.d.sendibm3.com/...` | 🔴 SUSPICIOUS | Tracking pixel via known spam infrastructure |
| `https://994mt.r.ag.d.sendibm3.com/mk/cl/...` | 🔴 SUSPICIOUS | Click-tracking redirect via `sendibm3.com` |
| `https://fonts.googleapis.com/...` | 🟢 OK | Legitimate Google Fonts CDN |

All non-Google URLs routed through `sendibm3.com` — IBM's email marketing relay, frequently used in unsolicited bulk email campaigns. The actual destination of any clicked link is masked behind redirect chains.

### Content Findings
- Call-to-action language: "Build yours now" — mild urgency
- External link to `moonbounce.gg` — a `.gg` TLD (Guernsey) commonly used by gaming/startup sites but also by low-reputation domains

---

## Analysis

Despite appearing to be a routine product notification, this email raised multiple red flags:

1. **Infrastructure mismatch** — A legitimate company would typically send from its own domain mail servers. Routing through `sendibm3.com` with no DKIM signature suggests either a bulk email service or spoofed sender.

2. **Redirect chains** — Every link in the email (including images) passes through `sendibm3.com` tracking servers before reaching the destination. This is a common technique to hide the true target URL from spam filters and recipients.

3. **No authentication** — The absence of SPF and DKIM records means there is no cryptographic proof the email originated from `getmoonbounce.com`.

4. **Gmail flagged it independently** — Gmail's own spam filter placed this in the Spam folder, consistent with PhishGuard's HIGH RISK verdict.

---

## Verdict

While this email may be unsolicited marketing rather than a targeted phishing attack, it exhibits the same infrastructure patterns used in phishing campaigns:
- Third-party relay with masked redirects
- No email authentication
- Tracking pixels to confirm email opens

**Recommended action:** Do not click any links. Mark as spam. Block sender domain.

---

## Takeaway

This case study demonstrates PhishGuard's ability to detect suspicious patterns in real-world emails — not just textbook phishing samples. The tool flagged the same email that Gmail's own filter classified as spam, validating its detection logic against live data.

---

*Analyzed using [PhishGuard](https://github.com/dagmawi3738-hue/Phisguard) — an open-source phishing email detector built in Python.*
