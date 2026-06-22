# 🛡️ PhishGuard — Phishing Email Detector

A command-line tool that analyzes email files for phishing indicators across headers, content, URLs, and attachments — and produces a scored risk report.

Built as a cybersecurity portfolio project demonstrating blue team/SOC analysis skills.

---

## 📸 Demo Output

```
══════════════════════════════════════════════════════════════════════
  PhishGuard — Phishing Email Analysis Report
══════════════════════════════════════════════════════════════════════
  File    : demo_phishing_email.eml
  From    : gmail.com
  Subject : URGENT!! Your Account Has Been Suspended - Verify Now
══════════════════════════════════════════════════════════════════════

  FINDINGS (15 total)
  ──────────────────────────────────────────────────────────────────

  [ Header ]
  🔴 HIGH    Sender uses free email provider (gmail.com)
  🔴 HIGH    Reply-To differs from From address — classic phishing trick
  🟡 MEDIUM  Return-Path domain doesn't match From domain
  🔵 LOW     Email passed through 7 hops — unusually high

  [ Authentication ]
  🟡 MEDIUM  No DKIM signature found — sender authenticity unverified

  [ URL ]
  🔴 HIGH    Link text shows 'www.mastercard.com' but goes to 'bit.ly'
  🔴 HIGH    URL uses raw IP address instead of domain name
  🔴 HIGH    URL shortener detected — hides true destination

  Risk Score : 100/100  [████████████████████]
  Verdict    : 🚨 HIGH RISK — LIKELY PHISHING
══════════════════════════════════════════════════════════════════════
```

---

## 🚀 Features

| Category | What It Checks |
|----------|---------------|
| **Headers** | Free email providers, Reply-To mismatches, Return-Path spoofing, excessive relay hops |
| **Authentication** | SPF fail/missing, DKIM missing, DMARC fail |
| **Subject** | Urgency keywords, ALL CAPS manipulation |
| **Content** | Urgency language, sensitive data requests (SSN, bank account, bitcoin, gift cards) |
| **URLs** | Raw IP addresses, URL shorteners, suspicious TLDs (.xyz .tk .ml), brand spoofing, HTTP vs HTTPS, mismatched link text |
| **Attachments** | Dangerous file types (.exe, .vbs, .ps1, macro-enabled Office), double extension tricks |

---

## 📦 Installation

**Requirements:** Python 3.7+

```bash
# Clone the repo
git clone https://github.com/yourusername/phishguard.git
cd phishguard

# Install optional dependencies (recommended)
pip install requests dnspython
```

> The tool runs without any dependencies — `requests` and `dnspython` are optional enhancements.

---

## 🔧 Usage

```bash
# Analyze an .eml file
python phishing_detector.py email.eml

# Run the built-in phishing demo
python phishing_detector.py --demo

# Pipe raw email via stdin
cat email.eml | python phishing_detector.py --stdin

# Show help
python phishing_detector.py --help
```

### Getting .eml files
- **Gmail:** Open email → Three dots menu → Download message
- **Outlook:** File → Save As → Outlook Message Format (.msg) or drag to desktop
- **Thunderbird:** File → Save As → File

---

## 📊 Scoring

Each finding contributes to a 0–100 risk score:

| Severity | Points |
|----------|--------|
| 🔴 HIGH   | +30    |
| 🟡 MEDIUM | +15    |
| 🔵 LOW    | +5     |

| Score Range | Verdict |
|-------------|---------|
| 70–100 | 🚨 HIGH RISK — LIKELY PHISHING |
| 40–69  | ⚠️ MEDIUM RISK — SUSPICIOUS |
| 15–39  | 🔍 LOW RISK — WORTH REVIEWING |
| 0–14   | ✅ LOOKS CLEAN |

---

## 🧠 Detection Logic

### Header Analysis
Checks the `From`, `Reply-To`, and `Return-Path` fields for mismatches — a common phishing tactic where attackers use a legitimate-looking display name but route replies to a malicious address.

### Authentication Checks
Parses `Received-SPF`, `DKIM-Signature`, and `Authentication-Results` headers to identify failed or missing email authentication — a strong indicator the email didn't originate from the claimed sender.

### URL Analysis
Extracts all hyperlinks from the email body and checks each one for:
- Raw IP addresses used instead of domain names
- URL shorteners that obscure the real destination
- Suspicious TLDs commonly used in phishing campaigns
- Mismatched anchor text vs actual link destination

### Content Analysis
Scans email body for urgency language and sensitive keyword patterns commonly used in social engineering attacks.

---

## 📁 Project Structure

```
phishguard/
├── phishing_detector.py   # Main detector script
├── README.md              # This file
└── samples/               # (Optional) Sample .eml files for testing
    └── demo_phishing.eml
```

---

## 🔮 Future Improvements

- [ ] VirusTotal API integration for URL reputation checks
- [ ] WHOIS lookup for domain age (new domains = higher risk)
- [ ] Machine learning classifier trained on phishing datasets
- [ ] Web interface (Flask) for drag-and-drop email analysis
- [ ] Batch mode to scan entire mailbox exports
- [ ] Export report to PDF or JSON

---

## 🎯 Skills Demonstrated

- Email protocol analysis (SMTP headers, SPF/DKIM/DMARC)
- Python scripting for security tooling
- Pattern recognition for social engineering indicators
- URL parsing and link analysis
- Threat intelligence concepts (IOC identification)
- Blue team / SOC analyst workflow

---

## 📚 References

- [MITRE ATT&CK T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [RFC 7208 — SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 — DKIM](https://tools.ietf.org/html/rfc6376)
- [PhishTank](https://www.phishtank.com/) — Phishing URL database

---

## 👤 Author

**Dagmawi Ginjo**  
Cybersecurity Student — University of Maryland Global Campus  
[LinkedIn](https://linkedin.com/in/yourprofile) | [GitHub](https://github.com/yourusername)

---

> ⚠️ **Disclaimer:** This tool is intended for educational and defensive security purposes only. Only analyze emails you own or have explicit permission to analyze.
