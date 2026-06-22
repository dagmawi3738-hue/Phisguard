#!/usr/bin/env python3
"""
PhishGuard - Phishing Email Detector
Analyzes email headers and content for phishing indicators.
Usage: python phishing_detector.py <email_file.eml>
       python phishing_detector.py --demo
"""

import re
import sys
import os
import email
import urllib.parse
from email import policy
from datetime import datetime

# ─── Try optional imports ────────────────────────────────────────────────────
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─── Known phishing / suspicious patterns ────────────────────────────────────
URGENCY_WORDS = [
    "urgent", "immediately", "account suspended", "verify now",
    "click here", "act now", "limited time", "your account will be",
    "unusual activity", "security alert", "confirm your identity",
    "update your information", "you have been selected",
    "congratulations", "you won", "claim your prize",
    "password expired", "locked", "suspended", "blocked",
]

SUSPICIOUS_KEYWORDS = [
    "ssn", "social security", "bank account", "wire transfer",
    "bitcoin", "gift card", "itunes", "google play",
    "send money", "western union", "moneygram",
    "login", "verify", "validate", "reset your password",
    "confirm payment", "invoice attached", "kindly",
]

FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com",
    "yandex.com", "gmx.com", "live.com", "msn.com",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
]

SUSPICIOUS_TLD = [
    ".xyz", ".top", ".club", ".online", ".site", ".tech",
    ".info", ".biz", ".ml", ".tk", ".ga", ".cf",
]

BRAND_SPOOFING = [
    "paypa1", "paypai", "amaz0n", "micros0ft", "app1e",
    "g00gle", "netf1ix", "faceb00k", "linkedln", "roblox-",
    "amazon-", "apple-", "microsoft-", "paypal-", "google-",
    "netflix-", "facebook-", "instagram-", "twitter-",
]


# ─── Findings tracker ────────────────────────────────────────────────────────
class Finding:
    def __init__(self, severity, category, description):
        self.severity = severity      # HIGH / MEDIUM / LOW
        self.category = category
        self.description = description

    def color(self):
        return {
            "HIGH":   RED,
            "MEDIUM": YELLOW,
            "LOW":    CYAN,
        }.get(self.severity, RESET)


# ─── Analysis functions ───────────────────────────────────────────────────────

def extract_urls(text):
    """Extract all URLs from text."""
    pattern = r'https?://[^\s<>"\')\]|,]+'
    return re.findall(pattern, text or "")


def check_headers(msg):
    findings = []

    from_addr  = msg.get("From", "")
    reply_to   = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    received   = msg.get_all("Received") or []
    spf        = msg.get("Received-SPF", "")
    dkim       = msg.get("DKIM-Signature", "")
    dmarc      = msg.get("Authentication-Results", "")
    subject    = msg.get("Subject", "")

    # ── From field checks ──
    from_email = re.search(r'<(.+?)>', from_addr)
    from_email = from_email.group(1).lower() if from_email else from_addr.lower().strip()
    from_domain = from_email.split("@")[-1] if "@" in from_email else ""

    if from_domain in FREE_EMAIL_PROVIDERS:
        findings.append(Finding("HIGH", "Header",
            f"Sender uses free email provider ({from_domain}) — suspicious for official comms"))

    for brand in BRAND_SPOOFING:
        if brand in from_domain:
            findings.append(Finding("HIGH", "Spoofing",
                f"Possible brand spoofing detected in sender domain: {from_domain}"))

    # ── Reply-To mismatch ──
    if reply_to and reply_to.lower() != from_addr.lower():
        rt_email = re.search(r'<(.+?)>', reply_to)
        rt_email = rt_email.group(1) if rt_email else reply_to.strip()
        findings.append(Finding("HIGH", "Header",
            f"Reply-To ({rt_email}) differs from From address — classic phishing trick"))

    # ── Return-Path mismatch ──
    if return_path and from_domain:
        rp_domain = return_path.split("@")[-1].replace(">", "").strip().lower()
        if rp_domain and rp_domain != from_domain:
            findings.append(Finding("MEDIUM", "Header",
                f"Return-Path domain ({rp_domain}) doesn't match From domain ({from_domain})"))

    # ── SPF / DKIM / DMARC ──
    if spf and "fail" in spf.lower():
        findings.append(Finding("HIGH", "Authentication",
            f"SPF check FAILED — email may not be from the claimed sender"))
    elif not spf:
        findings.append(Finding("LOW", "Authentication",
            "No SPF result found in headers"))

    if not dkim:
        findings.append(Finding("MEDIUM", "Authentication",
            "No DKIM signature found — sender authenticity unverified"))

    if dmarc and "fail" in dmarc.lower():
        findings.append(Finding("HIGH", "Authentication",
            "DMARC authentication FAILED"))

    # ── Subject urgency ──
    subject_lower = subject.lower()
    for word in URGENCY_WORDS:
        if word in subject_lower:
            findings.append(Finding("MEDIUM", "Subject",
                f"Urgency keyword in subject line: '{word}'"))
            break

    if subject == subject.upper() and len(subject) > 5:
        findings.append(Finding("LOW", "Subject",
            "Subject line is ALL CAPS — common manipulation tactic"))

    # ── Received hops ──
    if len(received) > 6:
        findings.append(Finding("LOW", "Header",
            f"Email passed through {len(received)} hops — unusually high, may indicate relay abuse"))

    return findings, from_domain, subject


def check_body(msg):
    findings = []
    urls = []

    # Get body text
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    body += part.get_payload(decode=True).decode(errors="replace")
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="replace")
        except Exception:
            body = str(msg.get_payload())

    body_lower = body.lower()

    # ── Urgency / manipulation language ──
    found_urgency = []
    for word in URGENCY_WORDS:
        if word in body_lower:
            found_urgency.append(word)
    if found_urgency:
        findings.append(Finding("MEDIUM", "Content",
            f"Urgency/manipulation language detected: {', '.join(found_urgency[:5])}"))

    # ── Suspicious keywords ──
    found_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in body_lower:
            found_keywords.append(kw)
    if found_keywords:
        findings.append(Finding("MEDIUM", "Content",
            f"Sensitive/suspicious keywords found: {', '.join(found_keywords[:5])}"))

    # ── Mismatched display text vs URL ──
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    text_url_pattern = re.compile(r'>(https?://[^<]+)<', re.IGNORECASE)
    hrefs = href_pattern.findall(body)
    display_urls = text_url_pattern.findall(body)

    for href in hrefs:
        for display in display_urls:
            href_domain = urllib.parse.urlparse(href).netloc
            display_domain = urllib.parse.urlparse(display).netloc
            if href_domain and display_domain and href_domain != display_domain:
                findings.append(Finding("HIGH", "URL",
                    f"Link text shows '{display_domain}' but actually goes to '{href_domain}'"))

    # ── Extract all URLs ──
    urls = extract_urls(body)
    urls += hrefs

    # Deduplicate
    urls = list(set(urls))

    return findings, body, urls


def check_urls(urls):
    findings = []
    analyzed = []

    for url in urls[:20]:  # cap at 20 URLs
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        url_findings = []

        # URL shortener
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                url_findings.append(Finding("HIGH", "URL",
                    f"URL shortener detected: {url} — hides true destination"))

        # Suspicious TLD
        for tld in SUSPICIOUS_TLD:
            if domain.endswith(tld):
                url_findings.append(Finding("MEDIUM", "URL",
                    f"Suspicious TLD ({tld}) in URL: {domain}"))

        # IP address instead of domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            url_findings.append(Finding("HIGH", "URL",
                f"URL uses raw IP address instead of domain name: {domain}"))

        # Lots of subdomains (phishing trick)
        subdomain_count = domain.count(".")
        if subdomain_count >= 4:
            url_findings.append(Finding("MEDIUM", "URL",
                f"Excessive subdomains ({subdomain_count}) — may be obfuscating real domain"))

        # Brand spoofing in URL
        for brand in BRAND_SPOOFING:
            if brand in domain:
                url_findings.append(Finding("HIGH", "URL",
                    f"Possible brand spoofing in URL: {domain}"))

        # HTTP (not HTTPS)
        if parsed.scheme == "http":
            url_findings.append(Finding("LOW", "URL",
                f"Non-HTTPS URL (unencrypted): {url}"))

        # Encoded characters (obfuscation)
        if "%" in url and url.count("%") > 3:
            url_findings.append(Finding("MEDIUM", "URL",
                f"Heavily URL-encoded link (possible obfuscation): {url[:80]}"))

        analyzed.append((url, url_findings))
        findings.extend(url_findings)

    return findings, analyzed


def check_attachments(msg):
    findings = []
    dangerous_ext = [
        ".exe", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".scr",
        ".hta", ".jar", ".com", ".pif", ".reg", ".msi", ".dll",
        ".docm", ".xlsm", ".pptm",  # macro-enabled Office
    ]

    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            fname_lower = filename.lower()
            for ext in dangerous_ext:
                if fname_lower.endswith(ext):
                    findings.append(Finding("HIGH", "Attachment",
                        f"Dangerous attachment type: {filename}"))
                    break
            else:
                # Double extension trick (e.g. invoice.pdf.exe)
                if fname_lower.count(".") >= 2:
                    findings.append(Finding("MEDIUM", "Attachment",
                        f"Double extension detected (possible disguise): {filename}"))

    return findings


# ─── Scoring ─────────────────────────────────────────────────────────────────

def calculate_score(findings):
    score = 0
    for f in findings:
        if f.severity == "HIGH":
            score += 30
        elif f.severity == "MEDIUM":
            score += 15
        elif f.severity == "LOW":
            score += 5
    return min(score, 100)


def verdict(score):
    if score >= 70:
        return RED + BOLD + "🚨 HIGH RISK — LIKELY PHISHING" + RESET
    elif score >= 40:
        return YELLOW + BOLD + "⚠️  MEDIUM RISK — SUSPICIOUS" + RESET
    elif score >= 15:
        return CYAN + BOLD + "🔍 LOW RISK — WORTH REVIEWING" + RESET
    else:
        return GREEN + BOLD + "✅ LOOKS CLEAN" + RESET


# ─── Report printer ──────────────────────────────────────────────────────────

def print_report(findings, score, from_domain, subject, analyzed_urls, email_file):
    width = 70
    line = "─" * width

    print(f"\n{BOLD}{'═' * width}{RESET}")
    print(f"{BOLD}  PhishGuard — Phishing Email Analysis Report{RESET}")
    print(f"{'═' * width}")
    print(f"  File    : {email_file}")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  From    : {from_domain or 'Unknown'}")
    print(f"  Subject : {subject or 'None'}")
    print(f"{'═' * width}\n")

    # ── Findings ──
    print(f"{BOLD}  FINDINGS ({len(findings)} total){RESET}")
    print(f"  {line}")

    categories = {}
    for f in findings:
        categories.setdefault(f.category, []).append(f)

    for cat, items in categories.items():
        print(f"\n  {BOLD}[ {cat} ]{RESET}")
        for f in items:
            icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.severity, "⚪")
            print(f"  {icon} {f.color()}{f.severity:6}{RESET}  {f.description}")

    # ── URLs summary ──
    if analyzed_urls:
        print(f"\n  {BOLD}[ URLs Analyzed ]{RESET}")
        for url, url_findings in analyzed_urls[:10]:
            short_url = url[:65] + "..." if len(url) > 65 else url
            status = RED + "SUSPICIOUS" + RESET if url_findings else GREEN + "OK" + RESET
            print(f"  {'🔴' if url_findings else '🟢'} [{status}] {short_url}")

    # ── Score & Verdict ──
    print(f"\n  {line}")
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    score_color = RED if score >= 70 else YELLOW if score >= 40 else GREEN
    print(f"\n  Risk Score : {score_color}{BOLD}{score}/100{RESET}  [{score_color}{bar}{RESET}]")
    print(f"  Verdict    : {verdict(score)}")

    print(f"\n  {BOLD}Severity Breakdown:{RESET}")
    high   = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low    = sum(1 for f in findings if f.severity == "LOW")
    print(f"  {RED}HIGH  : {high:2d}{RESET}  |  {YELLOW}MEDIUM: {medium:2d}{RESET}  |  {CYAN}LOW   : {low:2d}{RESET}")

    print(f"\n{'═' * width}\n")


# ─── Demo mode ───────────────────────────────────────────────────────────────

DEMO_EMAIL = """From: mastercardsIT@gmail.com
To: employee@mastercard.com
Reply-To: attacker@evil-phish.xyz
Return-Path: <bounce@phishing-domain.top>
Subject: URGENT!! Your Account Has Been Suspended - Verify Now
Received: from mail.phishing-domain.top (192.168.1.100) by mx.mastercard.com
Received: from smtp.evil.xyz by mail.phishing-domain.top
Received: from relay1.shady.ml by smtp.evil.xyz
Received: from relay2.bad.tk by relay1.shady.ml
Received: from relay3.test.ga by relay2.bad.tk
Received: from origin.cf by relay3.test.ga
Received: from start.biz by origin.cf

Hello (insert name),

URGENT: Your Mastercard employee account has been compromised. Immediate action is required!

Your account will be LOCKED in 1 hour unless you verify your identity immediately.

Click here to reset your password: http://192.168.100.5/mastercard-login/reset.php

Or visit our secure portal: https://mastercard-verify.xyz/login

You can also click: <a href="http://bit.ly/mc-reset">https://www.mastercard.com/reset</a>

We have detected unusual activity from an unrecognized device. Please confirm your identity and update your information immediately or your account access will be suspended.

Please provide your SSN and bank account details to verify your identity.

Send a gift card or bitcoin payment of $50 to unlock your account.

Kindly act now.

Regards,
Mastercard IT Security Team
"""


# ─── Main ────────────────────────────────────────────────────────────────────

def analyze(raw_email, label="input"):
    msg = email.message_from_string(raw_email, policy=policy.compat32)

    header_findings, from_domain, subject = check_headers(msg)
    body_findings, body, urls = check_body(msg)
    url_findings, analyzed_urls = check_urls(urls)
    attachment_findings = check_attachments(msg)

    all_findings = header_findings + body_findings + url_findings + attachment_findings
    score = calculate_score(all_findings)

    print_report(all_findings, score, from_domain, subject, analyzed_urls, label)
    return score


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(f"\n{BOLD}PhishGuard — Phishing Email Detector{RESET}")
        print("Usage:")
        print("  python phishing_detector.py email.eml     # Analyze an .eml file")
        print("  python phishing_detector.py --demo        # Run with built-in demo email")
        print("  python phishing_detector.py --stdin       # Pipe raw email via stdin\n")
        sys.exit(0)

    if sys.argv[1] == "--demo":
        print(f"\n{CYAN}[Demo mode — using built-in phishing sample]{RESET}")
        analyze(DEMO_EMAIL, label="demo_phishing_email.eml")

    elif sys.argv[1] == "--stdin":
        raw = sys.stdin.read()
        analyze(raw, label="<stdin>")

    else:
        path = sys.argv[1]
        if not os.path.exists(path):
            print(f"{RED}Error: File not found: {path}{RESET}")
            sys.exit(1)
        with open(path, "r", errors="replace") as f:
            raw = f.read()
        analyze(raw, label=path)


if __name__ == "__main__":
    main()
