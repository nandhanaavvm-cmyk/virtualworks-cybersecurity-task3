import re


URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "within 24 hours",
    "account suspended",
    "account will be closed",
    "final notice",
    "act now",
    "verify your account",
]

SENSITIVE_DATA_PATTERNS = [
    r"\bpassword\b",
    r"\bpin\b",
    r"\botp\b",
    r"\bssn\b",
    r"\baadhaar\b",
    r"\bpan\b",
    r"\bcredit card\b",
    r"\bdebit card\b",
    r"\bcvv\b",
    r"\bbank account\b",
]

SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf", ".ga", ".zip", ".mov")
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def analyze_email(subject, sender, body):
    full_text = f"{subject}\n{body}".lower()
    risk_score = 0
    findings = []

    # 1. Check urgent language
    found_urgency = [word for word in URGENCY_KEYWORDS if word in full_text]
    if found_urgency:
        risk_score += 2
        findings.append(f"Urgent language detected: {', '.join(found_urgency)}")

    # 2. Check requests for sensitive information
    found_sensitive = []
    for pattern in SENSITIVE_DATA_PATTERNS:
        if re.search(pattern, full_text):
            cleaned = pattern.replace(r"\b", "")
            found_sensitive.append(cleaned)
    if found_sensitive:
        risk_score += 3
        findings.append(f"Sensitive data prompts detected: {', '.join(found_sensitive)}")

    # 3. Check links and unusual TLDs
    urls = URL_PATTERN.findall(body)
    suspicious_urls = []
    for url in urls:
        domain = url.split("//", 1)[1].split("/", 1)[0].lower()
        has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain))
        has_bad_tld = domain.endswith(SUSPICIOUS_TLDS)
        if has_ip or has_bad_tld or len(url) > 75:
            suspicious_urls.append(url)

    if suspicious_urls:
        risk_score += 3
        findings.append(f"Suspicious links detected: {', '.join(suspicious_urls)}")
    elif urls:
        risk_score += 1
        findings.append(f"External links present ({len(urls)} link(s)) — verify sender before clicking.")

    # 4. Check sender mismatch / display-name trick
    if sender.strip():
        if "<" in sender and ">" in sender:
            display_part = sender.split("<", 1)[0].lower()
            email_part = sender.split("<", 1)[1].split(">", 1)[0].lower()
            if any(brand in display_part for brand in ["bank", "paypal", "amazon", "google", "microsoft", "hr", "admin"]):
                email_domain = email_part.split("@")[-1] if "@" in email_part else ""
                if not any(brand in email_domain for brand in ["bank", "paypal", "amazon", "google", "microsoft"]):
                    risk_score += 2
                    findings.append(f"Sender display name may not match actual address ({email_part}).")

    if risk_score >= 5:
        risk_level = "High Risk"
    elif risk_score >= 2:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return risk_level, risk_score, findings


def main():
    print("=== Email Risk Analyzer ===")
    sender = input("Sender (optional, e.g., Support <help@example.xyz>): ").strip()
    subject = input("Email Subject: ").strip()
    print("Paste email body (press Enter twice to finish):")

    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    body = "\n".join(lines).strip()

    if not subject and not body:
        print("Error: Please provide at least a subject or email body to analyze.")
        return

    risk_level, risk_score, findings = analyze_email(subject, sender, body)

    print(f"\nRisk Level: {risk_level} (Risk Score: {risk_score})")
    if findings:
        print("Flags found:")
        for item in findings:
            print(f" - {item}")
    else:
        print("No suspicious indicators detected.")


if __name__ == "__main__":
    main()
