# Email Risk Analyzer

A Python script that inspects email text for common phishing and social engineering indicators such as urgent pressure tactics, requests for sensitive data, and suspicious links.

## Features
- **Urgency Detection:** Flags high-pressure phrases commonly used in phishing lures.
- **Sensitive Data Prompts:** Detects mentions or requests involving passwords, OTPs, PINs, card details, and IDs.
- **Link Inspection:** Highlights URLs with high-risk top-level domains, raw IP addresses, or unusually long links.
- **Risk Scoring:** Classifies emails into *Low Risk*, *Medium Risk*, or *High Risk* with clear explanations.

## How to Run
1. Ensure Python 3 is installed.
2. Run the script in your terminal:
   ```bash
   python email_risk_analyzer.py
