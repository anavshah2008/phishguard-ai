# PhishGuard AI: Interactive Phishing Analyzer & Security Trainer

![PhishGuard AI Banner](thumbnail.png)

An interactive console-based cybersecurity toolkit built in Python for **Stanford Code in Place**. It combines heuristic phishing detection, an interactive security analyst game, and a password entropy auditor.

**Live Demo (Stanford Code in Place IDE):** [Run PhishGuard AI Online](https://codeinplace.stanford.edu/cipx/share/kn8I5pO3WiByat8XgZRj)

---

## Features

1. **Phishing Threat Scanner**
   - Scans sender addresses, subject lines, and message bodies for social engineering cues, typosquatted brand domains, raw IP URLs, and high-risk TLDs.
   - Outputs a 0–100 ASCII risk meter and triggered flags.
   - Automatically enables `call_gpt` forensic analysis when run inside the Code in Place IDE, and falls back gracefully to pure heuristics offline.

2. **Defend the Inbox (5-Round SOC Game)**
   - Inspect realistic phishing and legitimate emails, use optional hints, and build a classification streak to earn your analyst rank.

3. **Password Entropy Auditor**
   - Calculates bit-level entropy based on character pool size and length.
   - Flags common leaked passwords and estimates offline brute-force crack time.

---

## Run Locally

No external packages required—uses only the Python standard library.

```bash
git clone [https://github.com/anavshah2008/phishguard-ai.git](https://github.com/anavshah2008/phishguard-ai.git)
cd phishguard-ai
python main.py