import math
import random
import re

# Automatically use Code in Place's built-in call_gpt if available
try:
    from ai import call_gpt
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False


# --- HEURISTIC RULESET ---

URGENCY_TRIGGERS = {
    "urgent": 15,
    "immediately": 15,
    "suspended": 20,
    "verify your account": 25,
    "confirm your identity": 20,
    "within 24 hours": 20,
    "action required": 15,
    "unauthorized": 15,
    "click here": 15,
    "wire transfer": 25,
    "gift card": 25,
    "password expires": 20,
    "locked": 15,
}

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".tk", ".ru", ".zip", ".buzz", ".gq"]

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "stanford": "stanford.edu",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
}

COMMON_WEAK_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "admin", "letmein", "welcome", "iloveyou", "monkey",
}

# --- GAME SCENARIOS ---

INBOX_SCENARIOS = [
    {
        "sender": "security-alert@paypa1-verify.xyz",
        "subject": "URGENT: Your PayPal account has been suspended",
        "body": "Unauthorized login detected. Verify your account within 24 hours at http://192.168.45.12/paypal-login or funds will be frozen.",
        "is_phish": True,
        "hint": "Look closely at the sender's domain spelling and the URL format.",
        "explanation": "Typosquatted domain ('paypa1' with a 1 + '.xyz' TLD), high urgency, and a raw IP address link.",
    },
    {
        "sender": "notifications@github.com",
        "subject": "[GitHub] A new SSH key was added to your account",
        "body": "Hi there, a new SSH key was added to your GitHub account. If this was you, you can ignore this email. Otherwise, review your keys in Settings.",
        "is_phish": False,
        "hint": "Check whether the message pressures you into clicking an external link.",
        "explanation": "Legitimate domain (github.com), no urgent threat, and tells you to navigate to Settings yourself instead of clicking a shady link.",
    },
    {
        "sender": "it-helpdesk@stanford-portal.top",
        "subject": "Action Required: Password expires tonight",
        "body": "Your university password expires in 2 hours. Click here immediately to keep your current password: https://stanford-portal.top/reset",
        "is_phish": True,
        "hint": "Compare the claimed organization with the actual root domain.",
        "explanation": "Impersonates Stanford using a '.top' domain instead of 'stanford.edu' and manufactures a 2-hour deadline.",
    },
    {
        "sender": "billing@netflix.com",
        "subject": "Your monthly receipt",
        "body": "Thanks for being a member. Your monthly plan was renewed for $15.49. You can view your invoice anytime from your Account page.",
        "is_phish": False,
        "hint": "Check the sender domain and whether sensitive info is requested.",
        "explanation": "Matches the official netflix.com domain, informational tone, and no credential harvesting link.",
    },
    {
        "sender": "ceo.office.urgent@gmail.com",
        "subject": "Quick favor - in a meeting",
        "body": "Hey, I'm stuck in a board meeting and can't talk. Need you to buy 5 Apple gift cards immediately for a client. Will reimburse today.",
        "is_phish": True,
        "hint": "Notice the sender's email provider and the payment method requested.",
        "explanation": "Classic Business Email Compromise (BEC): uses a free Gmail address, claims they can't talk, and asks for gift cards.",
    },
    {
        "sender": "orders@amazon.com",
        "subject": "Your package has been delivered",
        "body": "Your order #114-8829103 was left near the front porch. Visit Amazon.com > Your Orders to see delivery photo.",
        "is_phish": False,
        "hint": "Does it ask you to log in through a suspicious link?",
        "explanation": "Official amazon.com sender with no suspicious external links or pressure tactics.",
    },
]


# --- UI HELPERS ---

def print_header(title):
    print("\n" + "=" * 56)
    print(f"  {title}")
    print("=" * 56)


def render_meter(score, width=25):
    filled = int((score / 100) * width)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {score}/100"


# --- MODULE 1: PHISHING THREAT SCANNER ---

def extract_urls(text):
    return re.findall(r"https?://[^\s]+", text)


def analyze_message(sender, subject, body):
    score = 0
    findings = []
    combined = f"{subject} {body}".lower()
    sender_lower = sender.lower().strip()

    # 1. Urgency & social engineering keywords
    for phrase, weight in URGENCY_TRIGGERS.items():
        if phrase in combined:
            score += weight
            findings.append(f"[+{weight}] Social engineering cue detected: '{phrase}'")

    # 2. Sender domain & brand impersonation check
    if "@" in sender_lower:
        domain = sender_lower.split("@")[-1]
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 25
                findings.append(f"[+25] High-risk sender TLD: '{tld}' in {domain}")

        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in combined and official_domain not in domain:
                score += 30
                findings.append(
                    f"[+30] Possible brand spoofing: mentions '{brand}', "
                    f"but sender domain is '{domain}' (expected '{official_domain}')"
                )
                break

    # 3. URL inspection
    urls = extract_urls(body)
    for url in urls:
        if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
            score += 35
            findings.append(f"[+35] Raw IP address used in URL: {url}")
        if url.startswith("http://"):
            score += 10
            findings.append(f"[+10] Unencrypted HTTP link: {url}")
        for tld in SUSPICIOUS_TLDS:
            if tld in url.lower():
                score += 20
                findings.append(f"[+20] Suspicious TLD '{tld}' inside link: {url}")

    score = min(score, 100)

    if score >= 60:
        verdict = "HIGH RISK (Likely Phishing)"
    elif score >= 30:
        verdict = "MEDIUM RISK (Suspicious - Verify Independently)"
    else:
        verdict = "LOW RISK (No Major Red Flags Detected)"

    return score, verdict, findings


def run_scanner():
    print_header("MODULE 1: PHISHING THREAT SCANNER")
    print("Paste a suspicious message, or type 'demo' to test a sample attack.\n")

    sender = input("Sender email (or 'demo'): ").strip()
    if sender.lower() == "demo":
        sample = INBOX_SCENARIOS[0]
        sender = sample["sender"]
        subject = sample["subject"]
        body = sample["body"]
        print(f"\nLoaded sample from: {sender}")
        print(f"Subject: {subject}")
        print(f"Body: {body}")
    else:
        subject = input("Subject line: ").strip()
        body = input("Message body: ").strip()

    score, verdict, findings = analyze_message(sender, subject, body)

    print("\n--- THREAT REPORT ---")
    print(f"Risk Meter : {render_meter(score)}")
    print(f"Verdict    : {verdict}")

    if findings:
        print("\nFlags Triggered:")
        for item in findings:
            print(f"  * {item}")
    else:
        print("\nNo heuristic red flags triggered.")

    if AI_AVAILABLE:
        ask_ai = input("\nRun AI Forensic Deep-Dive with call_gpt? (y/n): ").strip().lower()
        if ask_ai == "y":
            prompt = (
                "You are a cybersecurity analyst. In 3 concise bullet points, "
                "explain whether this message is phishing and what a user should do:\n"
                f"Sender: {sender}\nSubject: {subject}\nBody: {body}"
            )
            print("\n--- AI FORENSIC ANALYSIS ---")
            print(call_gpt(prompt))


# --- MODULE 2: DEFEND THE INBOX GAME ---

def run_inbox_game():
    print_header("MODULE 2: DEFEND THE INBOX (5 ROUNDS)")
    print("You are on SOC duty. Inspect each email and classify it:")
    print("  [P] Phishing   [S] Safe   [H] Hint (half points)\n")

    scenarios = random.sample(INBOX_SCENARIOS, k=min(5, len(INBOX_SCENARIOS)))
    total_points = 0
    streak = 0

    for idx, email in enumerate(scenarios, start=1):
        print(f"\n--- Email {idx}/{len(scenarios)} | Points: {total_points} | Streak: {streak} ---")
        print(f"From   : {email['sender']}")
        print(f"Subject: {email['subject']}")
        print(f"Body   : {email['body']}")

        used_hint = False
        while True:
            choice = input("\nYour call ([P]hish / [S]afe / [H]int): ").strip().lower()
            if choice == "h":
                print(f"HINT: {email['hint']}")
                used_hint = True
            elif choice in ("p", "s"):
                break
            else:
                print("Please enter P, S, or H.")

        guessed_phish = (choice == "p")
        if guessed_phish == email["is_phish"]:
            earned = 50 if used_hint else 100
            total_points += earned
            streak += 1
            print(f"CORRECT! (+{earned} pts)")
        else:
            streak = 0
            print("MISSED! Streak reset.")

        print(f"Why: {email['explanation']}")

    print_header("SHIFT COMPLETE")
    print(f"Final Score: {total_points} / {len(scenarios) * 100}")
    if total_points >= 400:
        print("Rank: Senior Threat Hunter")
    elif total_points >= 250:
        print("Rank: SOC Analyst")
    else:
        print("Rank: Security Trainee - run another shift!")


# --- MODULE 3: PASSWORD ENTROPY AUDITOR ---

def format_crack_time(seconds):
    if seconds < 1:
        return "Instant"
    units = [
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, unit_sec in units:
        if seconds >= unit_sec:
            val = seconds / unit_sec
            if val > 1e9:
                return f"{val:.1e} {name}"
            return f"{val:.1f} {name}"
    return f"{seconds:.1f} seconds"


def audit_password():
    print_header("MODULE 3: PASSWORD ENTROPY AUDITOR")
    pw = input("Enter a test password (do not use your real banking password): ")

    if not pw:
        print("Empty password entered.")
        return

    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 32

    entropy = len(pw) * math.log2(pool) if pool > 0 else 0
    # Assume 10 billion offline guesses/sec (modern GPU rig)
    guesses = 2 ** entropy
    crack_seconds = guesses / 1e10

    tips = []
    if pw.lower() in COMMON_WEAK_PASSWORDS:
        entropy = min(entropy, 10)
        crack_seconds = 0.001
        tips.append("Appears in common leaked password lists.")
    if len(pw) < 12:
        tips.append("Increase length to at least 12-16 characters.")
    if not any(c.isupper() for c in pw) or not any(c.islower() for c in pw):
        tips.append("Mix uppercase and lowercase letters.")
    if not any(c.isdigit() for c in pw):
        tips.append("Add numbers.")
    if not any(not c.isalnum() for c in pw):
        tips.append("Add symbols (e.g., !, @, #, _).")

    strength_score = min(int((entropy / 80) * 100), 100)

    print("\n--- PASSWORD AUDIT ---")
    print(f"Strength Meter : {render_meter(strength_score)}")
    print(f"Entropy        : {entropy:.1f} bits (character pool: {pool})")
    print(f"Est. Crack Time: {format_crack_time(crack_seconds)} (at 10B guesses/sec)")

    if tips:
        print("\nRecommendations:")
        for tip in tips:
            print(f"  * {tip}")
    else:
        print("\nSolid password structure!")


# --- MAIN LOOP ---

def main():
    print_header("PHISHGUARD AI - CYBERSECURITY TOOLKIT")
    ai_status = "ENABLED (Code in Place IDE)" if AI_AVAILABLE else "OFFLINE MODE (Heuristics Only)"
    print(f"AI Forensics: {ai_status}")

    while True:
        print("\nChoose a module:")
        print("  1. Phishing Threat Scanner")
        print("  2. Defend the Inbox (Game)")
        print("  3. Password Entropy Auditor")
        print("  4. Exit")

        choice = input("\nEnter 1-4: ").strip()
        if choice == "1":
            run_scanner()
        elif choice == "2":
            run_inbox_game()
        elif choice == "3":
            audit_password()
        elif choice == "4":
            print("\nStay sharp out there. Exiting PhishGuard AI.")
            break
        else:
            print("Invalid option. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()