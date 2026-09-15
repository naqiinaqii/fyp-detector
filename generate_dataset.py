
import csv
import random

random.seed(42)

# -------------------------
# NORMAL (label 0)
# -------------------------
NORMAL_TEMPLATES = [
    "Hi {name}, are you free {time}?",
    "Reminder: {event} at {time}.",
    "Can you send me the {doc} later?",
    "Thanks for your help with {task}.",
    "See you {day}.",
    "Meeting moved to {day} {time}.",
    "I’ll call you in {mins} minutes.",
    "Please review the {doc} when you can.",
    "Class starts at {time}.",
    "Don’t forget to submit {thing} by {day}.",
    "Happy birthday {name}!",
    "Are we still on for {event}?",
    "I’m on my way, arriving in {mins} mins.",
    "Can we reschedule to {day}?",
    "Receipt: payment of {amount} received. Ref {ref}.",
    "Your order #{ref} has been shipped.",
    "Your parcel is delivered. Thank you.",
    "Let’s meet at {place} {time}.",
    "Please WhatsApp me when you arrive (normal).",
    "Here is the code for the classroom door: {num} (normal).",
]

NAMES = ["Ali", "Aisyah", "Haziq", "Nadia", "Amin", "Siti", "Farah", "Hakim", "Syafiq", "Nur"]
TIMES = ["9am", "10am", "2pm", "3pm", "5pm", "tonight", "tomorrow morning", "this afternoon"]
DAYS = ["today", "tomorrow", "Friday", "Saturday", "next week", "Monday"]
EVENTS = ["presentation", "meeting", "class", "appointment", "group discussion", "consultation"]
DOCS = ["report", "slides", "proposal", "chapter draft", "minutes", "form"]
TASKS = ["the project", "the assignment", "the prototype", "the research", "the survey"]
THINGS = ["your assignment", "the draft", "the survey response", "the slides"]
PLACES = ["library", "campus", "office", "cafe", "lab"]
AMOUNTS = ["$5", "$10", "$25", "$50", "BND 5", "BND 10", "BND 20", "BND 50"]
def make_ref():
    return str(random.randint(100000, 999999))

def make_num():
    return str(random.randint(1000, 999999))

def normal_msg():
    t = random.choice(NORMAL_TEMPLATES)
    return t.format(
        name=random.choice(NAMES),
        time=random.choice(TIMES),
        day=random.choice(DAYS),
        event=random.choice(EVENTS),
        doc=random.choice(DOCS),
        task=random.choice(TASKS),
        thing=random.choice(THINGS),
        place=random.choice(PLACES),
        mins=random.choice([5, 10, 15, 20, 30, 45]),
        amount=random.choice(AMOUNTS),
        ref=make_ref(),
        num=make_num(),
    )

# -------------------------
# SCAM / SOCIAL ENGINEERING (label 1)
# -------------------------
SCAM_INTROS = [
    "This is IT support.",
    "IT Helpdesk here.",
    "Security Team notice.",
    "Bank Security Alert.",
    "Admin Team:",
    "Official Support:",
    "Service Provider Notice:",
    "Account Center:",
]

SCAM_URGENCY = [
    "Immediately",
    "Urgently",
    "Now",
    "ASAP",
    "Within 30 minutes",
    "Within 24 hours",
    "Today only",
]

SCAM_THREATS = [
    "or your account will be deleted",
    "or your account will be suspended",
    "or your account will be locked",
    "to avoid termination",
    "to avoid legal action",
    "to prevent permanent loss",
]

SCAM_ACTIONS = [
    "Confirm your login details",
    "Verify your account",
    "Update your password",
    "Reset your account now",
    "Sign in to verify",
    "Reply with your verification code",
    "Send your OTP code",
    "Provide your PIN",
    "Share your username and password",
    "Install AnyDesk so we can fix it",
    "Install TeamViewer for verification",
    "Click the link to continue",
]

SCAM_PAYMENT = [
    "Pay a small fee to release your parcel",
    "Send money via gift card",
    "Transfer via crypto to confirm",
    "Wire transfer required to avoid cancellation",
    "Pay outstanding balance immediately",
]

SCAM_REWARDS = [
    "Congratulations! You won a prize",
    "You are selected for a reward",
    "Claim your bonus now",
    "Free gift waiting for you",
]

SCAM_OFFPLATFORM = [
    "Message me on WhatsApp to complete verification",
    "Contact me on Telegram now",
    "DM me privately for the verification steps",
]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "rebrand.ly", "cutt.ly", "is.gd"]
PHISH_DOMAINS = [
    "secure-login", "verify-account", "support-check", "login-update", "account-security",
    "bank-secure", "it-helpdesk", "security-alert", "confirm-access"
]
TLDs = [".com", ".net", ".xyz", ".top", ".click", ".info"]

def fake_url():
    kind = random.random()
    if kind < 0.25:
        # shortened
        return f"https://{random.choice(URL_SHORTENERS)}/{make_ref()}"
    elif kind < 0.55:
        # many subdomains
        host = f"login.{random.choice(PHISH_DOMAINS)}.secure.verify{random.choice(TLDs)}"
        return f"https://{host}/auth/{make_ref()}"
    elif kind < 0.75:
        # IP address
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        return f"http://{ip}/verify/{make_ref()}"
    else:
        # punycode-ish
        return f"https://xn--{random.choice(PHISH_DOMAINS)}{random.choice(TLDs)}/login/{make_ref()}"

def scam_msg():
    style = random.random()

    intro = random.choice(SCAM_INTROS)
    urgency = random.choice(SCAM_URGENCY).lower()
    threat = random.choice(SCAM_THREATS)

    # Mix patterns: authority + credential + urgency; payment; reward; offplatform; url
    if style < 0.35:
        action = random.choice(SCAM_ACTIONS)
        # add sensitive target words more often
        sensitive_add = random.choice([
            " with your OTP",
            " with your verification code",
            " and your login details",
            " and your password",
            "",
        ])
        return f"{intro} {action}{sensitive_add} {urgency} {threat}."
    elif style < 0.55:
        pay = random.choice(SCAM_PAYMENT)
        return f"{intro} {pay} {urgency} {threat}. {random.choice(SCAM_ACTIONS)}."
    elif style < 0.70:
        reward = random.choice(SCAM_REWARDS)
        return f"{reward}. {random.choice(SCAM_ACTIONS)} {urgency}. Link: {fake_url()}"
    elif style < 0.85:
        off = random.choice(SCAM_OFFPLATFORM)
        return f"{intro} {off} {urgency} {threat}. Ref: {make_ref()}"
    else:
        # pure link drop
        return f"{intro} Security verification required {urgency}. {fake_url()}"

def build_dataset(n_total=600, scam_ratio=0.5):
    n_scam = int(n_total * scam_ratio)
    n_norm = n_total - n_scam

    rows = []
    for _ in range(n_norm):
        rows.append((normal_msg(), 0))
    for _ in range(n_scam):
        rows.append((scam_msg(), 1))

    random.shuffle(rows)
    return rows

def main():
    rows = build_dataset(n_total=600, scam_ratio=0.5)  # 300 normal, 300 scam
    with open("training_data.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows(rows)

    print("✅ Dataset generated: training_data.csv (600 rows + header)")
    print("Tip: run -> python3 train_model.py")

if __name__ == "__main__":
    main()
