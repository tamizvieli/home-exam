"""
Configuration constants for the Malicious Email Scorer backend.
All scoring weights and thresholds are defined here per the specification.
"""

# Scoring weights per category (max points)
WEIGHTS = {
    "sender_authentication": 30,
    "domain_spoofing_bad_tld": 40,
    "domain_spoofing_free_provider": 20,
    "link_manipulation_per_link": 20,
    "link_manipulation_max": 40,  # Category ceiling
    "social_engineering": 40,
    "urgency_language": 15,
    "attachment_with_urgency": 10,  # Bonus for attachments + urgency combo
}

# Bad TLDs that indicate potential spoofing
BAD_TLDS = [".tk", ".xyz", ".ml", ".ga", ".cf", ".gq"]

# Free email providers (non-corporate)
FREE_PROVIDERS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "mail.ru"]

# URL shortener domains
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "short.link"]

# Social engineering keywords (case-insensitive, will be applied on normalized text)
SOCIAL_ENGINEERING_KEYWORDS = [
    "password",
    "credit card",
    "bank account",
    "wire transfer",
    "social security",
    "ssn",
    "verify your account",
    "confirm your identity",
    "update payment",
    "update billing",
    "payment method",
    "account details",
    "personal information",
    "security question",
]

# Urgency language keywords (case-insensitive, will be applied on normalized text)
# Expanded to catch common variations and synonyms
URGENCY_KEYWORDS = [
    "urgent",
    "urgently",
    "urgency",
    "act now",
    "asap",
    "quickly",
    "hurry",
    "immediate",
    "immediately",
    "immediate action",
    "account suspended",
    "suspended account",
    "locked account",
    "account locked",
    "blocked account",
    "disabled account",
    "verify immediately",
    "confirm now",
    "respond now",
    "click now",
    "act immediately",
    "limited time",
    "expire",
    "expires",
    "expiring",
    "expired",
    "expiration",
    "within 24 hours",
    "within 48 hours",
    "time sensitive",
    "final notice",
    "last chance",
    "last warning",
    "final warning",
    "final reminder",
    "dont wait",
    "do not delay",
    "dont delay",
    "critical",
    "emergency",
    "action required",
    "response required",
    "attention required",
]

# Regex patterns for urgency detection (flexible matching on normalized text)
# These patterns catch common phishing phrases even with word variations
URGENCY_PATTERNS = [
    r'\b(act|respond|click|verify|confirm)\s+(now|immediately|today|asap)\b',
    r'\baccount\s+(suspended|locked|frozen|blocked|disabled|closed)\b',
    r'\bwithin\s+\d+\s+(hours?|days?|minutes?)\b',
    r'\b(urgent|immediate|critical)\s+(action|attention|response|notice)\b',
    r'\bfinal\s+(notice|warning|reminder|chance)\b',
    r'\btime\s+(sensitive|critical|limited)\b',
    r'\blast\s+(chance|warning|notice|reminder)\b',
    r'\baction\s+required\b',
    r'\bresponse\s+required\b',
]

# Risk level thresholds
THRESHOLDS = {
    "safe": (0, 39),
    "suspicious": (40, 74),
    "dangerous": (75, 100),
}

# Verdict messages (Hebrew, per specification)
VERDICTS = {
    "safe": "נראה תקין",
    "suspicious": "חשד בינוני - יש לנקוט זהירות",
    "dangerous": "סכנה - חשד גבוה לפישינג/הונאה",
}

# Explanation templates (Hebrew, per specification)
EXPLANATIONS = {
    "sender_auth_fail": "זהות השולח לא אומתה (DKIM/SPF). ייתכן שמדובר בזיוף.",
    "domain_spoofing": "השולח משתמש בסיומת כתובת או ספק חינמי שאינם אופייניים לתקשורת עסקית רשמית.",
    "link_manipulation": "זוהו קישורים מוסווים או מקוצרים המפנים לאתרים שונים מהמוצג.",
    "social_engineering": "ההודעה מכילה בקשה חריגה למסירת פרטים אישיים, הרשאות או פעולה פיננסית.",
    "urgency_language": "שימוש בשפה המייצרת תחושת דחיפות מזויפת לפעולה מיידית.",
    "attachment_with_urgency": "שילוב של קבצים מצורפים עם שפת דחיפות מעלה את רמת החשד.",
}