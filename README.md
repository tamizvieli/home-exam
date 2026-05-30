# Malicious Email Scorer
 
**Privacy-first Gmail Add-on for phishing detection using deterministic heuristics**
 
A complete security analysis system that scores emails on a 0-100 maliciousness scale with full explainability and zero data leakage to third-party services.
 
**Developed by:** Tami Zvieli   
 
---
 
##  Project Overview
 
### Privacy-First Philosophy
 
This project implements a **privacy-first, security-first** approach to email security analysis:
 
- **Zero Data Leakage:** No email content is sent to external APIs (LLMs, reputation services, etc.)
- **Deterministic Analysis:** 100% reproducible results using weighted heuristics
- **In-Memory Processing:** All analysis is performed in-memory and discarded after response
- **Static Analysis Only:** No DNS lookups or active checks that could leak metadata
- **Explainable Scoring:** Every point is backed by a specific, documented rule
> **Why this matters:** For security tools, transparency and user trust outweigh marginal accuracy gains from black-box AI models.
 
---
 
## 🏗 Architecture
 
```
┌─────────────────┐
│  Gmail Add-on   │  Frontend (Google Apps Script)
│  Card Service   │  - Extracts email data
└────────┬────────┘  - Sends to Backend API
         │
         │ HTTPS POST /analyze
         ▼
┌─────────────────┐
│ FastAPI Backend │  Backend (Python 3.11)
│                 │  - Text normalization (anti-obfuscation)
│  Scoring Engine │  - 6 weighted rule categories
│  (6 categories) │  - Returns score + explanations
└─────────────────┘
```
 
**Separation of Concerns:**
- **Frontend:** Lightweight data extraction only (Google Apps Script)
- **Backend:** All business logic, scoring, and rule evaluation (FastAPI)
**Deployment:**
- **Production:** Render.com (Frankfurt region for low-latency)
- **API:** https://home-exam-1.onrender.com
---
 
##  The Scoring Engine
 
The engine implements weighted heuristics across six categories. Scores accumulate additively:
 
```
S = min(100, Σ(w_i × I_i))
```
 
Where `w_i` is the weight for rule category `i`, and `I_i` is an indicator (0 or 1) whether the rule triggered.
 
| Category | Max Points | Rationale |
|----------|-----------|-----------|
| **Sender Authentication** | 30 | SPF/DKIM failure = strong spoofing indicator |
| **Domain Spoofing** | 60 | Bad TLD (.tk, .xyz) + free providers (Gmail for corporate impersonation) |
| **Link Manipulation** | 40 | URL shorteners (bit.ly) + display/href mismatch |
| **Social Engineering** | 40 | Direct requests for credentials/payment info |
| **Urgency Language** | 15 | Time-pressure tactics ("act now", "final warning") |
| **Attachment + Urgency** | 10 | Combo bonus (common phishing pattern) |
 
**Threshold Design:**
 
| Range | Risk Level | Color | Rationale |
|-------|------------|-------|-----------|
| 0-39 | Safe | 🟢 Green | Legitimate urgent emails from Gmail can score ~35 |
| 40-74 | Suspicious | 🟠 Orange | Single high-weight rule triggered |
| 75-100 | Dangerous | 🔴 Red | Multiple indicators = high confidence |
 
---
 
## Key Improvements
 
**Deployment:** Local (ngrok) → Production (Render.com) with CI/CD  
**Detection:** 8 → 38 keywords + 9 regex patterns + TextNormalizer for obfuscation  
**Robustness:** 400/500 error handling + privacy-safe logging (only error types)  
**Code Quality:** Full type hints + comprehensive docstrings + centralized config  
 
**Impact:** Test score improved 0 → 55 after normalization on obfuscated text
 
---
 
## Security Mindset
 
### Anti-Obfuscation Layer
 
Attackers frequently use obfuscation to evade keyword detection. **TextNormalizer** implements 6-step preprocessing:
 
1. Remove zero-width characters (U+200B-U+200D, U+FEFF)
2. Remove soft hyphens (U+00AD)
3. Convert homoglyphs (Cyrillic → Latin)
4. Convert leet-speak (`3→e`, `4→a`, `0→o`)
5. Unicode normalization (NFC)
6. Lowercase + whitespace normalization
**Privacy Guarantees:**
- ❌ No external API calls for email content
- ❌ No data storage or logging of sensitive information
- ❌ No DNS lookups (would leak queried domains)
- ✅ All analysis runs in-memory and is discarded after response
---
 
##  Performance
 
**Measured on production (Render.com):**
 
| Operation | Latency | Notes |
|-----------|---------|-------|
| Text normalization | <1ms | Per 10KB email |
| Keyword matching | <1ms | 38 keywords |
| Regex matching | 1-2ms | 9 patterns (ReDoS-safe) |
| HTML parsing | 2-5ms | BeautifulSoup |
| **Full analysis** | **5-10ms** | **End-to-end** |
 
**Comparison:**
- This approach: **5-10ms**
- LLM API call: **200-2000ms** (20-200x slower)
- Local LLM: **50-500ms** (5-50x slower)
**Trade-off:** ~10% lower accuracy (estimated 80-85% vs. 90-95% for LLMs), but 20-200x faster with zero privacy risk and 100% explainability.
 
---
 
##  Example Analysis
 
### Test Case: Maximum Score (All Rules Triggered)
 
**Input:**
```json
{
  "sender": "urgent@phishing.tk",
  "subject": "URGENT: Verify your account NOW!",
  "body_html": "<html><a href='http://bit.ly/fake'>Click here</a></html>",
  "body_text": "Update your password immediately. Final warning!",
  "attachment_extensions": [".exe"],
  "headers": {
    "authentication_results": "spf=fail; dkim=none"
  }
}
```
 
**Expected Output:**
```json
{
  "score": 100,
  "risk_level": "dangerous",
  "verdict": "סכנה - חשד גבוה לפישינג/הונאה",
  "explanations": [
    "זהות השולח לא אומתה (DKIM/SPF)",
    "השולח משתמש בסיומת כתובת חשודה (.tk)",
    "נמצא קיצור כתובת URL חשוד (bit.ly)",
    "זוהתה בקשה חשודה למידע רגיש (password)",
    "זוהתה שפה דחופה ולוחצת",
    "שילוב חשוד של קובץ מצורף ושפה דחופה"
  ]
}
```
 
**Rules Triggered:**
-  SPF/DKIM fail (30 pts)
-  Bad TLD .tk (40 pts)
-  URL shortener (20 pts)
-  Social engineering "password" (40 pts)
-  Urgency keywords (15 pts)
-  Attachment + urgency combo (10 pts)
- **Total:** 155 → **Capped at 100**
---
 
##  Limitations & Future Work
 
### Current Limitations
 
1. **Static Heuristics:** The system relies on predefined dictionaries and regex patterns. While highly performant and private, it requires manual updates to catch entirely new "zero-day" phrasing.
2. **Attachment Scanning:** To maintain strict privacy and performance, attachments are currently analyzed by their extensions alone, without deep-scanning the file contents.
### Future Enhancements (Given More Time)
 
1. **Hybrid LLM Fallback:** Introduce a secondary, *opt-in* pipeline where only emails scoring in the "suspicious" threshold (40-74) are sent to an LLM for semantic analysis, balancing cost/privacy with accuracy.
2. **Feedback Loop:** Add a "Report False Positive" button in the Gmail UI to dynamically adjust weights based on user corrections.
3. **Multi-Language Support:** Expand the urgency and social engineering dictionaries (currently optimized for English) to natively support Hebrew and other languages.
---
 
##  How to Use (End User)
 
Once the add-on is installed:
 
1. **Open any email** in Gmail
2. **Click the add-on icon** in the right sidebar (🛡️ shield icon)
3. **Click "🔍 Analyze Email"** button
4. **View results** (appears within 2-5 seconds):
   - Risk score (0-100)
   - Risk level (Safe/Suspicious/Dangerous) with color indicator
   - Detailed explanations in Hebrew
**Example result:**
```
✅ תוצאות ניתוח אבטחה
ציון סיכון: 75/100 🔴
רמת סיכון: מסוכן
פסק דין: סכנה - חשד גבוה לפישינג/הונאה
 
הסברים מפורטים:
• זוהתה בקשה חשודה למידע רגיש
• נמצא קיצור כתובת URL חשוד
• זוהתה שפה דחופה ולוחצת
```
 
---
 
## installation & Setup
 
### Prerequisites
 
- Python 3.11+
- Google account (for Gmail Add-on deployment)
- GitHub account (optional, for deployment)
### Backend Setup
 
**1. Clone the repository:**
```bash
git clone https://github.com/tamizvieli/home-exam.git
cd home-exam/backend
```
 
**2. Install dependencies:**
```bash
pip install -r requirements.txt
```
 
**3. Run locally:**
```bash
uvicorn app.main:app --reload --port 8000
```
 
**4. Verify:**
- Open: http://localhost:8000/docs (Swagger UI)
- Test the POST /analyze endpoint
---
 
### Frontend Setup (Gmail Add-on)
 
**1. Create Apps Script project:**
- Navigate to: https://script.google.com
- New Project → Name: "Malicious Email Scorer"
**2. Add code:**
- Copy contents of `frontend/Code.gs`
- Enable "Show appsscript.json" in settings
- Copy contents of `frontend/appsscript.json`
**3. Configure Backend URL:**
```javascript
// In Code.gs, line 9:
const API_BASE_URL = 'https://home-exam-1.onrender.com';  // Production
// Or for local testing:
// const API_BASE_URL = 'http://localhost:8000';  // Requires ngrok
```
 
**4. Deploy:**
- Deploy → Test deployments → Install (Gmail add-on)
- Open Gmail → Open any email → Click add-on icon → "Analyze Email"
---
 
### Production Deployment (Render.com)
 
**Option A: Automatic (via render.yaml):**
1. Push code to GitHub
2. Connect Render.com to repository
3. Render auto-detects `render.yaml`
4. Click "Create Web Service"
**Option B: Manual:**
1. New Web Service → Connect Git repository
2. Settings:
   - **Root Directory:** (empty)
   - **Build Command:** `cd backend && pip install -r requirements.txt`
   - **Start Command:** `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Environment Variable:** `PYTHON_VERSION=3.11.9`
---
## 📁 Project Structure
 
```
├── README.md                    # This file
├── runtime.txt                  # Python version (3.11.9)
├── .gitignore                   # Git exclusions
│
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI routes, CORS, error handling
│   │   ├── models.py            # Pydantic schemas (request/response)
│   │   ├── config.py            # Weights, keywords, thresholds
│   │   ├── text_normalizer.py  # Anti-obfuscation preprocessing
│   │   └── scoring_engine.py   # Core rules engine (6 categories)
│   ├── requirements.txt         # Python dependencies
│   └── .gitignore               # Backend-specific exclusions
│
└── frontend/
    ├── Code.gs                  # Apps Script main logic
    └── appsscript.json          # Manifest & OAuth scopes
```
---
**Live Demo:**
- Backend API: https://home-exam-1.onrender.com/docs
- GitHub Repository: https://github.com/tamizvieli/malicious-Email-Scorer
---
 
