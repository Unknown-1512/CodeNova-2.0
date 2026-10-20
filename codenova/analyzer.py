"""CodeNova 2.0 - pure-Python scam / spam forensics engine.

Pipeline
    1. scikit-learn TF-IDF (word + char n-grams) + Logistic Regression  -> ML probability
    2. Linguistic & URL rule engine (regex red-flag phrases)            -> rule probability
    3. Blend both, calibrate confidence, classify scam type, highlight phrases
    4. Images: Tesseract OCR (pytesseract) + QR decoding (pyzbar / OpenCV)
"""
import html
import re
import time

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

# --------------------------------------------------------------------------
# 1. Training corpus (small built-in seed set; extend it with your own data)
# --------------------------------------------------------------------------
SCAM_SAMPLES = [
    "USPS: Your package could not be delivered due to an unpaid redelivery fee of $1.99. Pay now at usps-redeliver.top/pay or it will be returned.",
    "CONGRATULATIONS! I am Sarah from Indeed Recruiting. Work 30 mins daily liking YouTube & TikTok videos and earn $450-$750/day paid instantly via USDT! Zero experience needed. Message WhatsApp +14155550148 right now!",
    "Your crypto wallet has been flagged. Verify now by entering your 12 word seed phrase at wallet-secure.xyz to avoid permanent loss of funds.",
    "URGENT: Your bank account will be suspended within 24 hours. Verify your identity and confirm your OTP at http://sbi-verify.click/login",
    "You have won a $1000 Amazon gift card! Claim your prize now before it expires: bit.ly/3xFreeGift",
    "Earn $300 per day working from home. No experience required. Telegram us now to start. Guaranteed income!",
    "Dear customer, your KYC has expired. Update immediately or your account will be blocked: tinyurl.com/kyc-update-now",
    "Final notice: you have an unpaid toll balance. Pay a small fee today to avoid a penalty and legal action: toll-pay.info/us",
    "Hi, I'm Emma from LinkedIn HR. We have a part-time job rating hotels, earn $200-$500 daily. Contact us on WhatsApp +447700900123 for details.",
    "Your Netflix subscription is on hold. Update your payment details now at netflix-billing.live to avoid cancellation.",
    "Congratulations, you've been selected as the lucky winner of our lottery! Send your bank details and processing fee to claim $50,000.",
    "Airdrop alert! Connect your wallet and share your private key to claim 5 ETH free bitcoin giveaway. Limited time only!",
    "Your parcel is held at customs. Pay the customs charge of $2.50 immediately: dhl-customs-fee.shop",
    "We noticed suspicious login on your account. Sign in to confirm your password and CVV right now: secure-apple-id.top",
    "Make money online! Like videos and get paid in USDT daily. Join our Telegram group, zero investment, instant withdrawal.",
    "IRS NOTICE: You owe back taxes. Pay immediately via gift card or face arrest. Call +18885550199 now.",
    "Hello dear, I have a business proposal worth $4.5 million. Reply with your account number to receive your share, urgent and confidential.",
    "Your Amazon order #8832 was declined. Verify your account within 12 hours: amzn-verify.click/order",
    "Hiring now! Easy task job, rate products and earn $150/hour. Message WhatsApp immediately, limited slots, paid instantly.",
    "Your SIM will be blocked today. Share the OTP sent to your phone to complete verification urgently.",
    "Free iPhone 15 winner! Click here to claim your reward before midnight: cutt.ly/winiphone",
    "Dear user, your PayPal account is limited. Confirm your details and login now to restore access: paypal-resolve.xyz",
    "Claim your crypto recovery refund. Enter your recovery phrase to receive unclaimed USDT immediately.",
    "Your HDFC credit card reward points expire today! Redeem now: hdfc-rewards.top/claim. Act now!",
]

HAM_SAMPLES = [
    "Hey, are we still on for dinner tonight at 8? I was thinking that Italian place near the station.",
    "Your verification code is 482913. Do not share this code with anyone. It expires in 10 minutes.",
    "Hi Mom, I reached home safely. Will call you after I finish dinner.",
    "Reminder: your dentist appointment is tomorrow at 10:30 AM. Reply C to confirm.",
    "Can you send me the meeting notes from yesterday? I want to review them before the standup.",
    "Thanks for your payment. Your electricity bill for September has been received. Receipt available in the app.",
    "Happy birthday! Hope you have an amazing day. Let's catch up this weekend.",
    "The project deadline has moved to Friday. Please update the document and share it with the team.",
    "Your Uber is arriving in 3 minutes. Look for a white Toyota Innova.",
    "Don't forget to bring the laptop charger tomorrow. Also, the movie starts at 6.",
    "Your order has shipped and will arrive on Thursday. Track it in the official app anytime.",
    "I'll be a few minutes late, traffic is heavy near the bridge. Start without me.",
    "Class notes are uploaded to the portal. The exam is next Monday, good luck everyone.",
    "Lunch at the canteen? I'm free after the 1 PM call.",
    "Your monthly statement is ready. Log in through the official app to view it.",
    "Can we reschedule our call to 4 PM? Something came up at work.",
    "Dinner plans: I booked a table for four at 7:30. Let me know if anyone is allergic to anything.",
    "Great job on the presentation today! The client really liked the demo.",
    "Please find the invoice attached for the consulting work done in October.",
    "Mom says the family function is on Sunday. Can you come with us?",
    "Your flight is on time. Check-in opens 3 hours before departure at the airline counter.",
    "Just landed. Heading to the hotel now, will text you when I get settled.",
]


def _build_model():
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, lowercase=True, min_df=1)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), sublinear_tf=True, lowercase=True)),
    ])
    model = Pipeline([
        ("tfidf", features),
        ("clf", LogisticRegression(C=8.0, max_iter=1000, class_weight="balanced")),
    ])
    X = SCAM_SAMPLES + HAM_SAMPLES
    y = [1] * len(SCAM_SAMPLES) + [0] * len(HAM_SAMPLES)
    model.fit(X, y)
    return model


_MODEL = None


def get_model():
    global _MODEL
    if _MODEL is None:
        _MODEL = _build_model()
    return _MODEL


# --------------------------------------------------------------------------
# 2. Linguistic & URL rules
# --------------------------------------------------------------------------
# (name, category, weight, regex, flags, explanation)
RULES = [
    ("Unrealistic income promise", "employment", 0.40,
     r"(\$\s?\d[\d,]*(\s?[-–]\s?\$?\d[\d,]*)?\s?(/|per|a)\s?(day|hour|week|month|daily))"
     r"|earn\s+\$?\d[\d,]*|guaranteed (income|returns?)|zero experience|no experience (needed|required)"
     r"|work from home|paid instantly|zero investment|instant withdrawal", re.I,
     "Promises large, fast earnings with no skills or investment - the hallmark of fake job offers."),
    ("Fake 'task' job pattern", "employment", 0.35,
     r"\b(liking|rating|reviewing|subscrib\w+)\b.{0,40}\b(youtube|tiktok|videos?|products?|hotels?)\b"
     r"|\bpart[- ]time job\b|\beasy task\b|\bhiring now\b|\brecruit(er|ing|ment)\b", re.I,
     "Pays money for trivial online tasks, then asks for deposits later (task scam)."),
    ("Off-platform chat push", "employment", 0.28,
     r"\b(whatsapp|telegram|signal)\b|wa\.me/\S*|t\.me/\S*", re.I,
     "Moves the conversation to a private messenger where scammers avoid platform moderation."),
    ("Phone number bait", "generic", 0.10,
     r"\+\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}", 0,
     "Unsolicited phone number inviting contact outside official channels."),
    ("Crypto payment / wallet lure", "crypto", 0.32,
     r"\b(usdt|bitcoin|btc|ethereum|eth|crypto(currency)?|wallet|airdrop|giveaway)\b", re.I,
     "Requests or promises crypto - irreversible and untraceable, preferred by fraudsters."),
    ("Seed phrase / private key request", "crypto", 0.60,
     r"\b(seed|recovery) phrase\b|\bprivate key\b|\b12[- ]word\b", re.I,
     "Anyone asking for your seed phrase or private key is stealing your wallet. No legitimate service asks."),
    ("Credential / OTP harvesting", "phishing", 0.38,
     r"\b(otp|one[- ]time (password|code)|cvv|password|verify your (account|identity)|confirm your (details|account|password)"
     r"|sign in|login|kyc|account number|bank details|payment details)\b", re.I,
     "Tries to get you to hand over codes, passwords or financial details."),
    ("Delivery / customs fee demand", "parcel", 0.42,
     r"\b(redelivery|customs|delivery|shipping|release|processing|handling)\s+(fee|charge)s?\b"
     r"|\bunpaid\s+(fee|toll|balance)\b|\bpay (a )?(small )?fee\b|\bpackage could not be delivered\b|\bparcel is held\b", re.I,
     "Demands a small fee for a parcel/toll - a classic smishing hook to capture card details."),
    ("Delivery brand impersonation", "parcel", 0.14,
     r"\b(usps|fedex|dhl|ups|royal mail|india post|package|parcel)\b", re.I,
     "Name-drops a courier to appear legitimate."),
    ("Prize / lottery bait", "prize", 0.36,
     r"\b(congratulations|you('ve| have) (won|been selected)|lucky winner|winner|lottery|prize|claim your|gift card|free (iphone|gift)|reward)\b", re.I,
     "Claims you won something you never entered for."),
    ("False urgency / pressure", "generic", 0.28,
     r"\b(urgent(ly)?|immediately|right now|act now|last chance|limited (time|slots)|final notice|expires? (today|soon)|within \d+ (hours?|minutes?)|before midnight|today!)\b", re.I,
     "Creates time pressure so you act before thinking."),
    ("Threat / account suspension", "phishing", 0.36,
     r"account (will be |has been )?(suspended|blocked|locked|closed|limited)|\bon hold\b|legal action|\barrest\b|\bpenalty\b|\bflagged\b", re.I,
     "Threatens negative consequences to force compliance."),
    ("Brand impersonation", "generic", 0.10,
     r"\b(indeed|linkedin|amazon|paypal|hdfc|sbi|icici|netflix|apple|microsoft|irs|bank)\b", re.I,
     "Mentions a trusted brand - verify through the brand's official app/site instead."),
    ("Shouting / excessive caps", "generic", 0.08,
     r"\b[A-Z]{6,}\b!*", 0,
     "ALL-CAPS words are used to grab attention and add urgency."),
    ("Suspicious TLD / link", "generic", 0.32,
     r"(https?://\S+|www\.\S+|\b[\w-]+\.(xyz|top|click|link|info|shop|live|icu|cc)\b(/\S*)?)", re.I,
     "Contains a link on a domain commonly abused by scammers."),
    ("URL shortener", "generic", 0.45,
     r"\b(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|goo\.gl)/\S+", re.I,
     "Shortened link hides the real destination."),
]

LINK_RE = re.compile(r"(https?://\S+|www\.\S+|\b[\w-]+\.(?:xyz|top|click|link|info|shop|live|icu|cc|com|net|org)\b/\S*|\b(?:bit\.ly|tinyurl\.com|cutt\.ly)/\S+)", re.I)

CATEGORY_LABELS = {
    "employment": "Task & Fake Employment Scam",
    "parcel": "Parcel / Delivery Fee Smishing",
    "crypto": "Crypto Wallet / Seed Phrase Scam",
    "phishing": "Phishing / Credential Theft",
    "prize": "Prize / Lottery Scam",
    "generic": "Suspicious Social-Engineering Message",
}


def _severity(weight):
    if weight >= 0.35:
        return "critical"
    if weight >= 0.25:
        return "high"
    return "medium"


def _merge_spans(spans):
    spans = sorted(spans, key=lambda s: (s[0], -(s[1] - s[0])))
    merged = []
    for start, end, sev in spans:
        if merged and start < merged[-1][1]:
            prev = merged[-1]
            order = {"medium": 0, "high": 1, "critical": 2}
            if order[sev] > order[prev[2]]:
                prev[2] = sev
            prev[1] = max(prev[1], end)
        else:
            merged.append([start, end, sev])
    return merged


def _highlight(text, spans):
    out, pos = [], 0
    for start, end, sev in _merge_spans(spans):
        out.append(html.escape(text[pos:start]))
        out.append(f'<mark class="hl hl-{sev}">{html.escape(text[start:end])}</mark>')
        pos = end
    out.append(html.escape(text[pos:]))
    return "".join(out).replace("\n", "<br>")


# --------------------------------------------------------------------------
# 3. Main analysis
# --------------------------------------------------------------------------
def analyze(text, qr_payloads=None, context=""):
    t0 = time.perf_counter()
    qr_payloads = qr_payloads or []
    scanned = text.strip()
    for payload in qr_payloads:
        scanned += f"\nQR CODE: {payload}"

    if not scanned:
        raise ValueError("No readable text to analyze.")

    ml_prob = float(get_model().predict_proba([scanned])[0][1])

    triggers, spans, miss_prob = [], [], 1.0
    cat_weight = {}
    for name, cat, weight, pattern, flags, why in RULES:
        matches = list(re.finditer(pattern, scanned, flags))
        if not matches:
            continue
        sev = _severity(weight)
        phrases = []
        for m in matches:
            spans.append((m.start(), m.end(), sev))
            p = m.group(0).strip()
            if p and p not in phrases:
                phrases.append(p)
        miss_prob *= (1 - weight)
        cat_weight[cat] = cat_weight.get(cat, 0) + weight
        triggers.append({"name": name, "severity": sev, "weight": weight,
                         "phrases": phrases[:4], "why": why, "category": cat})

    if qr_payloads:
        weight = 0.50
        miss_prob *= (1 - weight)
        cat_weight["phishing"] = cat_weight.get("phishing", 0) + weight
        for payload in qr_payloads:
            idx = scanned.find(payload)
            if idx >= 0:
                spans.append((idx, idx + len(payload), "critical"))
        triggers.append({"name": "Hidden QR code destination", "severity": "critical", "weight": weight,
                         "phrases": qr_payloads[:3],
                         "why": "A QR code hides its destination from the eye; scam QR codes lead to phishing or payment pages.",
                         "category": "phishing"})

    if context and re.search(r"\b(unknown|unsolicited|stranger|unexpected|random|didn'?t (ask|request|order)|never (ordered|applied|signed))\b", context, re.I):
        weight = 0.15
        miss_prob *= (1 - weight)
        triggers.append({"name": "Unsolicited sender (your context)", "severity": "medium", "weight": weight,
                         "phrases": [context[:80]],
                         "why": "You reported this came from an unknown or unexpected sender - a strong real-world scam signal.",
                         "category": "generic"})

    rule_prob = min(0.99, 1 - miss_prob)
    final = 0.55 * ml_prob + 0.45 * rule_prob
    if rule_prob > 0.85 and ml_prob > 0.6:
        final = max(final, 0.9 * max(ml_prob, rule_prob))
    if not triggers:
        final = min(final, 0.25)
    final = max(0.01, min(0.995, final))

    agreement = 1 - abs(ml_prob - rule_prob)
    confidence = 0.6 * agreement + 0.4 * abs(final - 0.5) * 2
    confidence = max(0.5, min(0.99, confidence))

    score = round(final * 100, 1)
    if score >= 75:
        risk, risk_class = "CRITICAL SCAM RISK", "critical"
    elif score >= 50:
        risk, risk_class = "HIGH SCAM RISK", "high"
    elif score >= 30:
        risk, risk_class = "SUSPICIOUS - REVIEW", "medium"
    else:
        risk, risk_class = "LIKELY SAFE", "safe"

    if score < 30:
        category = "Likely Legitimate Message"
    else:
        scam_cats = {k: v for k, v in cat_weight.items() if k != "generic"} or cat_weight
        top = max(scam_cats, key=scam_cats.get) if scam_cats else "generic"
        category = CATEGORY_LABELS[top]

    triggers.sort(key=lambda t: -t["weight"])
    links = [m.group(0) for m in LINK_RE.finditer(scanned)]
    red_flags = len([t for t in triggers if t["severity"] in ("critical", "high")])
    tokens = len(re.findall(r"\S+", scanned))

    summary = _summary(score, ml_prob, category, triggers, len(links), tokens)

    return {
        "score": score,
        "ml": round(ml_prob * 100, 1),
        "rules": round(rule_prob * 100, 1),
        "confidence": round(confidence * 100, 1),
        "tokens": tokens,
        "risk": risk,
        "risk_class": risk_class,
        "category": category,
        "triggers": triggers,
        "trigger_count": len(triggers),
        "red_flags": red_flags,
        "links": len(links),
        "highlighted": _highlight(scanned, spans),
        "summary": summary,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
    }


def _summary(score, ml_prob, category, triggers, links, tokens):
    if score < 30:
        return (f"Python forensic analysis rates this message at {score}% spam/scam probability. "
                f"The statistical model ({ml_prob*100:.1f}% ML confidence) found conversational wording and "
                f"{len(triggers)} weak manipulation signal(s). It looks like a normal, safe message - "
                "still, never share OTPs or passwords with anyone who asks.")
    names = ", ".join(t["name"].lower() for t in triggers[:4])
    return (f"Python forensic analysis rates this submitted message at {score}% spam/scam probability "
            f"({category}). The content combines statistical spam phrasing ({ml_prob*100:.1f}% ML confidence) "
            f"with {len(triggers)} concrete manipulation trigger(s) engineered to extract credentials, money, or clicks: "
            f"{names}. It contains {links} link(s) across {tokens} scanned words. Do not reply, click, "
            "pay, or share codes - report and delete it.")


# --------------------------------------------------------------------------
# 4. Image input: OCR + QR   (works with Tesseract OR pip-only RapidOCR;
#    QR decoding works with OpenCV (pip-only) OR pyzbar)
# --------------------------------------------------------------------------
import io
import os
import shutil

_TESS_READY = None
_RAPID = None


def _tesseract_ok():
    """True when pytesseract AND the Tesseract program are both usable."""
    global _TESS_READY
    if _TESS_READY is None:
        try:
            import pytesseract
            cmd = os.environ.get("TESSERACT_CMD")
            if not cmd and not shutil.which("tesseract"):
                for p in (r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                          r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                          "/opt/homebrew/bin/tesseract", "/usr/local/bin/tesseract"):
                    if os.path.exists(p):
                        cmd = p
                        break
            if cmd:
                pytesseract.pytesseract.tesseract_cmd = cmd
            pytesseract.get_tesseract_version()
            _TESS_READY = True
        except Exception:
            _TESS_READY = False
    return _TESS_READY


def _rapid_engine():
    global _RAPID
    if _RAPID is None:
        try:
            from rapidocr_onnxruntime import RapidOCR
            _RAPID = RapidOCR()
        except Exception:
            _RAPID = False
    return _RAPID


def _alnum(s):
    return sum(ch.isalnum() for ch in s)


def _clean_ocr(text):
    lines = []
    for ln in text.replace("\r", "").split("\n"):
        ln = re.sub(r"[ \t]+", " ", ln).strip()
        if _alnum(ln) >= 2 and "test sample" not in ln.lower():
            lines.append(ln)
    return "\n".join(lines)


def _ocr_variants(img):
    """Pre-processed copies of the image: upscaled, high contrast, and
    colour-inverted when the screenshot is a dark-mode UI."""
    from PIL import ImageOps, ImageStat
    gray = ImageOps.grayscale(img)
    if gray.width < 1400:
        scale = min(3.0, 1400 / gray.width)
        gray = gray.resize((int(gray.width * scale), int(gray.height * scale)))
    dark = ImageStat.Stat(gray).mean[0] < 110
    variants = []
    if dark:
        variants.append(("dark-ui", ImageOps.autocontrast(ImageOps.invert(gray))))
    variants.append(("light-ui", ImageOps.autocontrast(gray)))
    if not dark:
        variants.append(("inverted", ImageOps.autocontrast(ImageOps.invert(gray))))
    return variants


def _ocr_tesseract(img):
    import pytesseract
    best, best_n = "", 0
    for _name, v in _ocr_variants(img):
        for psm in (6, 11):
            try:
                txt = pytesseract.image_to_string(v, config=f"--psm {psm}")
            except Exception:
                continue
            n = _alnum(txt)
            if n > best_n:
                best, best_n = txt, n
        if best_n >= 40:
            break
    return _clean_ocr(best)


def _ocr_rapid(img):
    import numpy as np
    engine = _rapid_engine()
    if not engine:
        return ""
    result, _ = engine(np.array(img.convert("RGB")))
    if not result:
        return ""
    rows = sorted(result, key=lambda r: (round(r[0][0][1] / 12), r[0][0][0]))
    return _clean_ocr("\n".join(r[1] for r in rows))


def ocr_image(img):
    """Return (text, engine_name). Tries Tesseract, then RapidOCR."""
    text, engine = "", None
    if _tesseract_ok():
        text, engine = _ocr_tesseract(img), "Tesseract OCR"
    if _alnum(text) < 15 and _rapid_engine():
        alt = _ocr_rapid(img)
        if _alnum(alt) > _alnum(text):
            text, engine = alt, "RapidOCR (ONNX)"
    return text, engine


def decode_qr(img):
    """Return a list of QR payload strings found anywhere in the image."""
    import numpy as np
    from PIL import ImageOps

    payloads = []

    def add(value):
        value = (value or "").strip()
        if value and value not in payloads:
            payloads.append(value)

    try:  # pyzbar (needs the zbar library)
        from pyzbar.pyzbar import decode
        for im in (img, ImageOps.invert(img.convert("L"))):
            for d in decode(im):
                add(d.data.decode("utf-8", "ignore"))
    except Exception:
        pass

    if not payloads:
        try:  # OpenCV - pip-only, no system install
            import cv2
            bgr = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2BGR)
            gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
            candidates = [bgr, gray,
                          cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC),
                          cv2.bitwise_not(gray),
                          cv2.resize(gray, None, fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA)]
            det = cv2.QRCodeDetector()
            for c in candidates:
                try:
                    ok, decoded, _pts, _ = det.detectAndDecodeMulti(c)
                    if ok:
                        for d in decoded:
                            add(d)
                except Exception:
                    pass
                if not payloads:
                    try:
                        data, _p, _s = det.detectAndDecode(c)
                        add(data)
                    except Exception:
                        pass
                if payloads:
                    break
        except Exception:
            pass
    return payloads


def extract_from_image(source):
    """source: bytes, file-like object or path.
    Returns (ocr_text, qr_payloads, warnings, engine_name)."""
    from PIL import Image

    warnings = []
    if isinstance(source, (bytes, bytearray)):
        source = io.BytesIO(source)
    elif hasattr(source, "stream"):  # werkzeug FileStorage
        source = source.stream
    img = Image.open(source).convert("RGB")

    text, engine = ocr_image(img)
    if engine is None:
        warnings.append("No OCR engine found. Install Tesseract, or run: pip install rapidocr-onnxruntime")

    payloads = decode_qr(img)
    return text, payloads, warnings, engine
