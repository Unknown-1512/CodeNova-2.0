"""CodeNova 2.0 - Scam Message & Image Spam Percentage Forensics Dashboard (Flask)."""
import io
import json
import platform
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, url_for

import analyzer
from samples import SAMPLES, SAMPLE_BY_ID

BASE = Path(__file__).parent
DB_PATH = BASE / "codenova.db"
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB uploads
UPLOAD_DIR = BASE / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}

QUICK_FILLS = [
    {"label": "USPS Smishing Fee SMS", "kind": "scam",
     "text": "USPS: Your package could not be delivered due to an unpaid redelivery fee of $1.99. "
             "Pay now at usps-redeliver.top/pay within 24 hours or it will be returned to sender."},
    {"label": "WhatsApp $750/Day Job", "kind": "scam",
     "text": "CONGRATULATIONS! I am Sarah from Indeed Recruiting. Work 30 mins daily liking YouTube & TikTok "
             "videos and earn $450-$750/day paid instantly via USDT! Zero experience needed. "
             "Message WhatsApp +14155550148 right now!"},
    {"label": "Crypto Wallet Seed Trap", "kind": "scam",
     "text": "ALERT: Your crypto wallet has been flagged. Verify now by entering your 12 word seed phrase "
             "at wallet-secure.xyz to avoid permanent loss of funds."},
    {"label": "Dinner Plans Message", "kind": "safe",
     "text": "Hey, are we still on for dinner tonight at 8? I booked a table at that Italian place near the "
             "station. Let me know if anyone is allergic to anything."},
]


@app.context_processor
def inject_asset_version():
    css = BASE / "static" / "style.css"
    return {"asset_v": int(css.stat().st_mtime)}


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   created TEXT, label TEXT, mode TEXT, title TEXT,
                   score REAL, risk_class TEXT, category TEXT, result TEXT)"""
        )
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def stats():
    rows = get_db().execute("SELECT mode, score FROM scans").fetchall()
    total = len(rows)
    text_n = sum(1 for r in rows if r["mode"] == "text")
    flagged = sum(1 for r in rows if r["score"] >= 50)
    mean = round(sum(r["score"] for r in rows) / total, 1) if total else 0.0
    return {"total": total, "text": text_n, "image": total - text_n,
            "flagged": flagged, "mean": mean, "safe": total - flagged}


# ------------------------------------------------------------------ routes
def render_dashboard(result=None, **extra):
    s = stats()
    return render_template("index.html", stats=s, history_count=s["total"], result=result,
                           quick_fills=QUICK_FILLS, samples=SAMPLES, py_version=platform.python_version(), **extra)


@app.route("/")
def index():
    return render_dashboard()


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    row = get_db().execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return redirect(url_for("index"))
    result = json.loads(row["result"])
    result.update(title=row["title"], created=row["created"], label=row["label"],
                  mode=row["mode"], id=row["id"])
    return render_dashboard(result, selected_mode=row["mode"])


@app.errorhandler(413)
def too_large(_e):
    return render_dashboard(error="That file is larger than 10 MB. Please choose a smaller image.",
                            selected_mode="image"), 413


@app.route("/scan", methods=["POST"])
def scan():
    mode = request.form.get("mode", "text")
    label = request.form.get("label", "").strip()[:80]
    warnings, qr, text, engine, image_url = [], [], "", None, None

    try:
        if mode == "image":
            file = request.files.get("image")
            sample = SAMPLE_BY_ID.get(request.form.get("sample", ""))
            if file and file.filename:
                ext = Path(file.filename).suffix.lower()
                if ext not in ALLOWED_EXT:
                    return render_dashboard(error="Unsupported file type. Please upload a PNG, JPG or WEBP image.",
                                            selected_mode="image")
                data = file.read()
                name = f"{uuid.uuid4().hex[:12]}{ext}"
                (UPLOAD_DIR / name).write_bytes(data)
                image_url = url_for("static", filename=f"uploads/{name}")
                text, qr, warnings, engine = analyzer.extract_from_image(io.BytesIO(data))
            elif sample:
                path = BASE / "static" / "samples" / sample["file"]
                image_url = url_for("static", filename=f"samples/{sample['file']}")
                text, qr, warnings, engine = analyzer.extract_from_image(path)
                if not text:  # no OCR engine installed: use the sample's transcript
                    text, qr = sample["text"], (qr or list(sample["qr"]))
                    engine = "Built-in sample transcript"
                    warnings.append("No OCR engine is installed, so this sample used its stored transcript. "
                                    "Install Tesseract or run: pip install rapidocr-onnxruntime")
            else:
                return render_dashboard(error="Please choose an image, drop a screenshot, or pick a sample.",
                                        selected_mode="image")
            if not text and not qr:
                return render_dashboard(
                    error="No text or QR code could be read from that image. " + " ".join(warnings),
                    selected_mode="image")
        else:
            text = request.form.get("message", "").strip()
            if not text:
                return render_dashboard(error="Please paste a message to scan.", selected_mode="text")

        context = request.form.get("context", "").strip()[:200] if mode == "image" else ""
        result = analyzer.analyze(text, qr, context)
    except Exception as exc:  # corrupt image etc.
        return render_dashboard(error=f"Could not analyze input: {exc}", selected_mode=mode)

    first_line = (text or (qr[0] if qr else "QR code")).strip().splitlines()[0]
    if mode == "image" and text:
        # skip short header lines such as "SMS Text Message" when naming the scan
        lines = [ln for ln in text.splitlines() if len(ln) > 25]
        first_line = lines[0] if lines else first_line
    title = label or (first_line[:60] + ("…" if len(first_line) > 60 else ""))
    now = datetime.now().strftime("%m/%d/%Y, %I:%M:%S %p")
    result.update(warnings=warnings, extracted_text=text if mode == "image" else "",
                  qr=qr, engine=engine, image_url=image_url, context=context)

    db = get_db()
    cur = db.execute(
        "INSERT INTO scans (created,label,mode,title,score,risk_class,category,result) VALUES (?,?,?,?,?,?,?,?)",
        (now, label, mode, title, result["score"], result["risk_class"], result["category"], json.dumps(result)))
    db.commit()
    return redirect(url_for("view_scan", scan_id=cur.lastrowid) + "#results")


@app.route("/history")
def history():
    rows = get_db().execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    s = stats()
    return render_template("history.html", rows=rows, history_count=s["total"], py_version=platform.python_version())


@app.route("/history/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    db = get_db()
    db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    db.commit()
    return redirect(url_for("history"))


if __name__ == "__main__":
    analyzer.get_model()  # train once at start-up
    app.run(host="127.0.0.1", port=5000, debug=False)
