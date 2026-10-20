# CodeNova 2.0 — Scam Message & Image Spam Forensics Dashboard

Paste a message or upload a screenshot → get a spam/scam percentage dashboard with every suspicious phrase explained.
All analysis runs in Python (Flask + scikit-learn + Tesseract OCR + PyZbar).

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

### Image scanning (OCR + QR)
Works out of the box after `pip install -r requirements.txt`:
- **OCR:** uses Tesseract if installed, otherwise the pip-only RapidOCR engine.
- **QR codes:** decoded with OpenCV (pip-only); pyzbar is an optional extra.
- Dark-mode screenshots are auto-inverted before OCR.
- Optional Tesseract: Windows installer (set `TESSERACT_CMD` if not on PATH), `brew install tesseract`, or `sudo apt install tesseract-ocr`.
- The 4 sample buttons use bundled images in `static/samples/` (regenerate with `python gen_samples.py`).

## Files
- `analyzer.py` – TF-IDF + Logistic Regression model, regex red-flag rules, score blending, OCR/QR extraction
- `samples.py`, `gen_samples.py` – sample screenshot registry and generator
- `app.py` – Flask routes + SQLite scan history (`codenova.db`)
- `templates/` – dashboard (`index.html`) and history (`history.html`)
- `static/style.css` – dashboard styling

## Improve accuracy
The built-in model trains on a small seed set (`SCAM_SAMPLES` / `HAM_SAMPLES` in `analyzer.py`).
Add more real examples there (or load a CSV such as the UCI SMS Spam Collection) for better results.

## Updating from an older copy
Delete the old folder (or overwrite every file), stop any running `python app.py`, start it again and hard-refresh the browser (Ctrl+F5).
