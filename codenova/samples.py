"""Built-in sample screenshots for the 'instant OCR + QR test' buttons.

All brands, phone numbers and domains in these samples are fictional.
`text` / `qr` are the ground-truth transcripts, used only as a fallback if
no OCR engine is installed on the machine (a warning is shown when that happens).
"""

SAMPLES = [
    {
        "id": "parcel-sms",
        "file": "smishing-parcel.png",
        "label": "Parcel Delivery SMS",
        "sub": "Smishing OCR",
        "kind": "scam",
        "text": ("URGENT DELIVERY NOTICE: Your parcel #4059481290 cannot be delivered due to an "
                 "incomplete address and an unpaid $1.95 redelivery fee. Update your card details "
                 "within 12 hours or your package will be destroyed: "
                 "https://parcelgo-redelivery.top/confirm"),
        "qr": [],
    },
    {
        "id": "qr-quishing",
        "file": "qr-quishing.png",
        "label": "Account QR Quishing",
        "sub": "QR Code + OCR",
        "kind": "scam",
        "text": ("Security Team - Action required. Your password expires today. Scan the QR code "
                 "below with your phone to re-authenticate and keep access to your email. "
                 "Failure to verify within 24 hours will suspend your account."),
        "qr": ["https://cloudsuite-secure-login.click/auth"],
    },
    {
        "id": "dark-job",
        "file": "dark-whatsapp-job.png",
        "label": "Dark WhatsApp Job Lure",
        "sub": "Dark-UI OCR",
        "kind": "scam",
        "text": ("Hi! I'm Priya from a remote hiring team. We pay $200-$400 per day for simple video "
                 "liking tasks. No experience needed, paid instantly in USDT. Message us on Telegram "
                 "+44 7700 900555 today!"),
        "qr": [],
    },
    {
        "id": "dental",
        "file": "dental-reminder.png",
        "label": "Dental Clinic Reminder",
        "sub": "Clean / Safe",
        "kind": "safe",
        "text": ("Hi Rahul, this is a reminder of your dental check-up tomorrow at 10:30 AM at Smile "
                 "Care Clinic. Reply C to confirm or call the front desk to reschedule. See you soon!"),
        "qr": [],
    },
]

SAMPLE_BY_ID = {s["id"]: s for s in SAMPLES}
