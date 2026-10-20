"""Regenerates static/samples/*.png (run once: python gen_samples.py)."""
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

from samples import SAMPLE_BY_ID

OUT = Path(__file__).parent / "static" / "samples"
OUT.mkdir(parents=True, exist_ok=True)

FONT_DIRS = ["/usr/share/fonts/truetype/dejavu/", "C:/Windows/Fonts/", "/Library/Fonts/", "/System/Library/Fonts/Supplemental/"]


def font(size, bold=False):
    names = (["DejaVuSans-Bold.ttf", "arialbd.ttf", "Arial Bold.ttf"] if bold
             else ["DejaVuSans.ttf", "arial.ttf", "Arial.ttf"])
    for d in FONT_DIRS:
        for n in names:
            if (Path(d) / n).exists():
                return ImageFont.truetype(str(Path(d) / n), size)
    return ImageFont.load_default(size)


def wrap(draw, text, fnt, max_w):
    lines, cur = [], ""
    for word in text.split():
        trial = (cur + " " + word).strip()
        if draw.textlength(trial, font=fnt) <= max_w:
            cur = trial
        else:
            lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def draw_lines(draw, lines, x, y, fnt, fill, gap=10):
    for ln in lines:
        draw.text((x, y), ln, font=fnt, fill=fill)
        y += fnt.size + gap
    return y


def footer(draw, w, h, fill):
    f = font(16)
    t = "CodeNova 2.0 test sample - fictional"
    draw.text(((w - draw.textlength(t, font=f)) / 2, h - 30), t, font=f, fill=fill)


def parcel_sms():
    w, h = 760, 720
    img = Image.new("RGB", (w, h), (242, 242, 247))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 120], fill=(250, 250, 252))
    t = "SMS Text Message"
    d.text(((w - d.textlength(t, font=font(30, True))) / 2, 24), t, font=font(30, True), fill=(20, 20, 20))
    t = "+1 617 555 0194"
    d.text(((w - d.textlength(t, font=font(22))) / 2, 72), t, font=font(22), fill=(110, 110, 120))
    t = "Today 9:41 AM"
    d.text(((w - d.textlength(t, font=font(20))) / 2, 140), t, font=font(20), fill=(130, 130, 140))
    f = font(27)
    lines = wrap(d, SAMPLE_BY_ID["parcel-sms"]["text"], f, w - 160)
    bh = len(lines) * (f.size + 10) + 50
    d.rounded_rectangle([40, 185, w - 40, 185 + bh], radius=30, fill=(229, 229, 234))
    draw_lines(d, lines, 70, 210, f, (15, 15, 15))
    footer(d, w, h, (150, 150, 160))
    return img


def qr_quishing():
    s = SAMPLE_BY_ID["qr-quishing"]
    w, h = 800, 900
    img = Image.new("RGB", (w, h), (255, 255, 255))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 110], fill=(0, 90, 170))
    d.text((40, 32), "Security Team", font=font(36, True), fill=(255, 255, 255))
    f = font(27)
    y = draw_lines(d, wrap(d, s["text"], f, w - 80), 40, 150, f, (30, 30, 30))
    enc = cv2.QRCodeEncoder.create()
    m = enc.encode(s["qr"][0])
    scale = 9
    m = cv2.resize(m, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    m = np.pad(m, 4 * scale, constant_values=255)
    qr = Image.fromarray(m).convert("RGB")
    img.paste(qr, ((w - qr.width) // 2, y + 30))
    footer(d, w, h, (150, 150, 150))
    return img


def dark_job():
    w, h = 760, 720
    img = Image.new("RGB", (w, h), (11, 20, 26))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 120], fill=(31, 44, 52))
    d.ellipse([30, 30, 90, 90], fill=(70, 90, 100))
    d.text((110, 30), "Remote Jobs Hiring", font=font(30, True), fill=(233, 237, 239))
    d.text((110, 75), "online", font=font(20), fill=(0, 168, 132))
    f = font(27)
    lines = wrap(d, SAMPLE_BY_ID["dark-job"]["text"], f, w - 150)
    bh = len(lines) * (f.size + 10) + 70
    d.rounded_rectangle([40, 170, w - 60, 170 + bh], radius=22, fill=(32, 44, 51))
    y = draw_lines(d, lines, 65, 195, f, (233, 237, 239))
    d.text((w - 170, 170 + bh - 36), "10:12 PM", font=font(18), fill=(134, 150, 160))
    footer(d, w, h, (110, 125, 135))
    return img


def dental():
    w, h = 760, 640
    img = Image.new("RGB", (w, h), (229, 221, 213))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 120], fill=(7, 94, 84))
    d.text((40, 36), "Smile Care Clinic", font=font(32, True), fill=(255, 255, 255))
    f = font(27)
    lines = wrap(d, SAMPLE_BY_ID["dental"]["text"], f, w - 150)
    bh = len(lines) * (f.size + 10) + 70
    d.rounded_rectangle([40, 160, w - 60, 160 + bh], radius=22, fill=(255, 255, 255))
    draw_lines(d, lines, 65, 185, f, (25, 25, 25))
    d.text((w - 170, 160 + bh - 36), "8:30 AM", font=font(18), fill=(140, 140, 140))
    footer(d, w, h, (120, 120, 120))
    return img


if __name__ == "__main__":
    for name, fn in [("parcel-sms", parcel_sms), ("qr-quishing", qr_quishing),
                     ("dark-job", dark_job), ("dental", dental)]:
        fn().save(OUT / SAMPLE_BY_ID[name]["file"])
        print("wrote", SAMPLE_BY_ID[name]["file"])
