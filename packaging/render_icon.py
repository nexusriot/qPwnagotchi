#!/usr/bin/env python3
"""Render qPwnagotchi app icon at multiple sizes using PIL.

Draws at 1024x1024 then downsamples with LANCZOS for crispness.
"""
from PIL import Image, ImageDraw, ImageFilter
import os

S = 1024  # master canvas; everything in 0..256 design units * 4

def U(x):  # design unit (256-base) -> px
    return x * (S // 256)

def rounded_rect_mask(size, radius):
    m = Image.new("L", size, 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle((0, 0, size[0]-1, size[1]-1), radius=radius, fill=255)
    return m

def vgradient(size, c0, c1):
    w, h = size
    img = Image.new("RGB", size, c0)
    px = img.load()
    for y in range(h):
        t = y / max(1, h-1)
        r = int(c0[0]*(1-t) + c1[0]*t)
        g = int(c0[1]*(1-t) + c1[1]*t)
        b = int(c0[2]*(1-t) + c1[2]*t)
        for x in range(w):
            px[x, y] = (r, g, b)
    return img

# --- base canvas (transparent) ---
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

# rounded square background with gradient
bg_box = (U(8), U(8), U(248), U(248))
bg_w, bg_h = bg_box[2]-bg_box[0], bg_box[3]-bg_box[1]
grad = vgradient((bg_w, bg_h), (0x1f, 0x6f, 0xeb), (0x0b, 0x2a, 0x52))
mask = rounded_rect_mask((bg_w, bg_h), U(44))
bg = Image.new("RGBA", (bg_w, bg_h), (0, 0, 0, 0))
bg.paste(grad, (0, 0), mask)
img.paste(bg, (bg_box[0], bg_box[1]), bg)

d = ImageDraw.Draw(img, "RGBA")

# subtle top highlight
hl = Image.new("RGBA", (bg_w, bg_h//2), (255, 255, 255, 16))
hl_mask = rounded_rect_mask((bg_w, bg_h//2), U(44))
img.paste(hl, (bg_box[0], bg_box[1]), hl_mask)

# --- WiFi waves (behind device) ---
def arc(cx, cy, r, start, end, width, color):
    d.arc((cx-r, cy-r, cx+r, cy+r), start=start, end=end, fill=color, width=width)

wave_color = (0x9a, 0xd1, 0xff, 220)
# left side - concentric arcs centered roughly at device left edge top
for r, w in [(U(40), U(5)), (U(62), U(5)), (U(84), U(5))]:
    arc(U(40), U(78), r, 200, 260, w, wave_color)
# right side mirrored
for r, w in [(U(40), U(5)), (U(62), U(5)), (U(84), U(5))]:
    arc(U(216), U(78), r, 280, 340, w, wave_color)

# --- antenna ---
d.line((U(128), U(44), U(128), U(22)), fill=(0xe6, 0xed, 0xf3, 255), width=U(6))
# antenna ball
r = U(9)
d.ellipse((U(128)-r, U(16)-r, U(128)+r, U(16)+r),
          fill=(0xff, 0x5d, 0x5d, 255), outline=(0xe6, 0xed, 0xf3, 255), width=U(3)//1 or 1)

# --- device shadow ---
shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
sd = ImageDraw.Draw(shadow)
sd.rounded_rectangle((U(40), U(62)+U(4), U(216), U(210)+U(4)),
                     radius=U(18), fill=(0, 0, 0, 90))
shadow = shadow.filter(ImageFilter.GaussianBlur(radius=U(3)))
img.alpha_composite(shadow)

# --- device body ---
d.rounded_rectangle((U(40), U(62), U(216), U(210)),
                    radius=U(18),
                    fill=(0x11, 0x16, 0x1f, 255),
                    outline=(0x2a, 0x31, 0x40, 255),
                    width=max(1, U(3)//1))

# --- screen (e-ink) ---
screen_box = (U(56), U(78), U(200), U(182))
sw, sh = screen_box[2]-screen_box[0], screen_box[3]-screen_box[1]
screen = vgradient((sw, sh), (0xf4, 0xf1, 0xc1), (0xc9, 0xc3, 0x89))
smask = rounded_rect_mask((sw, sh), U(6))
img.paste(screen, (screen_box[0], screen_box[1]), smask)

# status bar
sb_h = U(14)
sb = Image.new("RGBA", (sw, sb_h), (0x11, 0x16, 0x1f, 220))
sb_mask = Image.new("L", (sw, sb_h), 0)
sbd = ImageDraw.Draw(sb_mask)
# match top corners of screen
sbd.rounded_rectangle((0, 0, sw-1, sb_h*4), radius=U(6), fill=255)
img.paste(sb, (screen_box[0], screen_box[1]), sb_mask)

# status text (drawn as small rectangles to avoid font deps; readable at large sizes)
try:
    from PIL import ImageFont
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", U(10))
    d.text((U(62), U(80)), "PWN!", fill=(0xf4, 0xf1, 0xc1, 255), font=font)
    txt = "CH 6"
    bbox = d.textbbox((0, 0), txt, font=font)
    tw = bbox[2]-bbox[0]
    d.text((U(194)-tw, U(80)), txt, fill=(0xf4, 0xf1, 0xc1, 255), font=font)
except Exception:
    pass

# --- Pwnagotchi face (◕‿‿◕) ---
eye_color = (0x11, 0x16, 0x1f, 255)
hl_color = (0xf4, 0xf1, 0xc1, 255)
# left eye
er = U(14)
d.ellipse((U(92)-er, U(122)-er, U(92)+er, U(122)+er), fill=eye_color)
sr = U(4)
d.ellipse((U(96)-sr, U(117)-sr, U(96)+sr, U(117)+sr), fill=hl_color)
# right eye
d.ellipse((U(164)-er, U(122)-er, U(164)+er, U(122)+er), fill=eye_color)
d.ellipse((U(168)-sr, U(117)-sr, U(168)+sr, U(117)+sr), fill=hl_color)

# mouth: ‿‿  (two small u-shapes)
mw = U(5)
# left u
d.arc((U(108), U(146), U(128), U(160)), start=20, end=160, fill=eye_color, width=mw)
# right u
d.arc((U(128), U(146), U(148), U(160)), start=20, end=160, fill=eye_color, width=mw)

# --- buttons and speaker grille ---
for cx in (U(76), U(92), U(108)):
    rr = U(4)
    d.ellipse((cx-rr, U(198)-rr, cx+rr, U(198)+rr), fill=(0x2a, 0x31, 0x40, 255))
d.rounded_rectangle((U(150), U(194), U(200), U(202)), radius=U(2), fill=(0x2a, 0x31, 0x40, 255))

# --- final: write sizes ---
out_dir = os.path.dirname(os.path.abspath(__file__))
for size in (16, 24, 32, 48, 64, 128, 256, 512):
    out = img.resize((size, size), Image.LANCZOS)
    out.save(os.path.join(out_dir, f"qpwnagotchi-{size}.png"))
img.save(os.path.join(out_dir, "qpwnagotchi-1024.png"))
print("rendered to", out_dir)
