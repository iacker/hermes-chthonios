#!/usr/bin/env python3
"""Generate the Hermes Chthonios architecture animation (looping GIF).
Renders frames of the seal -> sealed -> unseal -> unsealed cycle."""
import math, os
from PIL import Image, ImageDraw, ImageFont, ImageFilter

W, H = 1200, 540
OUT = "assets/_frames"
os.makedirs(OUT, exist_ok=True)

SF   = "/System/Library/Fonts/SFNS.ttf"
MONO = "/System/Library/Fonts/SFNSMono.ttf"
def font(path, sz):
    return ImageFont.truetype(path, sz)

f_title = font(SF, 34)
f_h     = font(SF, 26)
f_lbl   = font(SF, 20)
f_small = font(SF, 17)
f_mono  = font(MONO, 18)
f_mono_s= font(MONO, 15)
f_badge = font(SF, 16)

CYAN   = (60, 224, 224)
VIOLET = (150, 90, 240)
GREEN  = (60, 220, 150)
RED    = (240, 90, 110)
DIM    = (120, 130, 150)
WHITE  = (232, 238, 248)
BG_TOP = (10, 13, 22)
BG_BOT = (16, 12, 28)

def lerp(a, b, t): return a + (b - a) * t
def lerpc(c1, c2, t): return tuple(int(lerp(c1[i], c2[i], t)) for i in range(3))
def ease(t):  # smoothstep
    t = max(0.0, min(1.0, t)); return t*t*(3-2*t)

def bg():
    im = Image.new("RGB", (W, H), BG_TOP)
    top = Image.new("RGB", (W, H), BG_TOP); bot = Image.new("RGB", (W, H), BG_BOT)
    mask = Image.new("L", (W, H))
    md = ImageDraw.Draw(mask)
    for y in range(H):
        md.line([(0, y), (W, y)], fill=int(255 * y / H))
    im = Image.composite(bot, top, mask)
    return im.convert("RGBA")

def rrect(d, box, r, fill=None, outline=None, width=2):
    d.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)

def glow_layer(draw_fn):
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    draw_fn(d)
    return layer.filter(ImageFilter.GaussianBlur(9))

def text_center(d, cx, y, s, fnt, fill):
    w = d.textlength(s, font=fnt)
    d.text((cx - w/2, y), s, font=fnt, fill=fill)

def padlock(d, cx, cy, scale, color, open_amt):
    """Draw a padlock. open_amt 0=closed,1=open (shackle lifted+rotated)."""
    bw, bh = int(64*scale), int(52*scale)
    body = [cx-bw//2, cy-bh//2, cx+bw//2, cy+bh//2]
    # shackle
    sr = int(22*scale)
    lift = int(open_amt * 14 * scale)
    sx = cx - int(open_amt*10*scale)
    top = cy - bh//2 - sr + lift
    d.arc([sx-sr, top-sr, sx+sr, top+sr], 180, 360, fill=color, width=max(3,int(6*scale)))
    d.line([sx-sr, top, sx-sr, cy-bh//2], fill=color, width=max(3,int(6*scale)))
    if open_amt < 0.5:
        d.line([sx+sr, top, sx+sr, cy-bh//2], fill=color, width=max(3,int(6*scale)))
    else:
        d.line([sx+sr, top, sx+sr, top+int(8*scale)], fill=color, width=max(3,int(6*scale)))
    rrect(d, body, int(10*scale), fill=None, outline=color, width=max(3,int(5*scale)))
    # keyhole
    kh = cy - int(4*scale)
    d.ellipse([cx-int(6*scale), kh-int(6*scale), cx+int(6*scale), kh+int(6*scale)], outline=color, width=max(2,int(3*scale)))
    d.line([cx, kh, cx, kh+int(16*scale)], fill=color, width=max(2,int(3*scale)))

# scrambled ciphertext lines
import random
random.seed(7)
CIPHER = ["".join(random.choice("0123456789abcdef") for _ in range(28)) for _ in range(3)]
KEYS = ["OPENAI_API_KEY=sk-··········", "RUNPOD_KEY=rp_··········", "ANTHROPIC_KEY=sk-ant-·····"]

# ------- timeline (frames) -------
# Phase durations
P_UNSEALED = 16
P_SEAL     = 16
P_SEALED   = 16
P_UNSEAL   = 16
TOTAL = P_UNSEALED + P_SEAL + P_SEALED + P_UNSEAL

def phase_state(i):
    """Return (state_name, seal_progress 0..1) where seal 0=unsealed,1=sealed, and active caption."""
    if i < P_UNSEALED:
        return ("unsealed", 0.0, None, 0.0)
    i2 = i - P_UNSEALED
    if i2 < P_SEAL:
        t = ease(i2 / (P_SEAL-1))
        return ("sealing", t, "seal", 0.0)
    i3 = i2 - P_SEAL
    if i3 < P_SEALED:
        return ("sealed", 1.0, None, 0.0)
    i4 = i3 - P_SEALED
    t = ease(i4 / (P_UNSEAL-1))
    # ripple for touch
    return ("unsealing", 1.0 - t, "unseal", i4/(P_UNSEAL-1))

CARD = (430, 150, 770, 400)  # central profile card

def draw_frame(i):
    state, seal, caption, ripple = phase_state(i)
    im = bg()
    d = ImageDraw.Draw(im, "RGBA")

    # header
    text_center(d, W//2, 30, "HERMES  CHTHONIOS", f_title, WHITE)
    text_center(d, W//2, 72, "a profile's credentials, sealed at rest", f_small, DIM)

    cx = (CARD[0]+CARD[2])//2
    # card color by state
    accent = lerpc(GREEN, RED, seal)
    # glow behind card
    def gl(dd):
        rrect(dd, [CARD[0]-6,CARD[1]-6,CARD[2]+6,CARD[3]+6], 22,
               outline=accent+(140,), width=6)
    im.alpha_composite(glow_layer(gl))
    d = ImageDraw.Draw(im, "RGBA")

    rrect(d, CARD, 20, fill=(20,24,36,235), outline=accent, width=3)
    # card title
    text_center(d, cx, CARD[1]+16, "profile: redteam", f_h, WHITE)

    # env filename toggles
    fname = ".env.chthonios" if seal > 0.5 else ".env"
    fcol  = accent
    text_center(d, cx, CARD[1]+54, fname, f_mono_s, fcol)

    # content region: keys (readable) morph to ciphertext
    ry = CARD[1]+92
    for k in range(3):
        yy = ry + k*30
        if seal < 0.5:
            s = KEYS[k]; col = lerpc(WHITE, DIM, seal*2)
        else:
            s = CIPHER[k]; col = lerpc(DIM, accent, (seal-0.5)*2)
        text_center(d, cx, yy, s, f_mono_s, col)

    # padlock at bottom of card
    padlock(d, cx, CARD[3]-6, 0.7, accent, open_amt=1.0-seal)

    # status line under card
    if seal > 0.5:
        text_center(d, cx, CARD[3]+22, "✗  cannot call any model", f_lbl, RED)
    else:
        text_center(d, cx, CARD[3]+22, "✓  profile can run", f_lbl, GREEN)

    # ---- left: the two locks (roots of trust) ----
    lx = 210
    text_center(d, lx, 150, "ROOT OF TRUST", f_small, DIM)
    # passphrase badge
    rrect(d, [lx-140, 185, lx+140, 250], 14, fill=(24,26,40,220), outline=CYAN, width=2)
    # key glyph
    d.ellipse([lx-116, 200, lx-104, 212], outline=CYAN, width=3)
    d.line([lx-105, 206, lx-92, 206], fill=CYAN, width=3)
    d.line([lx-95, 206, lx-95, 212], fill=CYAN, width=3)
    d.text((lx-84, 197), "Passphrase", font=f_badge, fill=WHITE)
    d.text((lx-118, 222), "AES-256-GCM · scrypt", font=f_small, fill=DIM)
    # yubikey badge
    rrect(d, [lx-140, 268, lx+140, 333], 14, fill=(24,26,40,220), outline=VIOLET, width=2)
    # shield glyph
    sgx, sgy = lx-110, 288
    d.polygon([(sgx,sgy-8),(sgx+10,sgy-4),(sgx+10,sgy+4),(sgx,sgy+11),(sgx-10,sgy+4),(sgx-10,sgy-4)], outline=VIOLET, width=3)
    d.text((lx-84, 281), "YubiKey (FIDO2)", font=f_badge, fill=WHITE)
    d.text((lx-118, 305), "hardware · touch", font=f_small, fill=DIM)

    # ---- right: agent/gateway ----
    gx = 990
    text_center(d, gx, 150, "AGENT GATEWAY", f_small, DIM)
    online = seal < 0.5
    gcol = GREEN if online else DIM
    rrect(d, [gx-120, 185, gx+120, 333], 16, fill=(22,24,38,220), outline=gcol, width=2)
    text_center(d, gx, 210, "model", f_lbl, WHITE)
    text_center(d, gx, 236, "provider", f_lbl, WHITE)
    dot = GREEN if online else RED
    d.ellipse([gx-8, 285, gx+8, 301], fill=dot)
    text_center(d, gx, 305, "online" if online else "no key", f_small, dot)

    # ---- connecting arrows with animated pulse ----
    # left lock -> card (unseal direction) ; card -> agent (serves keys)
    def arrow(x1, y, x2, col, prog=None, active=False):
        d.line([x1, y, x2, y], fill=col+(120,), width=3)
        # arrowhead
        d.polygon([(x2,y),(x2-10,y-6),(x2-10,y+6)], fill=col+(160,))
        if active and prog is not None:
            px = lerp(x1, x2, prog)
            for rr,aa in [(10,90),(6,160),(3,230)]:
                d.ellipse([px-rr,y-rr,px+rr,y+rr], fill=col+(aa,))

    # lock -> card
    if caption == "unseal":
        arrow(lx+145, 259, CARD[0]-4, VIOLET, prog=1-seal, active=True)
    else:
        arrow(lx+145, 259, CARD[0]-4, (70,80,100))
    # card -> agent
    arrow(CARD[2]+4, 259, gx-124, GREEN if online else (70,80,100),
          prog=None, active=False)

    # ---- caption banner (seal / unseal action) ----
    if caption:
        if caption == "seal":
            txt = "seal  ·  no key needed  ·  an agent can lock itself"
            ccol = lerpc(GREEN, RED, seal)
        else:
            txt = "unseal  ·  YubiKey present + touch  ·  only a human opens it"
            ccol = lerpc(RED, GREEN, 1-seal)
        bw = d.textlength(txt, font=f_lbl)
        bx = W//2 - bw/2
        rrect(d, [bx-20, 470, bx+bw+20, 508], 18, fill=(18,20,32,235), outline=ccol, width=2)
        d.text((bx, 478), txt, font=f_lbl, fill=WHITE)
        # touch ripple flourish
        if caption == "unseal" and ripple > 0:
            rr = int(ripple*60)+6
            aa = int(180*(1-ripple))
            d.ellipse([lx-rr, 300-rr, lx+rr, 300+rr], outline=VIOLET+(aa,), width=3)
    else:
        # steady-state label
        lab = "SEALED — at rest, unreadable" if seal>0.5 else "UNSEALED — live for this session"
        lcol = RED if seal>0.5 else GREEN
        text_center(d, W//2, 478, lab, f_lbl, lcol)

    return im.convert("RGB")

frames = [draw_frame(i) for i in range(TOTAL)]
# hold a bit longer on steady states by duplicating first/mid frames
paths = []
for idx, fr in enumerate(frames):
    p = f"{OUT}/f{idx:03d}.png"; fr.save(p); paths.append(p)
print("rendered", len(frames), "frames")
