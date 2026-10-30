#!/usr/bin/env python3
"""
Renders the boot artwork from the brand definition in include/brand.h.

The appliance needs these as PNGs: Plymouth cannot draw an SVG and GRUB's
PNG reader is all it has. They are generated here and committed under
board/splash/ so tools/build-image.sh never needs Pillow or a font stack
on the build host -- it copies files.

Re-run after changing brand.h:

    python3 tools/make-splash.py

Everything below is derived from BRAND_* so a re-skin stays a one-file edit.
"""

import os
import re
import sys
from PIL import Image, ImageDraw, ImageFont, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
OUT = os.path.join(PROJ, "board", "splash")

# Read from include/brand.h like every other string here, so a re-skin
# stays a one-file change. Written out literally, this was one of the two
# places that quietly kept the previous name after a rebrand.
def _author(path=os.path.join(os.path.dirname(__file__), "..", "include", "brand.h")):
    m = re.search(r'#define\s+BRAND_AUTHOR\s+"([^"]+)"', open(path).read())
    if not m:
        raise SystemExit("make-splash: BRAND_AUTHOR is not defined in include/brand.h")
    return m.group(1)

AUTHOR = _author()


# ── brand.h ────────────────────────────────────────────────────────────

def brand():
    """Pulls the #defines we draw with, so the artwork cannot drift."""
    text = open(os.path.join(PROJ, "include", "brand.h")).read()
    want = ("PRODUCT", "VENDOR", "TAGLINE", "VERSION", "EDITION",
            "COLOR_PRIMARY", "COLOR_SECONDARY", "COLOR_DARK",
            "COLOR_PANEL", "COLOR_MUTED", "COLOR_TEXT")
    out = {}
    for key in want:
        m = re.search(r'#define\s+BRAND_%s\s+"([^"]*)"' % key, text)
        if not m:
            sys.exit("brand.h has no BRAND_%s" % key)
        out[key] = m.group(1)
    return out


def rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


# ── fonts ──────────────────────────────────────────────────────────────

FONT_DIRS = ["/usr/share/fonts/truetype/dejavu",
             "/usr/share/fonts/truetype/liberation",
             "/usr/share/fonts/truetype/freefont"]


def font(names, size):
    for d in FONT_DIRS:
        for n in names:
            p = os.path.join(d, n)
            if os.path.exists(p):
                return ImageFont.truetype(p, size)
    sys.exit("no usable font found in %s" % ", ".join(FONT_DIRS))


def bold(size):
    return font(["DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf",
                 "FreeSansBold.ttf"], size)


def regular(size):
    return font(["DejaVuSans.ttf", "LiberationSans-Regular.ttf",
                 "FreeSans.ttf"], size)


# ── the flame, straight off BRAND_LOGO_SVG ─────────────────────────────
#
# Both paths in brand.h are a cubic down the left, a semicircular bottom,
# and a cubic back up the right. Sampling them here keeps the boot screen
# and the web console showing the same mark.

def cubic(p0, p1, p2, p3, steps=48):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        pts.append((u * u * u * p0[0] + 3 * u * u * t * p1[0] +
                    3 * u * t * t * p2[0] + t * t * t * p3[0],
                    u * u * u * p0[1] + 3 * u * u * t * p1[1] +
                    3 * u * t * t * p2[1] + t * t * t * p3[1]))
    return pts


def semicircle(cx, cy, r, steps=48):
    """
    Left to right through the bottom, so the flame sits in a bowl.

    SVG y grows downward, so the half we want is the one with positive
    sin -- going through theta = pi/2 at (cx, cy + r). Negating it here
    scoops the base out instead, which is what the mark must not do.
    """
    import math
    return [(cx + r * math.cos(math.pi - math.pi * i / steps),
             cy + r * math.sin(math.pi - math.pi * i / steps))
            for i in range(steps + 1)]


def flame_outline():
    pts = cubic((24, 2), (24, 2), (12, 14), (12, 26))
    pts += semicircle(24, 26, 12)
    pts += cubic((36, 26), (36, 14), (24, 2), (24, 2))
    return pts


def flame_inner():
    pts = cubic((24, 14), (24, 14), (18, 20.5), (18, 26))
    pts += semicircle(24, 26, 6)
    pts += cubic((30, 26), (30, 20.5), (24, 14), (24, 14))
    return pts


def gradient(size, c0, c1):
    """Diagonal two-stop ramp, matching the SVG's x1,y1 -> x2,y2."""
    w, h = size
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            t = (x / max(w - 1, 1) + y / max(h - 1, 1)) / 2
            px[x, y] = tuple(int(c0[i] + (c1[i] - c0[i]) * t) for i in range(3))
    return img


def logo(px, b, glow=True):
    """The flame at `px` square, transparent, 4x supersampled."""
    s = 4
    n = px * s
    scale = n / 48.0

    mask = Image.new("L", (n, n), 0)
    d = ImageDraw.Draw(mask)
    d.polygon([(x * scale, y * scale) for x, y in flame_outline()], fill=255)

    inner = Image.new("L", (n, n), 0)
    ImageDraw.Draw(inner).polygon(
        [(x * scale, y * scale) for x, y in flame_inner()], fill=140)

    body = gradient((n, n), rgb(b["COLOR_PRIMARY"]), rgb(b["COLOR_SECONDARY"]))
    body.paste(Image.new("RGB", (n, n), rgb(b["COLOR_DARK"])), (0, 0), inner)

    out = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    out.paste(body, (0, 0), mask)
    out = out.resize((px, px), Image.LANCZOS)

    if not glow:
        return out

    # A soft halo so the mark does not sit flat on the background.
    halo = Image.new("RGBA", (px, px), (0, 0, 0, 0))
    halo.paste(Image.new("RGBA", (px, px), rgb(b["COLOR_PRIMARY"]) + (110,)),
               (0, 0), out.split()[3])
    halo = halo.filter(ImageFilter.GaussianBlur(px // 14))

    canvas = Image.new("RGBA", (px, px), (0, 0, 0, 0))
    canvas.alpha_composite(halo)
    canvas.alpha_composite(out)
    return canvas


# ── background ─────────────────────────────────────────────────────────

def background(w, h, b):
    """Dark field with a warm bloom behind where the logo sits."""
    dark = rgb(b["COLOR_DARK"])
    img = Image.new("RGB", (w, h), dark)

    # Drawn small and scaled up: a per-pixel radial ramp at 1920x1080 in
    # pure Python takes minutes, and the result is a blur either way.
    sw, sh = 160, 90
    small = Image.new("RGB", (sw, sh))
    px = small.load()
    warm = rgb(b["COLOR_PRIMARY"])
    for y in range(sh):
        for x in range(sw):
            dx = (x - sw / 2) / (sw / 2)
            dy = (y - sh * 0.42) / (sh / 2)
            t = max(0.0, 1.0 - (dx * dx + dy * dy) ** 0.5)
            t = (t ** 3) * 0.17
            px[x, y] = tuple(int(dark[i] + (warm[i] - dark[i]) * t)
                             for i in range(3))
    img = small.resize((w, h), Image.BICUBIC)

    # Vignette, so the edges do not glow on a large panel.
    vig = Image.new("L", (sw, sh), 0)
    vp = vig.load()
    for y in range(sh):
        for x in range(sw):
            dx = (x - sw / 2) / (sw / 2)
            dy = (y - sh / 2) / (sh / 2)
            vp[x, y] = int(min(1.0, (dx * dx + dy * dy) ** 0.5 * 0.85) * 150)
    img.paste(Image.new("RGB", (w, h), (0, 0, 0)),
              (0, 0), vig.resize((w, h), Image.BICUBIC))
    return img


def text_image(s, fnt, fill, track=0):
    """Transparent PNG of exactly one line, optionally letter-spaced."""
    probe = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    if track:
        w = sum(int(probe.textlength(c, font=fnt)) + track for c in s)
    else:
        w = int(probe.textlength(s, font=fnt))
    asc, desc = fnt.getmetrics()
    h = asc + desc
    img = Image.new("RGBA", (max(w, 1) + 4, h + 4), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if track:
        x = 2
        for c in s:
            d.text((x, 2), c, font=fnt, fill=fill)
            x += int(probe.textlength(c, font=fnt)) + track
    else:
        d.text((2, 2), s, font=fnt, fill=fill)
    return img


def centred(canvas, img, y):
    canvas.alpha_composite(img, ((canvas.width - img.width) // 2, y))
    return y + img.height


# ── compositions ───────────────────────────────────────────────────────

def splash(w, h, b, top=0.5, version=False):
    """
    The full boot screen in one image.

    `top` is where the centre of the logo-and-wordmark block sits, as a
    fraction of the height. The GRUB background pushes it up to 0.3 so the
    menu has the lower half to itself; the standalone splash leaves it
    centred.
    """
    canvas = background(w, h, b).convert("RGBA")

    unit = h / 768.0
    mark = logo(int(190 * unit), b)
    name = text_image("%s by %s" % (b["PRODUCT"], b["VENDOR"]),
                      bold(int(46 * unit)), rgb(b["COLOR_TEXT"]) + (255,))
    tag = text_image(b["TAGLINE"].upper(), regular(int(15 * unit)),
                     rgb(b["COLOR_MUTED"]) + (255,), track=int(4 * unit))
    by = text_image(AUTHOR, bold(int(17 * unit)),
                    rgb(b["COLOR_PRIMARY"]) + (255,), track=int(1 * unit))

    gap1, gap2 = int(26 * unit), int(16 * unit)
    block = mark.height + gap1 + name.height + gap2 + tag.height

    y = int(h * top - block / 2)
    y = centred(canvas, mark, y) + gap1
    y = centred(canvas, name, y) + gap2
    centred(canvas, tag, y)

    # The byline is pinned to the bottom rather than floated under the
    # tagline: Plymouth draws its progress bar in the middle band and GRUB
    # draws its menu there, so anything parked under the tagline is covered.
    centred(canvas, by, h - by.height - int(54 * unit))

    if version:
        ver = text_image("%s %s  %s" % (b["PRODUCT"], b["VERSION"],
                                        b["EDITION"]),
                         regular(int(13 * unit)),
                         rgb(b["COLOR_MUTED"]) + (255,))
        canvas.alpha_composite(ver, (int(28 * unit),
                                     h - ver.height - int(22 * unit)))
    return canvas.convert("RGB")


def main():
    b = brand()
    os.makedirs(OUT, exist_ok=True)

    made = []

    def save(name, img):
        p = os.path.join(OUT, name)
        img.save(p, optimize=True)
        made.append((name, os.path.getsize(p)))

    # Plymouth composites the pieces itself and animates the logo, so its
    # backdrop carries no artwork -- drawing the wordmark twice, once baked
    # in and once on top, is the usual way these themes end up blurry.
    save("background.png", background(1024, 768, b))
    save("logo.png", logo(256, b))
    save("title.png", text_image("%s by %s" % (b["PRODUCT"], b["VENDOR"]),
                                 bold(46), rgb(b["COLOR_TEXT"]) + (255,)))
    save("tagline.png", text_image(b["TAGLINE"].upper(), regular(15),
                                   rgb(b["COLOR_MUTED"]) + (255,), track=4))
    save("byline.png", text_image(AUTHOR, bold(17),
                                  rgb(b["COLOR_PRIMARY"]) + (255,), track=1))

    # Progress bar. Plymouth's script plugin has no fill primitive, so the
    # bar is this image scaled to the width it should be -- which is why it
    # is a flat ramp and not something with ends that would stretch.
    save("bar.png", gradient((256, 8), rgb(b["COLOR_PRIMARY"]),
                             rgb(b["COLOR_SECONDARY"])))
    save("track.png", Image.new("RGB", (256, 8), rgb(b["COLOR_PANEL"])))

    # GRUB draws one flat image and puts its menu on top of it.
    save("grub.png", splash(1024, 768, b, top=0.30, version=True))

    # One-file fallback, and the picture the docs show.
    save("splash.png", splash(1920, 1080, b, version=True))

    width = max(len(n) for n, _ in made)
    for name, size in made:
        print("  %-*s  %6.1f KB" % (width, name, size / 1024.0))
    print("wrote %d files to %s" % (len(made), OUT))


if __name__ == "__main__":
    main()
