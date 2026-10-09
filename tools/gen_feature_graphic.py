#!/usr/bin/env python3
"""Generate the F-Droid "feature graphic" (store banner) for 5G-Proxy-Client.

F-Droid renders `fastlane/metadata/android/<locale>/images/featureGraphic.png`
as a full-width banner above the app icon on the listing page.  Without the
file the listing simply has no header, which is what made the Client entry look
thinner than the Pro one -- so this script is the source of record for it.

Canvas
------
1024x500, the size F-Droid documents for feature graphics.  The artwork is
deliberately nothing but a gradient plus three lines of white text: the Pro
listing's banner is built the same way, and the two apps share an icon palette,
so keeping the composition identical is what makes them read as siblings.

Gradient
--------
Sampled from the Pro banner and re-fitted as a *bilinear* blend of four corner
colours.  Sampling the shipped PNG at nine points and solving for the corners
reproduces every sample to within 1/255, so the two banners are colour-matched
by construction rather than by eye:

    top-left  #0d47a1      top-right    #029598
    bottom-left #0b5a9f    bottom-right #00a896

Type
----
The Pro banner's face could not be identified with certainty -- metric
comparison of its title (cap height 60px, width 530px, so width/cap = 8.83)
puts Arial Bold at 8.76 and Segoe UI Bold at 8.69, and no installed face
reproduces its unusually shallow `y` descender.  Segoe UI is used here because
its x-height/cap-height ratio (0.714) is the closest match to the measured
0.711, and it is the UI face the app already ships against.  Font resolution
falls back through a candidate list so the script still runs off-Windows.

Text is positioned by *cap height* and *ink top* rather than by nominal point
size, so the layout survives a font substitution: the y-coordinates below are
the Pro banner's, measured off its row profile.

Usage (from the repo root):

    python tools/gen_feature_graphic.py
    python tools/gen_feature_graphic.py --preview /tmp/banner_preview.png
"""

from __future__ import annotations

import argparse
import os
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFont

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(
    REPO, "fastlane", "metadata", "android", "en-US", "images", "featureGraphic.png"
)

W, H = 1024, 500

# Bilinear corner colours (see module docstring).
CORNER_TL = (0x0D, 0x47, 0xA1)
CORNER_TR = (0x02, 0x95, 0x98)
CORNER_BL = (0x0B, 0x5A, 0x9F)
CORNER_BR = (0x00, 0xA8, 0x96)

TEXT_COLOUR = (255, 255, 255)

# (text, font role, cap height in px, y of the ink top).  All three lines are
# centred horizontally; the y values mirror the Pro banner's row profile.
LINES = [
    ("5G Proxy Client", "bold", 60.0, 155),
    ("Route all device traffic through a remote SOCKS5 server", "regular", 21.5, 269),
    ("No root | TUN interface | TCP + UDP relay", "regular", 21.5, 319),
]

# First hit wins.  Segoe UI first (see docstring); DejaVu ships with matplotlib
# and keeps the script usable on a machine without the Windows fonts.
FONT_CANDIDATES = {
    "bold": [
        r"C:\Windows\Fonts\segoeuib.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "DejaVuSans-Bold.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
    ],
    "regular": [
        r"C:\Windows\Fonts\segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "DejaVuSans.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    ],
}


def resolve_font(role: str) -> str:
    for path in FONT_CANDIDATES[role]:
        try:
            ImageFont.truetype(path, 40)
        except Exception:
            continue
        return path
    raise SystemExit(f"error: no usable {role} font found; tried {FONT_CANDIDATES[role]}")


def gradient(w: int, h: int) -> Image.Image:
    """Bilinear blend of the four corner colours."""
    tx = np.linspace(0.0, 1.0, w, dtype=np.float64)[None, :, None]
    ty = np.linspace(0.0, 1.0, h, dtype=np.float64)[:, None, None]
    tl = np.array(CORNER_TL, dtype=np.float64)
    tr = np.array(CORNER_TR, dtype=np.float64)
    bl = np.array(CORNER_BL, dtype=np.float64)
    br = np.array(CORNER_BR, dtype=np.float64)
    arr = (1 - tx) * (1 - ty) * tl + tx * (1 - ty) * tr + (1 - tx) * ty * bl + tx * ty * br
    return Image.fromarray(np.clip(arr, 0, 255).round().astype(np.uint8), "RGB")


def cap_height(font: ImageFont.FreeTypeFont) -> int:
    """Height of a capital `H` in this face, in pixels."""
    probe = Image.new("L", (400, 400), 0)
    ImageDraw.Draw(probe).text((50, 50), "H", font=font, fill=255)
    box = probe.getbbox()
    return box[3] - box[1]


def size_for_cap(path: str, target_cap: float) -> ImageFont.FreeTypeFont:
    """Largest face size whose cap height does not exceed `target_cap`.

    Measured rather than computed from the font's `unitsPerEm`, so it works the
    same for any fallback face.
    """
    ref = 200
    ref_cap = cap_height(ImageFont.truetype(path, ref))
    size = max(1, int(round(ref * target_cap / ref_cap)))
    # Land on the size closest to the target (the rounding above can overshoot).
    best = min(
        (size + d for d in (-1, 0, 1)),
        key=lambda s: abs(cap_height(ImageFont.truetype(path, s)) - target_cap),
    )
    return ImageFont.truetype(path, best)


def text_layer(text: str, font: ImageFont.FreeTypeFont) -> Image.Image:
    """White text on transparency, cropped to its ink bounding box."""
    canvas = Image.new("RGBA", (4096, 512), (0, 0, 0, 0))
    ImageDraw.Draw(canvas).text((100, 100), text, font=font, fill=TEXT_COLOUR + (255,))
    box = canvas.getbbox()
    if not box:
        raise SystemExit(f"error: nothing rendered for {text!r}")
    return canvas.crop(box)


def render() -> tuple[Image.Image, list[tuple[str, ImageFont.FreeTypeFont, tuple[int, int]]]]:
    img = gradient(W, H)
    placed = []
    for text, role, target_cap, ink_top in LINES:
        font = size_for_cap(resolve_font(role), target_cap)
        layer = text_layer(text, font)
        x = (W - layer.width) // 2
        img.paste(layer, (x, ink_top), layer)
        placed.append((text, font, (x, ink_top, layer.width, layer.height)))
    return img, placed


def render_preview(img: Image.Image, path: str) -> None:
    """Mock up the banner as F-Droid shows it: scaled to the listing width."""
    widths = [1024, 720, 360]
    gap, head = 12, 22
    sheet = Image.new(
        "RGB",
        (max(widths) + gap * 2, head + sum(w * H // W + gap for w in widths) + gap),
        (245, 246, 248),
    )
    d = ImageDraw.Draw(sheet)
    y = head
    for w in widths:
        h = w * H // W
        d.text((gap, y - 16), f"{w}px wide", fill=(90, 90, 90))
        sheet.paste(img.resize((w, h), Image.LANCZOS), (gap, y))
        y += h + gap
    sheet.save(path)
    print(f"preview  -> {path}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=DEFAULT_OUT, help="output PNG (default: en-US featureGraphic)")
    ap.add_argument("--preview", help="also write a scaled-down mock-up PNG here")
    args = ap.parse_args()

    img, placed = render()
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    img.save(args.out)
    print(f"canvas   : {W}x{H}")
    print(f"gradient : TL {CORNER_TL} TR {CORNER_TR} BL {CORNER_BL} BR {CORNER_BR}")
    for text, font, (x, y, w, h) in placed:
        print(f"  {text[:44]!r:<48} ink {w}x{h} at ({x},{y})"
              f"  [{os.path.basename(font.path)} {font.size}px cap={cap_height(font)}]")
    print(f"written  -> {args.out}")

    if args.preview:
        os.makedirs(os.path.dirname(os.path.abspath(args.preview)), exist_ok=True)
        render_preview(img, args.preview)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
