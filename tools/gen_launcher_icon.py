#!/usr/bin/env python3
"""Generate the Android adaptive launcher icon for 5G-Proxy-Client.

The artwork of record is the store listing icon:
    fastlane/metadata/android/en-US/images/icon.png

That file is a *store graphic*, not a launcher icon: it carries a decorative
rounded frame and a "5G-PROXY-CLIENT" wordmark.  Neither survives the trip to a
48dp launcher icon (the wordmark renders ~4dp tall, i.e. a smudge; the frame
would double up with the launcher's own mask).  So this script lifts the logo
out of the frame, white-keys it so it composites cleanly over the adaptive
background colour, and re-emits it as the adaptive-icon foreground at every
density bucket -- plus a monochrome layer for Android 13+ themed icons.

Geometry.  Layers are 108x108dp and the platform only ever shows the middle of
them:

    // frameworks/base/graphics/java/android/graphics/drawable/AdaptiveIconDrawable.java
    private static final float DEFAULT_VIEW_PORT_SCALE = 1f / (1 + 2 * EXTRA_INSET_PERCENTAGE);  // 2/3
    int insetWidth = (int) (bounds.width() / (DEFAULT_VIEW_PORT_SCALE * 2));                    // 0.75 * w
    outRect.set(cX - insetWidth, cY - insetHeight, cX + insetWidth, cY + insetHeight);          // 1.5x

i.e. each layer is laid out at 1.5x the icon bounds, so the *visible* region is
the central 72x72dp.  The docs add that the logo "must not exceed 66x66dp,
because the inner 66x66dp of the icon appears within the masked viewport".

This logo is 1.43:1, so a width of 60dp is the sweet spot: it reads at 83% of
the visible width without the horizontal extremes colliding with a circular
OEM mask (a 66dp-wide logo visibly touches it).

The white-key is exact rather than a threshold: for a logo flattened onto a
white background,  alpha = 1 - min(r,g,b)/255  and
colour = (observed - 255*(1-alpha)) / alpha.  Composited back over white this
reproduces the source pixel-for-pixel, so nothing is lost visually.

Usage (from the repo root):

    python tools/gen_launcher_icon.py
    python tools/gen_launcher_icon.py --preview /tmp/icon_preview.png
"""

from __future__ import annotations

import argparse
import os
import sys

import numpy as np
from PIL import Image, ImageDraw

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join(
    REPO, "fastlane", "metadata", "android", "en-US", "images", "icon.png"
)
RES = os.path.join(REPO, "app", "src", "main", "res")

CANVAS_DP = 108.0
LOGO_W_DP = 60.0
# Central fraction of the layer an OEM mask actually shows (see module docstring).
VISIBLE_FRACTION = 72.0 / 108.0

# Logo bounding box inside the 512x512 source, in source pixels.  Measured:
# the real artwork spans x 70..442, y 90..348; this adds a ~3px margin so
# anti-aliased edges are not clipped, while staying clear of the frame's inner
# glow (ends ~x53) and the wordmark (starts ~y368).
CROP = (67, 87, 446, 353)

# Below this alpha the source is the artwork's soft drop shadow, not the mark.
MONO_ALPHA_FLOOR = 48

DENSITIES = {
    "mdpi": 1.0,
    "hdpi": 1.5,
    "xhdpi": 2.0,
    "xxhdpi": 3.0,
    "xxxhdpi": 4.0,
}


def white_key(img: Image.Image) -> Image.Image:
    """Turn the white backdrop of a flattened logo into transparency."""
    arr = np.asarray(img.convert("RGB")).astype(np.float64)
    alpha = np.clip(1.0 - arr.min(axis=2) / 255.0, 0.0, 1.0)
    safe = np.maximum(alpha, 1e-6)[..., None]
    colour = np.clip((arr - 255.0 * (1.0 - alpha)[..., None]) / safe, 0.0, 255.0)
    out = np.dstack([colour, alpha * 255.0]).round().astype(np.uint8)
    return Image.fromarray(out, "RGBA")


def to_monochrome(logo: Image.Image) -> Image.Image:
    """Flatten the logo to an opaque-black silhouette for themed icons.

    Android tints this layer with a single colour, so only the alpha carries
    meaning.  The source's soft shadow is dropped -- left in, it renders as a
    grey halo around the tinted mark.
    """
    alpha = np.asarray(logo.getchannel("A")).astype(np.float64)
    alpha = np.clip((alpha - MONO_ALPHA_FLOOR) * 255.0 / (255.0 - MONO_ALPHA_FLOOR), 0, 255)
    black = np.zeros(alpha.shape + (3,), dtype=np.uint8)
    return Image.fromarray(np.dstack([black, alpha.round().astype(np.uint8)]), "RGBA")


def build_layer(art: Image.Image, canvas_px: int) -> Image.Image:
    """Centre the art in a transparent canvas of the requested pixel size."""
    target_w = max(1, round(LOGO_W_DP / CANVAS_DP * canvas_px))
    target_h = max(1, round(art.height * target_w / art.width))
    scaled = art.resize((target_w, target_h), Image.LANCZOS)
    canvas = Image.new("RGBA", (canvas_px, canvas_px), (0, 0, 0, 0))
    canvas.paste(
        scaled,
        ((canvas_px - target_w) // 2, (canvas_px - target_h) // 2),
        scaled,
    )
    return canvas


def as_displayed(layer: Image.Image, icon_px: int, bg=(255, 255, 255, 255)) -> Image.Image:
    """Crop the central 72dp of a layer and scale it to the icon size."""
    m = round(layer.size[0] * VISIBLE_FRACTION)
    o = (layer.size[0] - m) // 2
    vis = layer.crop((o, o, o + m, o + m)).resize((icon_px, icon_px), Image.LANCZOS)
    out = Image.new("RGBA", (icon_px, icon_px), bg)
    out.alpha_composite(vis)
    return out


def mask_shape(img: Image.Image, shape: str) -> Image.Image:
    px = img.size[0]
    if shape == "none":
        return img
    mask = Image.new("L", (px, px), 0)
    md = ImageDraw.Draw(mask)
    if shape == "circle":
        md.ellipse((0, 0, px - 1, px - 1), fill=255)
    else:
        md.rounded_rectangle((0, 0, px - 1, px - 1), radius=int(px * 0.22), fill=255)
    out = img.copy()
    out.putalpha(mask)
    return out


def render_preview(logo: Image.Image, mono: Image.Image, path: str) -> None:
    """Mock up how the icon reads under Android's mask shapes and sizes."""
    render_px = 432  # same as xxxhdpi, so the mock-up is not resolution-limited
    variants = [
        ("colour / squircle", build_layer(logo, render_px), "squircle", (255, 255, 255, 255)),
        ("colour / circle", build_layer(logo, render_px), "circle", (255, 255, 255, 255)),
        ("themed / monochrome", build_layer(mono, render_px), "squircle", (222, 233, 250, 255)),
    ]
    sizes = [192, 96, 48]
    cell, head, label_w = 210, 26, 150

    sheet = Image.new(
        "RGB", (label_w + cell * len(variants), head + cell * len(sizes)), (245, 246, 248)
    )
    d = ImageDraw.Draw(sheet)
    for c, (label, *_rest) in enumerate(variants):
        d.text((label_w + c * cell + 8, 8), label, fill=(70, 70, 70))
    for r, size in enumerate(sizes):
        d.text((8, head + r * cell + size // 2), f"{size}px", fill=(90, 90, 90))
        for c, (_label, layer, shape, bg) in enumerate(variants):
            im = mask_shape(as_displayed(layer, size, bg), shape)
            ox = label_w + c * cell + (cell - size) // 2
            oy = head + r * cell + (cell - size) // 2
            sheet.paste(im, (ox, oy), im)
    sheet.save(path)
    print(f"preview  -> {path}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", default=DEFAULT_SRC, help="source artwork (PNG)")
    ap.add_argument("--preview", help="also write a masked mock-up PNG here")
    args = ap.parse_args()

    if not os.path.isfile(args.src):
        print(f"error: source artwork not found: {args.src}", file=sys.stderr)
        return 1

    logo = white_key(Image.open(args.src).convert("RGB").crop(CROP))
    mono = to_monochrome(logo)
    # The visible 72dp of the layer is what maps to the icon, so the logo's
    # on-screen share is LOGO_W_DP/72, not LOGO_W_DP/108.
    shown = LOGO_W_DP / (CANVAS_DP * VISIBLE_FRACTION)
    print(f"source   : {args.src}")
    print(f"crop     : {CROP}  -> {logo.size[0]}x{logo.size[1]} px")
    print(f"logo     : {LOGO_W_DP:.0f}dp wide in the 108dp layer"
          f" -> fills {shown * 100:.0f}% of the icon's width"
          f" ({LOGO_W_DP * 48 / 72:.0f}dp wide in a 48dp icon)")

    for bucket, scale in DENSITIES.items():
        canvas_px = round(CANVAS_DP * scale)
        out_dir = os.path.join(RES, f"mipmap-{bucket}")
        os.makedirs(out_dir, exist_ok=True)
        build_layer(logo, canvas_px).save(os.path.join(out_dir, "ic_launcher_foreground.png"))
        build_layer(mono, canvas_px).save(os.path.join(out_dir, "ic_launcher_monochrome.png"))
        print(f"layer    -> mipmap-{bucket}/ic_launcher_{{foreground,monochrome}}.png"
              f"  ({canvas_px}x{canvas_px})")

    if args.preview:
        os.makedirs(os.path.dirname(os.path.abspath(args.preview)), exist_ok=True)
        render_preview(logo, mono, args.preview)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
