"""Render docs/media/social-preview.png (1280 x 640), the GitHub repository social card.

Usage:
    python -I scripts/demo-gif/social.py [--out docs/media/social-preview.png]

Needs Pillow and the Segoe UI and Cascadia fonts from C:/Windows/Fonts. Colors are the dark-green palette
of the project's briefing deck.
"""

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
FONTS = Path("C:/Windows/Fonts")

BG = (0x12, 0x1D, 0x17)  # #121D17
PANEL = (0x18, 0x26, 0x20)  # #182620
BORDER = (0x2E, 0x41, 0x37)  # #2E4137
TEXT = (0xE6, 0xEE, 0xE8)  # #E6EEE8
DIM = (0x8E, 0xA0, 0x94)  # #8EA094
ACCENT = (0x36, 0xB9, 0x7A)  # #36B97A
INK = (0x7E, 0xD8, 0xA9)  # #7ED8A9

W, H = 1280, 640
SCALE = 4  # the motif is drawn at 4x and reduced for smooth edges

TITLE = "pqbind"
TAGLINE = "Post-quantum authentication for connections that already have post-quantum key exchange"
SUPPORT = "Hybrid Ed25519 + ML-DSA-87 proofs bound to the TLS exporter"


def wrap(draw, text, font, max_width):
    lines, line = [], ""
    for word in text.split():
        trial = f"{line} {word}".strip()
        if draw.textlength(trial, font=font) <= max_width:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def draw_motif(box):
    """Two linked nodes with a padlock between them, inside a panel. Returns the motif as an RGBA image."""
    x0, y0, x1, y1 = box
    width, height = x1 - x0, y1 - y0
    s = SCALE
    image = Image.new("RGBA", (width * s, height * s), (0, 0, 0, 0))
    d = ImageDraw.Draw(image)
    d.rounded_rectangle((0, 0, width * s - 1, height * s - 1), radius=22 * s, fill=PANEL, outline=BORDER, width=2 * s)

    cx, cy = width // 2, height // 2 - 14
    node_dx = 104
    r = 34
    left, right = (cx - node_dx, cy), (cx + node_dx, cy)

    # Faint rings around the nodes.
    for center in (left, right):
        for extra, color in ((20, BORDER),):
            d.ellipse(
                ((center[0] - r - extra) * s, (center[1] - r - extra) * s, (center[0] + r + extra) * s, (center[1] + r + extra) * s),
                outline=color,
                width=2 * s,
            )
    # The link between the nodes.
    d.line((left[0] * s, cy * s, right[0] * s, cy * s), fill=ACCENT, width=5 * s)
    # The nodes.
    for center in (left, right):
        d.ellipse(((center[0] - r) * s, (center[1] - r) * s, (center[0] + r) * s, (center[1] + r) * s), fill=BG, outline=ACCENT, width=5 * s)
        d.ellipse(((center[0] - 12) * s, (center[1] - 12) * s, (center[0] + 12) * s, (center[1] + 12) * s), fill=INK)

    # The padlock in the middle of the link.
    body_w, body_h = 60, 48
    bx0, by0 = cx - body_w // 2, cy - 6
    d.rounded_rectangle((bx0 * s, by0 * s, (bx0 + body_w) * s, (by0 + body_h) * s), radius=9 * s, fill=ACCENT)
    # The shackle: an outer rounded block in the light ink with the inside punched out in the panel color.
    d.rounded_rectangle(((cx - 19) * s, (by0 - 28) * s, (cx + 19) * s, (by0 + 6) * s), radius=19 * s, fill=INK)
    d.rounded_rectangle(((cx - 10) * s, (by0 - 19) * s, (cx + 10) * s, (by0 + 8) * s), radius=10 * s, fill=PANEL)
    d.rounded_rectangle((bx0 * s, by0 * s, (bx0 + body_w) * s, (by0 + body_h) * s), radius=9 * s, fill=ACCENT)
    d.ellipse(((cx - 6) * s, (by0 + 13) * s, (cx + 6) * s, (by0 + 25) * s), fill=BG)
    d.rounded_rectangle(((cx - 3) * s, (by0 + 22) * s, (cx + 3) * s, (by0 + 36) * s), radius=2 * s, fill=BG)

    return image.resize((width, height), Image.LANCZOS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(ROOT / "docs" / "media" / "social-preview.png"))
    args = parser.parse_args()

    image = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(image)

    # A thin accent bar at the top edge and a hairline frame.
    draw.rectangle((0, 0, W, 6), fill=ACCENT)

    title_font = ImageFont.truetype(str(FONTS / "segoeuib.ttf"), 148)
    tag_font = ImageFont.truetype(str(FONTS / "segoeuisl.ttf"), 40)
    support_font = ImageFont.truetype(str(FONTS / "CascadiaMono.ttf"), 23)

    left = 84
    draw.text((left - 4, 70), TITLE, font=title_font, fill=TEXT)

    text_width = 700
    y = 296
    for line in wrap(draw, TAGLINE, tag_font, text_width):
        draw.text((left, y), line, font=tag_font, fill=INK)
        y += 56

    # The motif panel on the right.
    box = (870, 110, 1200, 450)
    motif = draw_motif(box)
    image.paste(motif, (box[0], box[1]), motif)
    label_font = ImageFont.truetype(str(FONTS / "segoeui.ttf"), 22)
    cx = (box[0] + box[2]) // 2
    cy = box[1] + (box[3] - box[1]) // 2 - 14
    for dx, name in ((-104, "client"), (104, "server")):
        draw.text((cx + dx, cy + 78), name, font=label_font, fill=DIM, anchor="mm")
    draw.text((cx, cy + 128), "Ed25519 + ML-DSA-87", font=ImageFont.truetype(str(FONTS / "CascadiaMono.ttf"), 17), fill=DIM, anchor="mm")

    # The supporting line along the bottom, above a hairline.
    draw.line((left, 520, W - left, 520), fill=BORDER, width=2)
    draw.text((left, 548), SUPPORT, font=support_font, fill=DIM)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    image.save(out, optimize=True)
    print(f"{out}: {image.size[0]}x{image.size[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
