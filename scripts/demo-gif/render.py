"""Render docs/media/demo.gif and docs/media/demo-poster.png from the captured transcript.

Usage:
    python -I scripts/demo-gif/render.py [--work-dir DIR] [--ffmpeg PATH]

Reads docs/media/demo.transcript.json (written by capture.py). The text of the demo is drawn exactly as
captured; only the pacing is synthetic. Lines appear one after another with a pause before each scenario
heading and a longer pause after each verdict, and the final summary table stays on screen for about three
seconds. Colors come from simple rules on the text and never change it.

The summary table is 177 columns wide, so when it starts the terminal switches to a smaller font (like
pressing Ctrl+minus) so that every column fits without wrapping.

Needs Pillow and an ffmpeg executable (for the palette). Temporary frames go to --work-dir (default: a
temporary folder) and are not part of the repository.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[2]
FONT_DIR = Path("C:/Windows/Fonts")
MONO = FONT_DIR / "CascadiaMono.ttf"
UI = FONT_DIR / "segoeui.ttf"

# Colors.
# Palette of the maintainer's dark-green briefing deck.
CANVAS = (8, 14, 11)  # the margin around the window, a little darker than the window
WINDOW = (0x12, 0x1D, 0x17)  # #121D17
TITLEBAR = (0x18, 0x26, 0x20)  # #182620
BORDER = (0x2E, 0x41, 0x37)  # #2E4137
C = {
    "default": (0xE6, 0xEE, 0xE8),  # #E6EEE8
    "bright": (0xE6, 0xEE, 0xE8),
    "observed": (0xE6, 0xEE, 0xE8),
    "dim": (0x8E, 0xA0, 0x94),  # #8EA094
    "green": (0x7E, 0xD8, 0xA9),  # #7ED8A9 (accent ink; verdicts)
    "greenb": (0x36, 0xB9, 0x7A),  # #36B97A (accent; prompt, final line)
    "amber": (0xE2, 0xB5, 0x5A),  # #E2B55A
    "red": (0xE2, 0x6A, 0x5B),  # #E26A5B
    "teal": (0x7E, 0xD8, 0xA9),  # accent ink for the scenario tags
    "rule": (0x2E, 0x41, 0x37),
    "cursor": (0x8E, 0xA0, 0x94),
}

# Window geometry (pixels).
CANVAS_W = 1024
MARGIN = 16
WIN_W = CANVAS_W - 2 * MARGIN
TITLE_H = 34
BODY_PAD_X = 18
BODY_PAD_Y = 12
BODY_H = 588  # 28 rows in the normal view
WIN_H = TITLE_H + BODY_H + 2 * BODY_PAD_Y
CANVAS_H = WIN_H + 2 * MARGIN

# Two terminal views: the normal view and a zoomed-out view for the wide summary table.
VIEWS = {
    "normal": {"size": 16, "line_h": 21},
    "wide": {"size": 9.1, "line_h": 13},
}

# Column widths of the summary table (ID, Scenario, Expected, Observed), from the demo's own format string.
TABLE_COLS = (4, 70, 46, 46)

LABEL_RE = re.compile(r"^(    )(Story:|Expected:|Observed:|Verdict:|Note:)(\s*)(.*)$")
HEADING_RE = re.compile(r"^(\[[a-z0-9]+\])(.*)$")
RED_RE = re.compile(r"Err\([A-Za-z0-9_]+\)|REFUSED|Refused")
LABEL_COLORS = {"Story:": "dim", "Expected:": "dim", "Observed:": "observed", "Verdict:": "default", "Note:": "amber"}

# Pacing in seconds.
PACE = {
    "type_start": 0.7,
    "type_char": 0.07,
    "type_end": 0.55,
    "line": 0.075,
    "blank": 0.05,
    "heading_pause": 0.35,
    "after_verdict": 0.95,
    "after_note": 1.35,
    "before_summary": 0.6,
    "table_row": 0.2,
    "final_hold": 3.2,
}


def load_font(path, size, weight):
    font = ImageFont.truetype(str(path), size)
    try:
        font.set_variation_by_name(weight)
    except (OSError, AttributeError):
        pass
    return font


class Fonts:
    def __init__(self, mono_path):
        self.table = {}
        for name, view in VIEWS.items():
            self.table[(name, False)] = load_font(mono_path, view["size"], "Regular")
            self.table[(name, True)] = load_font(mono_path, view["size"], "Bold")

    def get(self, view, bold):
        return self.table[(view, bold)]

    def cell(self, view):
        return self.table[(view, False)].getlength("M")


# ----------------------------------------------------------------------------------------------
# Styling: simple rules on the text. Each line becomes a list of (text, color, bold) segments whose
# text joins back to exactly the captured line.
# ----------------------------------------------------------------------------------------------


def with_red(text, color, bold=False):
    segments = []
    position = 0
    for match in RED_RE.finditer(text):
        if match.start() > position:
            segments.append((text[position:match.start()], color, bold))
        segments.append((match.group(0), "red", bold))
        position = match.end()
    if position < len(text):
        segments.append((text[position:], color, bold))
    return segments


def style_paragraph(text, label_color, label):
    if label == "Verdict:":
        if text.strip() == "as expected":
            return [(text, "green", True)]
        if text.strip().upper() == "NOT AS EXPECTED":
            return [(text, "red", True)]
    return with_red(text, label_color)


def style_line(text, state):
    """Return (segments, rule_below, new_state). state is the paragraph label or 'summary'."""
    if text == "":
        return [], False, None if state != "summary" else "summary"
    if state == "summary":
        if text.startswith("All "):
            return [(text, "greenb", True)], False, state
        if text.startswith("ID "):
            return [(text, "bright", True)], True, state
        if text.startswith("Summary"):
            return [(text, "bright", True)], False, state
        cuts = [0]
        for width in TABLE_COLS:
            cuts.append(cuts[-1] + width)
        cuts.append(len(text))
        id_col = text[cuts[0]:cuts[1]]
        title = text[cuts[1]:cuts[2]]
        expected = text[cuts[2]:cuts[3]]
        observed = text[cuts[3]:cuts[4]]
        rest = text[cuts[4]:]
        segments = [(id_col, "teal", True), (title, "default", False)]
        segments += with_red(expected, "dim")
        segments += with_red(observed, "observed")
        segments += with_red(rest, "default")
        joined = "".join(s[0] for s in segments)
        assert joined == text
        return recolor_verdict(segments), False, state
    if text.startswith("Summary (transport"):
        return [(text, "bright", True)], False, "summary"
    heading = HEADING_RE.match(text)
    if heading:
        return [(heading.group(1), "teal", True), (heading.group(2), "bright", True)], False, None
    if text.startswith("pqbind demo (transport"):
        return [(text, "bright", True)], False, None
    label = LABEL_RE.match(text)
    if label:
        lead, name, gap, rest = label.groups()
        color = LABEL_COLORS[name]
        segments = [(lead, color, False), (name, color if name != "Verdict:" else "observed", name in ("Observed:", "Verdict:"))]
        segments.append((gap, color, False))
        segments += style_paragraph(rest, color, name)
        return segments, False, name
    if state in LABEL_COLORS and text.startswith(" " * 14):
        color = LABEL_COLORS[state]
        return [(text[:14], color, False)] + style_paragraph(text[14:], color, state), False, state
    return [(text, "default", False)], False, state


def recolor_verdict(segments):
    """Make the trailing 'as expected' of a table row green and bold."""
    out = []
    for text, color, bold in segments:
        index = text.find("as expected")
        if index >= 0:
            if index:
                out.append((text[:index], color, bold))
            out.append(("as expected", "green", True))
            tail = text[index + len("as expected"):]
            if tail:
                out.append((tail, color, bold))
        else:
            out.append((text, color, bold))
    return out


# ----------------------------------------------------------------------------------------------
# Drawing
# ----------------------------------------------------------------------------------------------


def make_base(ui_font_path):
    scale = 4
    size = (CANVAS_W * scale, CANVAS_H * scale)
    big = Image.new("RGB", size, CANVAS)
    win = (MARGIN * scale, MARGIN * scale, (MARGIN + WIN_W) * scale, (MARGIN + WIN_H) * scale)
    radius = 14 * scale
    shadow = Image.new("L", size, 0)
    ImageDraw.Draw(shadow).rounded_rectangle(
        (win[0] + 4 * scale, win[1] + 10 * scale, win[2] - 4 * scale, win[3] + 8 * scale), radius, fill=170
    )
    shadow = shadow.filter(ImageFilter.GaussianBlur(16 * scale))
    big.paste((0, 0, 0), mask=shadow)
    draw = ImageDraw.Draw(big)
    draw.rounded_rectangle(win, radius, fill=WINDOW)
    bar = (win[0], win[1], win[2], win[1] + TITLE_H * scale)
    draw.rounded_rectangle(bar, radius, fill=TITLEBAR, corners=(True, True, False, False))
    draw.rectangle((win[0], bar[3] - scale, win[2], bar[3]), fill=BORDER)
    draw.rounded_rectangle(win, radius, outline=BORDER, width=scale)
    for index, color in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        cx = win[0] + (24 + index * 22) * scale
        cy = win[1] + (TITLE_H // 2) * scale
        r = 6 * scale
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=color)
    base = big.resize((CANVAS_W, CANVAS_H), Image.LANCZOS)
    draw = ImageDraw.Draw(base)
    ui = ImageFont.truetype(str(ui_font_path), 14)
    draw.text((CANVAS_W / 2, MARGIN + TITLE_H / 2), "pqbind", font=ui, fill=C["dim"], anchor="mm")
    return base


class Renderer:
    def __init__(self, mono_path, ui_path):
        self.fonts = Fonts(mono_path)
        self.base = make_base(ui_path)

    def render(self, lines, view, cursor=None):
        """lines: list of (segments, rule_below) already limited to what is shown. cursor: (row, col) or None."""
        image = self.base.copy()
        draw = ImageDraw.Draw(image)
        geo = VIEWS[view]
        cell = self.fonts.cell(view)
        line_h = geo["line_h"]
        x0 = MARGIN + BODY_PAD_X
        y0 = MARGIN + TITLE_H + BODY_PAD_Y
        rows = BODY_H // line_h
        shown = lines[-(rows - (1 if cursor else 0)):] if cursor else lines[-rows:]
        ascent = self.fonts.get(view, False).getmetrics()[0]
        pad = (line_h - (ascent + self.fonts.get(view, False).getmetrics()[1])) / 2
        for row, (segments, rule) in enumerate(shown):
            col = 0
            baseline = y0 + row * line_h + pad + ascent
            for text, color, bold in segments:
                if text.strip():
                    draw.text((x0 + col * cell, baseline), text, font=self.fonts.get(view, bold), fill=C[color], anchor="ls")
                col += len(text)
            if rule:
                y = y0 + (row + 1) * line_h - 2
                draw.line((x0, y, x0 + 177 * cell, y), fill=C["rule"], width=1)
        if cursor is not None:
            row, col = cursor
            row = min(row, rows - 1)
            cx = x0 + col * cell
            cy = y0 + row * line_h + 2
            draw.rectangle((cx, cy, cx + cell - 1, cy + line_h - 5), fill=C["cursor"])
        return image


# ----------------------------------------------------------------------------------------------
# Timeline
# ----------------------------------------------------------------------------------------------

PROMPT_PREFIX = "$ "
PROMPT_COMMAND = "pqbind demo"


def prompt_segments(typed):
    segments = [(PROMPT_PREFIX, "greenb", True)]
    if typed:
        segments.append((PROMPT_COMMAND[:typed], "bright", False))
    return segments


def build_states(transcript, group):
    """Return a list of (n_lines, typed, view, cursor, hold_seconds) states and the styled buffer."""
    styled = []
    state = None
    for item in transcript["lines"]:
        segments, rule, state = style_line(item["text"], state)
        assert "".join(s[0] for s in segments) == item["text"], "styling must not change the text"
        styled.append((segments, rule))
    texts = [item["text"] for item in transcript["lines"]]

    states = []  # (n, typed, view, cursor_flag, hold)
    states.append((0, 0, "normal", True, PACE["type_start"]))
    for count in range(1, len(PROMPT_COMMAND) + 1):
        hold = PACE["type_end"] if count == len(PROMPT_COMMAND) else PACE["type_char"]
        states.append((0, count, "normal", True, hold))

    view = "normal"
    in_summary = False
    for index, text in enumerate(texts):
        nxt = texts[index + 1] if index + 1 < len(texts) else None
        if text.startswith("Summary (transport"):
            view = "wide"
            in_summary = True
        hold = PACE["blank"] if text == "" else PACE["line"]
        if in_summary and text and not text.startswith("Summary"):
            hold = PACE["table_row"]
        if text.startswith("Summary (transport"):
            hold = PACE["table_row"]
        if HEADING_RE.match(text) or text.startswith("Summary (transport"):
            if states:
                last = states[-1]
                states[-1] = (last[0], last[1], last[2], last[3], last[4] + (PACE["before_summary"] if in_summary else PACE["heading_pause"]))
        # A verdict lingers; when a note follows, the note lingers instead.
        if LABEL_RE.match(text) and LABEL_RE.match(text).group(2) == "Verdict:":
            note_follows = nxt is not None and LABEL_RE.match(nxt) and LABEL_RE.match(nxt).group(2) == "Note:"
            hold = 0.3 if note_follows else PACE["after_verdict"]
        if state_is_note_end(texts, index):
            hold = PACE["after_note"]
        if index == len(texts) - 1:
            hold = PACE["final_hold"]
        states.append((index + 1, len(PROMPT_COMMAND), view, not in_summary, hold))
    return styled, merge_fast_states(states, group)


def merge_fast_states(states, group):
    """Show runs of quickly printed lines in groups of `group` lines per frame (fewer frames, a smaller file)."""
    if group <= 1:
        return states
    merged = []
    pending = 0
    for state in states:
        n, typed, view, cursor_flag, hold = state
        fast = n > 0 and hold <= PACE["line"] + 1e-9 and typed == len(PROMPT_COMMAND)
        if fast and merged and merged[-1][5] < group and merged[-1][5] > 0:
            previous = merged[-1]
            merged[-1] = (n, typed, view, cursor_flag, previous[4] + hold, previous[5] + 1)
        else:
            merged.append((n, typed, view, cursor_flag, hold, 1 if fast else 0))
    return [state[:5] for state in merged]


def state_is_note_end(texts, index):
    """True for the last line of a Note paragraph (the next line is blank)."""
    # Find the paragraph label this line belongs to by walking back to the last labeled line.
    nxt = texts[index + 1] if index + 1 < len(texts) else ""
    if nxt != "":
        return False
    for back in range(index, -1, -1):
        match = LABEL_RE.match(texts[back])
        if match:
            return match.group(2) == "Note:"
        if texts[back] == "" or not texts[back].startswith(" " * 14):
            return False
    return False


def lines_for_state(styled, n, typed):
    prompt = (prompt_segments(typed), False)
    return [prompt] + styled[:n]


def cursor_for_state(renderer_view, styled, n, typed, cursor_flag, view):
    if not cursor_flag:
        return None
    if n == 0:
        return (0, len(PROMPT_PREFIX) + typed)
    return (n + 1, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transcript", default=str(ROOT / "docs" / "media" / "demo.transcript.json"))
    parser.add_argument("--out-dir", default=str(ROOT / "docs" / "media"))
    parser.add_argument("--work-dir", default=None, help="folder for the temporary frames (default: a temporary folder)")
    parser.add_argument("--ffmpeg", default=shutil.which("ffmpeg") or "ffmpeg")
    parser.add_argument("--colors", type=int, default=40)
    parser.add_argument("--group", type=int, default=3, help="quickly printed lines shown per frame")
    args = parser.parse_args()

    transcript = json.loads(Path(args.transcript).read_text(encoding="utf-8"))
    if transcript.get("exit_code") != 0:
        print("the transcript is of a run that did not exit 0; refusing to render", file=sys.stderr)
        return 1
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="pqbind-gif-"))
    frames_dir = work / "frames"
    frames_dir.mkdir(parents=True, exist_ok=True)
    for old in frames_dir.glob("*.png"):
        old.unlink()

    renderer = Renderer(MONO, UI)
    styled, states = build_states(transcript, args.group)

    list_lines = []
    total = 0.0
    last_path = None
    for number, (n, typed, view, cursor_flag, hold) in enumerate(states):
        lines = lines_for_state(styled, n, typed)
        cursor = cursor_for_state(renderer, styled, n, typed, cursor_flag, view)
        image = renderer.render(lines, view, cursor)
        path = frames_dir / f"frame{number:04d}.png"
        image.save(path)
        last_path = path
        list_lines.append(f"file '{path.as_posix()}'")
        list_lines.append(f"duration {hold:.3f}")
        total += hold
    list_lines.append(f"file '{last_path.as_posix()}'")  # the concat demuxer needs the last frame twice
    list_file = work / "frames.txt"
    list_file.write_text("\n".join(list_lines) + "\n", encoding="utf-8", newline="\n")

    # The poster is the last frame: the summary table, without the cursor.
    final = states[-1]
    poster = renderer.render(lines_for_state(styled, final[0], final[1]), final[2], None)
    poster.save(out_dir / "demo-poster.png", optimize=True)

    gif_path = out_dir / "demo.gif"
    filter_graph = (
        f"split[a][b];[a]palettegen=max_colors={args.colors}:stats_mode=full[p];"
        "[b][p]paletteuse=dither=none:diff_mode=rectangle"
    )
    command = [
        args.ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
        "-f", "concat", "-safe", "0", "-i", str(list_file),
        "-vf", filter_graph, "-fps_mode", "vfr", "-loop", "0", str(gif_path),
    ]
    subprocess.run(command, check=True)

    with Image.open(gif_path) as gif:
        frames = gif.n_frames
        duration = 0
        for frame in range(frames):
            gif.seek(frame)
            duration += gif.info.get("duration", 0)
    size_mb = gif_path.stat().st_size / (1024 * 1024)
    print(f"planned {total:.2f} s over {len(states)} states")
    print(f"{gif_path}: {frames} frames, {duration / 1000:.2f} s, {size_mb:.2f} MB, {CANVAS_W}x{CANVAS_H}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
