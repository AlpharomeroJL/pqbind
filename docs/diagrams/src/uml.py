"""UML 2.5 primitives for the pqbind diagrams, drawn as inline SVG.

Adapted from the briefing deck engine. Notation follows UML 2.5.1: diagram frames with a kind and name heading,
components with ball and socket assemblies and ports, deployment nodes as cubes, sequence lifelines with execution
specifications and combined fragments, class boxes, and state machine pseudostates.

Colors come from the design tokens through CSS variables. Elements carry three marker classes that the layout check
in render.py reads: `bx` groups a box whose text must stay inside its `bxr` rectangle, `w` marks a wire (a message,
flow, dependency or connector) that no label may cross, and `ob` marks a solid shape (an activation bar, a ball, a
port, a pseudostate) that no label may cover.
"""
import math
from xml.sax.saxutils import escape

INK, INK2, INK3 = "var(--ink-1)", "var(--ink-2)", "var(--ink-3)"
LINE, LINE2 = "var(--line)", "var(--line-2)"
PAPER, RAISED, RAISED2 = "var(--paper)", "var(--raised)", "var(--raised-2)"
ACC, ACCI, ACCS, ACCL = "var(--accent)", "var(--accent-ink)", "var(--accent-soft)", "var(--accent-line)"
AMB, AMBS = "var(--amber)", "var(--amber-soft)"
REC, RECS = "var(--rec)", "var(--rec-soft)"
SANS, MONO = "var(--sans)", "var(--mono)"
W, H = 816, 548


def tw(s, size=14, weight=400, font=SANS):
    """An estimate of the rendered width of `s`, for spacing legends and tabs. The layout check measures the real text."""
    if font == MONO:
        return len(s) * size * 0.6
    total = 0.0
    for ch in s:
        if ch in "il.,:;'!|()[]{} jtfr":
            total += 0.3
        elif ch in "mwMW":
            total += 0.85
        elif ch.isupper():
            total += 0.66
        elif ch.isdigit():
            total += 0.58
        else:
            total += 0.54
    return total * size * (1.04 if weight >= 600 else 1.0)


def _cls(*names):
    names = [n for n in names if n]
    return f' class="{" ".join(names)}"' if names else ""


def text(x, y, s, size=14.5, anchor="start", fill=INK, weight=400, italic=False, font=SANS, under=False, halo=False):
    extra = ' font-style="italic"' if italic else ""
    extra += ' text-decoration="underline"' if under else ""
    return (f'<text{_cls("h" if halo else None)} x="{x}" y="{y}" font-family="{font}" font-size="{size}" '
            f'font-weight="{weight}" text-anchor="{anchor}" fill="{fill}"{extra}>{escape(s)}</text>')


def rect(x, y, w, h, rx=0, fill="none", stroke=LINE2, sw=1.3, dash=None, opacity=None, cls=None):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    o = f' fill-opacity="{opacity}"' if opacity else ""
    return (f'<rect{_cls(cls)} x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"{o} '
            f'stroke="{stroke}" stroke-width="{sw}"{d}/>')


def line(x1, y1, x2, y2, stroke=INK3, sw=1.5, dash=None, wire=False):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<line{_cls("w" if wire else None)} x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="{sw}"{d}/>'


def path(d, stroke=INK3, sw=1.5, fill="none", dash=None, wire=False, cls=None):
    a = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<path{_cls("w" if wire else None, cls)} d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{a}/>'


def group(body, cls="bx"):
    return f'<g class="{cls}">{body}</g>'


def _rot(px, py, ang, x, y):
    c, s = math.cos(ang), math.sin(ang)
    return (round(x + px * c - py * s, 2), round(y + px * s + py * c, 2))


def head_open(x, y, ang, stroke=INK3, sw=1.5, size=10):
    """Open arrowhead: asynchronous messages, replies, dependencies and flows."""
    a, b = _rot(-size, -size * .55, ang, x, y), _rot(-size, size * .55, ang, x, y)
    return path(f"M{a[0]} {a[1]} L{x} {y} L{b[0]} {b[1]}", stroke, sw, wire=True)


def head_filled(x, y, ang, stroke=INK3, size=11):
    """Filled arrowhead: synchronous calls."""
    a, b = _rot(-size, -size * .5, ang, x, y), _rot(-size, size * .5, ang, x, y)
    return path(f"M{a[0]} {a[1]} L{x} {y} L{b[0]} {b[1]} Z", stroke, 1, stroke, wire=True)


def head_triangle(x, y, ang, size=13):
    """Hollow triangle: generalization and realization."""
    a, b = _rot(-size, -size * .6, ang, x, y), _rot(-size, size * .6, ang, x, y)
    return path(f"M{a[0]} {a[1]} L{x} {y} L{b[0]} {b[1]} Z", INK2, 1.4, PAPER, wire=True)


def diamond(x, y, ang, filled=True, size=9):
    """Composite aggregation end at the whole. ang points from the whole toward the part."""
    p = [_rot(0, 0, ang, x, y), _rot(size, -size * .55, ang, x, y), _rot(size * 2, 0, ang, x, y), _rot(size, size * .55, ang, x, y)]
    d = "M" + " L".join(f"{a} {b}" for a, b in p) + " Z"
    return path(d, INK2, 1.3, INK2 if filled else PAPER, wire=True)


def frame(kind, name, w=W, h=H):
    """A diagram frame with its pentagon heading."""
    tab = tw(kind, 15, 700) + tw(name, 15, 500) * 1.06 + 44
    head = (f'<text x="11" y="21" font-family="{SANS}" font-size="15" fill="{INK}">'
            f'<tspan font-weight="700">{escape(kind)}</tspan><tspan font-weight="500" dx="7">{escape(name)}</tspan></text>')
    return (rect(1, 1, w - 2, h - 2, 6, PAPER, LINE2, 1.4)
            + path(f"M1 30 L{tab - 11:.1f} 30 L{tab:.1f} 19 L{tab:.1f} 1", LINE2, 1.4) + head)


def legend(items, y=None, x=16, h=H):
    """A row of swatches. kinds: zone, amber, outside, neutral (boxes); pq, cl, red (solid lines); oob (dashed amber line)."""
    y = h - 25 if y is None else y
    out = ""
    for kind, label in items:
        if kind == "zone":
            out += rect(x, y, 22, 13, 2, ACCS, ACC, 1.3)
        elif kind == "amber":
            out += rect(x, y, 22, 13, 2, AMBS, AMB, 1.3)
        elif kind == "outside":
            out += rect(x, y, 22, 13, 2, RECS, REC, 1.3)
        elif kind == "neutral":
            out += rect(x, y, 22, 13, 2, RAISED2, LINE2, 1.3)
        elif kind == "pq":
            out += line(x, y + 7, x + 22, y + 7, ACC, 2.6)
        elif kind == "cl":
            out += line(x, y + 7, x + 22, y + 7, AMB, 2.6)
        elif kind == "red":
            out += line(x, y + 7, x + 22, y + 7, REC, 2.6)
        elif kind == "oob":
            out += line(x, y + 7, x + 22, y + 7, AMB, 2.2, "5 3")
        out += text(x + 28, y + 11.5, label, 13.5, fill=INK2)
        x += 28 + tw(label, 13.5) + 22
    return out


def comp_icon(x, y, stroke=INK3, bg=PAPER):
    """The component icon, at the top right of a component."""
    return (rect(x - 4, y, 19, 19, 0, "none", "none", 0, cls="ob") + rect(x, y, 15, 19, 0, "none", stroke, 1.2)
            + rect(x - 4, y + 3.5, 8, 4.5, 0, bg, stroke, 1.2)
            + rect(x - 4, y + 11, 8, 4.5, 0, bg, stroke, 1.2))


def component(x, y, w, h, name, stereo="«component»", fill=RAISED, stroke=LINE2, size=15.5, sw=1.3, name_y=None,
              icon=True, opacity=None, sub=None, sub_font=MONO):
    """A component. `sub` is an optional second line under the name, such as a tagged value."""
    out = rect(x, y, w, h, 3, fill, stroke, sw, None, opacity, cls="bxr")
    if icon:
        out += comp_icon(x + w - 21, y + 7, stroke if stroke != LINE2 else INK3)
    cx = x + (w - (20 if icon else 0)) / 2
    if stereo:
        out += text(cx, y + 20, stereo, 13.5, "middle", INK2)
        out += text(cx, name_y or y + 39, name, size, "middle", weight=600)
    elif sub:
        out += text(cx, y + h / 2 - 2, name, size, "middle", weight=500)
        out += text(cx, y + h / 2 + 16, sub, 12.5, "middle", ACCI, font=sub_font)
    else:
        out += text(cx, name_y or y + h / 2 + 5.5, name, size, "middle", weight=500)
    return group(out)


def external(x, y, w, h, name, size=15):
    """An outside library: the deck's red «external» component."""
    out = rect(x, y, w, h, 3, RECS, REC, 1.5, cls="bxr") + comp_icon(x + w - 21, y + 7, REC, RECS)
    cx = x + (w - 20) / 2
    out += text(cx, y + h / 2 - 3, "«external»", 13, "middle", INK2)
    out += text(cx, y + h / 2 + 15, name, size, "middle", weight=600)
    return group(out)


def ball(x, y, r=7):
    return f'<circle class="ob" cx="{x}" cy="{y}" r="{r}" fill="{PAPER}" stroke="{INK2}" stroke-width="1.5"/>'


def socket(x, y, ang, r=12):
    """A required interface: a half circle opening toward the provider. ang points at the provider."""
    a, b = _rot(0, -r, ang, x, y), _rot(0, r, ang, x, y)
    return path(f"M{a[0]} {a[1]} A{r} {r} 0 0 0 {b[0]} {b[1]}", INK2, 1.5)


def port(x, y, s=10):
    return rect(x - s / 2, y - s / 2, s, s, 0, PAPER, INK2, 1.4, cls="ob")


def note(x, y, w, h, lines, fold=11, size=13.5):
    d = (f"M{x} {y} L{x + w - fold} {y} L{x + w} {y + fold} L{x + w} {y + h} L{x} {y + h} Z "
         f"M{x + w - fold} {y} L{x + w - fold} {y + fold} L{x + w} {y + fold}")
    out = path(d, INK3, 1.2, RAISED, cls="bxr")
    for i, s in enumerate(lines):
        out += text(x + 9, y + 18 + i * 17, s, size, fill=INK2)
    return group(out)


def anchor(x1, y1, x2, y2):
    """The dashed line that attaches a note."""
    return line(x1, y1, x2, y2, INK3, 1.1, "4 3")


def cube(x, y, w, h, stereo, name, fill=RAISED, stroke=LINE2, d=12, opacity=None, sw=1.4):
    """A deployment node."""
    o = f' fill-opacity="{opacity}"' if opacity else ""
    top = f'<path d="M{x} {y} L{x + d} {y - d} L{x + w + d} {y - d} L{x + w} {y} Z" fill="{fill}"{o} stroke="{stroke}" stroke-width="{sw}"/>'
    side = f'<path d="M{x + w} {y} L{x + w + d} {y - d} L{x + w + d} {y + h - d} L{x + w} {y + h} Z" fill="{fill}"{o} stroke="{stroke}" stroke-width="{sw}"/>'
    out = top + side + rect(x, y, w, h, 0, fill, stroke, sw, None, opacity, cls="bxr")
    out += text(x + w / 2, y + 19, stereo, 13.5, "middle", INK2) + text(x + w / 2, y + 38, name, 16, "middle", weight=600)
    return group(out)


def artifact(x, y, w, h, name, sub=None, fill=PAPER, stroke=LINE2):
    left, top = x + w - 19, y + 6
    icon = path(f"M{left} {top} L{left + 8} {top} L{left + 13} {top + 5} L{left + 13} {top + 17} L{left} {top + 17} Z "
                f"M{left + 8} {top} L{left + 8} {top + 5} L{left + 13} {top + 5}", INK3, 1.1)
    cx = x + (w - 20) / 2
    out = rect(x, y, w, h, 0, fill, stroke, 1.2, cls="bxr") + icon
    out += text(cx, y + 17, "«artifact»", 13, "middle", INK2) + text(cx, y + 34, name, 14.5, "middle", weight=500)
    if sub:
        out += text(cx, y + 50, sub, 12.5, "middle", ACCI, font=MONO)
    return group(out)


def life_head(x, y, w, label, h=32, fill=RAISED, stroke=LINE2):
    return group(rect(x - w / 2, y, w, h, 0, fill, stroke, 1.3, cls="bxr") + text(x, y + h / 2 + 5.5, label, 14.5, "middle", weight=600))


def life_line(x, y1, y2):
    return line(x, y1, x, y2, INK3, 1.2, "6 5")


def activation(x, y1, y2, w=11):
    return rect(x - w / 2, y1, w, y2 - y1, 0, RAISED2, INK2, 1.2, cls="ob")


def msg(x1, x2, y, label, kind="async", color=INK3, lab_y=None, size=14, lab_x=None, lab_fill=INK, font=SANS, weight=400):
    """A message. kind: sync (filled head), async (open head), reply (dashed, open head)."""
    ang = 0 if x2 > x1 else math.pi
    out = line(x1, y, x2, y, color, 1.7, "7 5" if kind == "reply" else None, wire=True)
    out += head_filled(x2, y, ang, color) if kind == "sync" else head_open(x2, y, ang, color, 1.7)
    cx = lab_x if lab_x is not None else (x1 + x2) / 2
    out += text(cx, lab_y if lab_y is not None else y - 6, label, size, "middle", lab_fill, weight, font=font, halo=True)
    return out


def self_msg(x, y, label, side=1, dy=14, w=24, size=14, color=INK3, fill=INK):
    """A message from a lifeline to itself, with its nested execution specification."""
    x0 = x + side * 5.5
    x1 = x0 + side * w
    bar = x + side * 5
    out = rect(bar - 5, y + dy - 3, 10, 12, 0, RAISED, INK2, 1.2, cls="ob")
    out += path(f"M{x0} {y} L{x1} {y} L{x1} {y + dy} L{bar + side * 5} {y + dy}", color, 1.6, wire=True)
    out += head_filled(bar + side * 5, y + dy, math.pi if side > 0 else 0, color)
    out += text(x1 + side * 7, y + dy / 2 + 5, label, size, "start" if side > 0 else "end", fill, halo=True)
    return out


def fragment(x, y, w, h, op, guards=(), sep=None, stroke=INK3):
    tab = tw(op, 14, 700) + 24
    out = rect(x, y, w, h, 0, "none", stroke, 1.2)
    out += path(f"M{x} {y + 21} L{x + tab - 8:.1f} {y + 21} L{x + tab:.1f} {y + 13} L{x + tab:.1f} {y}", stroke, 1.2)
    out += text(x + 8, y + 16, op, 14, weight=700)
    for gx, gy, g, color in guards:
        out += text(gx, gy, g, 14, fill=color, weight=500, halo=True)
    for s in ([sep] if isinstance(sep, (int, float)) else sep or []):
        out += line(x, s, x + w, s, stroke, 1.2, "6 5")
    return out


def interaction_use(x, y, w, h, label, size=14.5, fill=RAISED, stroke=INK3):
    """A ref fragment: an interaction use that stands for another interaction."""
    out = rect(x, y, w, h, 0, fill, stroke, 1.3, cls="bxr")
    out += path(f"M{x} {y + 21} L{x + 34} {y + 21} L{x + 42} {y + 13} L{x + 42} {y}", stroke, 1.2)
    out += text(x + 8, y + 16, "ref", 14, weight=700)
    lines = label if isinstance(label, (list, tuple)) else [label]
    y0 = y + h / 2 + 5 - (len(lines) - 1) * 9
    for i, s in enumerate(lines):
        out += text(x + 22 + w / 2, y0 + i * 18, s, size, "middle", weight=500)
    return group(out)


def cls_box(x, y, w, name, members=(), stereo=None, fill=RAISED, stroke=LINE2, size=13, step=16.5, italic=False):
    """A class box: a name compartment (with an optional stereotype) and one member compartment."""
    nh = 26 + (16 if stereo else 0)
    mh = 8 + step * len(members) if members else 0
    out = rect(x, y, w, nh + mh, 0, fill, stroke, 1.3, cls="bxr")
    ty = y + 18
    if stereo:
        out += text(x + w / 2, ty, stereo, 12.5, "middle", INK2)
        ty += 16
    out += text(x + w / 2, ty, name, 14.5, "middle", weight=700, italic=italic)
    if members:
        out += line(x, y + nh, x + w, y + nh, stroke, 1.2)
        for i, m in enumerate(members):
            out += text(x + 8, y + nh + 16 + i * step, m, size, fill=INK2)
    return group(out), nh + mh


def initial(x, y, r=8):
    return f'<circle class="ob" cx="{x}" cy="{y}" r="{r}" fill="{INK}"/>'


def final(x, y, r=11):
    return (f'<g class="ob"><circle cx="{x}" cy="{y}" r="{r}" fill="none" stroke="{INK}" stroke-width="1.5"/>'
            f'<circle cx="{x}" cy="{y}" r="{r - 4.5}" fill="{INK}"/></g>')


def flow(pts, color=INK3, sw=1.6, dash=None):
    """A control flow, transition or dependency with an open arrowhead at the last point."""
    d = "M" + " L".join(f"{x} {y}" for x, y in pts)
    (a, b), (c, e) = pts[-2], pts[-1]
    return path(d, color, sw, dash=dash, wire=True) + head_open(c, e, math.atan2(e - b, c - a), color, sw)


def state_box(x, y, w, h, name, lines, fill=RAISED, stroke=LINE2, sw=1.5, size=14, step=20):
    """A state with a name compartment and an internal behavior compartment."""
    out = rect(x, y, w, h, 14, fill, stroke, sw, cls="bxr")
    out += text(x + w / 2, y + 25, name, 15.5, "middle", weight=700)
    if lines:
        out += line(x, y + 36, x + w, y + 36, stroke, 1.2)
        for i, s in enumerate(lines):
            out += text(x + 13, y + 57 + i * step, s, size, fill=INK)
    return group(out)


def svg(body, w=W, h=H):
    return f'<svg class="uml" viewBox="0 0 {w} {h}" role="img" xmlns="http://www.w3.org/2000/svg">{body}</svg>'
