"""Build the pqbind architecture slides: inline fonts and tokens, check the layout in headless Chrome, then screenshot.

Run with `python -I docs/diagrams/src/render.py` from anywhere. Needs Google Chrome and the DM Sans and IBM Plex Mono
woff2 files, read from PQBIND_FONTS_DIR (default C:\\dev\\vaultscribe\\packages\\fonts\\files). Writes
docs/diagrams/diagrams.html, one NN-name.png per slide (1280x720 at device scale 2) and one NN-name.svg per diagram.
The output loads nothing from the network. `--check-only` stops after the layout check.

The check prints one line per finding and exits 1 when there is any: text overlapping text, text crossing a wire or
covering a solid shape, text leaving its box or crossing another box's edge, text outside the diagram panel or the
page, and any overflowing column.
"""
import base64
import html
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SRC = Path(__file__).resolve().parent
OUT = SRC.parent
PAGE = OUT / "diagrams.html"
FONTS_DIR = Path(os.environ.get("PQBIND_FONTS_DIR", r"C:\dev\vaultscribe\packages\fonts\files"))
FONTS = [
    ("DM Sans", 400, "dm-sans/DMSans-Regular.woff2"),
    ("DM Sans", 500, "dm-sans/DMSans-Medium.woff2"),
    ("DM Sans", 600, "dm-sans/DMSans-SemiBold.woff2"),
    ("DM Sans", 700, "dm-sans/DMSans-Bold.woff2"),
    ("IBM Plex Mono", 400, "ibm-plex-mono/IBMPlexMono-Regular.woff2"),
    ("IBM Plex Mono", 500, "ibm-plex-mono/IBMPlexMono-Medium.woff2"),
]

# The pqbind mark: two ends joined by one bound line, inside a rounded tile.
MARK = ('<svg viewBox="0 0 26 26" aria-hidden="true"><rect x="1.5" y="1.5" width="23" height="23" rx="7" fill="var(--accent-soft)" '
        'stroke="var(--accent)" stroke-width="1.5"/><circle cx="8" cy="13" r="2.9" fill="var(--accent-ink)"/>'
        '<circle cx="18" cy="13" r="2.9" fill="var(--accent-ink)"/><path d="M10.9 13 H15.1" stroke="var(--accent-ink)" stroke-width="1.8"/>'
        '<path d="M13 6.6 V9.9 M13 16.1 V19.4" stroke="var(--accent)" stroke-width="1.6" stroke-linecap="round"/></svg>')

CHECK = r"""
<script>
window.addEventListener('load', function () { document.fonts.ready.then(function () {
  var out = [];
  function inter(a, b) { return Math.min(a.right, b.right) - Math.max(a.left, b.left) > 0 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 0; }
  function inside(a, b, tol) { return a.left >= b.left - tol && a.right <= b.right + tol && a.top >= b.top - tol && a.bottom <= b.bottom + tol; }
  function shrink(r, dx, dy) { return { left: r.left + dx, right: r.right - dx, top: r.top + dy, bottom: r.bottom - dy }; }
  function segHits(x1, y1, x2, y2, r) {
    var t0 = 0, t1 = 1, dx = x2 - x1, dy = y2 - y1, p = [-dx, dx, -dy, dy], q = [x1 - r.left, r.right - x1, y1 - r.top, r.bottom - y1];
    for (var i = 0; i < 4; i++) {
      if (p[i] === 0) { if (q[i] < 0) return false; continue; }
      var t = q[i] / p[i];
      if (p[i] < 0) { if (t > t1) return false; if (t > t0) t0 = t; } else { if (t < t0) return false; if (t < t1) t1 = t; }
    }
    return true;
  }
  function segments(el) {
    var m = el.getScreenCTM(), svg = el.ownerSVGElement, pts = [], segs = [];
    function P(x, y) { var p = svg.createSVGPoint(); p.x = x; p.y = y; p = p.matrixTransform(m); return [p.x, p.y]; }
    if (el.tagName === 'line') {
      var a = P(+el.getAttribute('x1'), +el.getAttribute('y1')), b = P(+el.getAttribute('x2'), +el.getAttribute('y2'));
      return [[a, b]];
    }
    var tok = (el.getAttribute('d') || '').match(/[MLHVZA]|-?[\d.]+/g) || [], i = 0, cur = null, start = null, cmd = 'M';
    function num() { return parseFloat(tok[i++]); }
    while (i < tok.length) {
      if (/[MLHVZA]/.test(tok[i])) cmd = tok[i++];
      if (cmd === 'Z') { if (cur && start) segs.push([P(cur[0], cur[1]), P(start[0], start[1])]); cur = start; continue; }
      if (cmd === 'A') { num(); num(); num(); num(); num(); cur = [num(), num()]; continue; }
      var nx, ny;
      if (cmd === 'H') { nx = num(); ny = cur[1]; } else if (cmd === 'V') { nx = cur[0]; ny = num(); } else { nx = num(); ny = num(); }
      if (cmd === 'M') { start = [nx, ny]; cmd = 'L'; } else segs.push([P(cur[0], cur[1]), P(nx, ny)]);
      cur = [nx, ny];
    }
    return segs;
  }
  document.querySelectorAll('.page').forEach(function (page, i) {
    var tag = 'p' + (i + 1) + ' ', pr = page.getBoundingClientRect();
    var foot = page.querySelector('.foot').getBoundingClientRect();
    var body = page.querySelector('.body');
    if (body.scrollHeight > body.clientHeight + 1) out.push(tag + 'body overflows by ' + (body.scrollHeight - body.clientHeight));
    page.querySelectorAll('.spec,.sr,.dia,.layout').forEach(function (e) {
      if (e.scrollHeight > e.clientHeight + 1 || e.scrollWidth > e.clientWidth + 1) out.push(tag + 'overflow: ' + e.textContent.trim().slice(0, 40));
    });
    var items = [], seen = new Set(), walker = document.createTreeWalker(page, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      var t = walker.currentNode;
      if (!t.nodeValue.trim()) continue;
      var svgEl = t.parentElement.closest('svg');
      if (svgEl) {
        var te = t.parentElement.closest('text');
        if (!te || seen.has(te)) continue;
        seen.add(te);
        items.push({ r: te.getBoundingClientRect(), s: te.textContent.trim().slice(0, 44), el: te, svg: svgEl });
      } else {
        var rg = document.createRange(); rg.selectNodeContents(t);
        Array.prototype.forEach.call(rg.getClientRects(), function (c) { if (c.width >= 1) items.push({ r: c, s: t.nodeValue.trim().slice(0, 44), el: t.parentElement, svg: null }); });
      }
    }
    items.forEach(function (it) {
      var c = it.r;
      if (c.right > pr.right - 30 || c.left < pr.left + 30 || c.bottom > pr.bottom - 2 || c.top < pr.top) out.push(tag + 'outside page: ' + it.s);
      if (!it.el.closest('.foot') && c.bottom > foot.top + 1) out.push(tag + 'into footer: ' + it.s);
      if (it.svg) {
        var sr = it.svg.getBoundingClientRect();
        if (c.left < sr.left + 3 || c.right > sr.right - 3 || c.top < sr.top + 2 || c.bottom > sr.bottom - 2) out.push(tag + 'outside the diagram panel: ' + it.s);
      }
    });
    for (var a = 0; a < items.length; a++) for (var b = a + 1; b < items.length; b++) {
      var x = items[a].r, y = items[b].r;
      var w = Math.min(x.right, y.right) - Math.max(x.left, y.left), h = Math.min(x.bottom, y.bottom) - Math.max(x.top, y.top);
      if (w > 1 && h > 4) out.push(tag + 'text overlap: ' + items[a].s + ' / ' + items[b].s);
    }
    page.querySelectorAll('svg.uml').forEach(function (svg) {
      var texts = items.filter(function (it) { return it.svg === svg; });
      var wires = [];
      svg.querySelectorAll('.w').forEach(function (el) { segments(el).forEach(function (s) { wires.push(s); }); });
      var solids = Array.prototype.map.call(svg.querySelectorAll('.ob'), function (el) { return el.getBoundingClientRect(); });
      var boxes = Array.prototype.map.call(svg.querySelectorAll('.bxr'), function (el) { return { r: el.getBoundingClientRect(), g: el.closest('.bx') }; });
      texts.forEach(function (it) {
        var core = shrink(it.r, 1, 3.5);
        for (var k = 0; k < wires.length; k++) {
          var s = wires[k];
          if (segHits(s[0][0], s[0][1], s[1][0], s[1][1], core)) { out.push(tag + 'text crosses a line: ' + it.s); break; }
        }
        for (var k2 = 0; k2 < solids.length; k2++) if (inter(core, solids[k2])) { out.push(tag + 'text covers a shape: ' + it.s); break; }
        var own = it.el.closest('.bx');
        boxes.forEach(function (bx) {
          var tight = shrink(it.r, 1, 2.5);
          if (bx.g === own) { if (!inside(tight, bx.r, 1)) out.push(tag + 'text leaves its box: ' + it.s); }
          else if (inter(tight, shrink(bx.r, 0.5, 0.5)) && !inside(tight, bx.r, 0)) out.push(tag + 'text crosses a box edge: ' + it.s);
        });
      });
    });
    out.push('p' + (i + 1) + ' info: body ' + body.clientHeight + ' used ' + body.scrollHeight);
  });
  var pre = document.createElement('pre'); pre.id = 'report'; pre.textContent = out.join('\n'); document.body.appendChild(pre);
  document.title = 'done';
}); });
</script>
"""


def load_diagrams():
    sys.dont_write_bytecode = True  # keep src/ free of __pycache__
    sys.path.insert(0, str(SRC))
    spec = importlib.util.spec_from_file_location("pqbind_diagrams", SRC / "diagrams.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def font_faces(only=None):
    faces = []
    for family, weight, rel in FONTS:
        if only is not None and (family, weight) not in only:
            continue
        data = base64.b64encode((FONTS_DIR / rel).read_bytes()).decode("ascii")
        faces.append(f"@font-face{{font-family:'{family}';font-style:normal;font-weight:{weight};src:url(data:font/woff2;base64,{data}) format('woff2');}}")
    return "\n".join(faces)


def slide_html(n, slide, diagram):
    rows = "".join(f'<div class="sr"><div class="k">{html.escape(k)}</div><div class="v">{v}</div></div>' for k, v in slide["callouts"])
    return (f'<section class="page" id="p{n}">\n'
            f'  <div class="top"><div class="brand">{MARK}pqbind</div><div class="lbl">{html.escape(slide["section"])}</div></div>\n'
            f'  <h1>{html.escape(slide["title"])}</h1>\n'
            f'  <div class="body"><div class="layout"><div class="dia">{diagram}</div><div class="spec">{rows}</div></div></div>\n'
            f'  <div class="foot">{n}</div>\n'
            f'</section>\n')


def build(diagrams):
    tokens = (SRC / "tokens.css").read_text(encoding="utf-8")
    pages = "".join(slide_html(n, s, diagrams.draw(s)) for n, s in enumerate(diagrams.SLIDES, 1))
    page = (SRC / "slides.src.html").read_text(encoding="utf-8")
    page = page.replace("/*{{FONTS}}*/", font_faces()).replace("/*{{TOKENS}}*/", tokens).replace("<!--{{SLIDES}}-->", pages)
    PAGE.write_text(page, encoding="utf-8", newline="\n")
    return tokens


def chrome(*args):
    profile = Path(tempfile.gettempdir()) / f"pqbind-diagrams-{uuid.uuid4().hex}"
    cmd = [CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
           "--disable-component-update", "--disable-sync", f"--user-data-dir={profile}", *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def check():
    with tempfile.TemporaryDirectory(prefix="pqbind-check-") as tmp:
        probe = Path(tmp) / "probe.html"
        probe.write_text(PAGE.read_text(encoding="utf-8").replace("</body>", CHECK + "</body>"), encoding="utf-8")
        result = chrome("--window-size=1280,720", "--virtual-time-budget=8000", "--dump-dom", probe.as_uri())
    match = re.search(r'<pre id="report">(.*?)</pre>', result.stdout, flags=re.S)
    if not match:
        print("the check produced no report", result.stderr[-400:])
        return 1
    lines = html.unescape(match.group(1)).splitlines()
    problems = [ln for ln in lines if " info: " not in ln]
    for ln in lines:
        print(ln)
    print(f"{len(problems)} problem(s)")
    return 1 if problems else 0


def render(diagrams):
    for n, slide in enumerate(diagrams.SLIDES, 1):
        png = OUT / f"{slide['file']}.png"
        if png.exists():
            png.unlink()
        chrome("--window-size=1280,720", "--force-device-scale-factor=2", "--hide-scrollbars", "--virtual-time-budget=5000",
               f"--screenshot={png}", PAGE.as_uri() + f"#p{n}")
        if not png.exists():
            print("no PNG for", slide["file"])
            return 1
        print(f"{png.name} {png.stat().st_size // 1024} KB")
    return 0


def standalone_svgs(diagrams, tokens):
    """One SVG per diagram: the panel alone, colors resolved, the fonts it uses embedded."""
    values = dict(re.findall(r"--([\w-]+):\s*([^;]+);", tokens))
    values["sans"] = "'DM Sans', sans-serif"
    values["mono"] = "'IBM Plex Mono', monospace"
    for slide in diagrams.SLIDES:
        body = diagrams.draw(slide)
        body = re.sub(r"var\(--([\w-]+)\)", lambda m: values[m.group(1)], body)
        weights = {int(w) for w in re.findall(r'font-weight="(\d+)"', body)} | {400}
        used = {("DM Sans", w) for w in weights}
        if "IBM Plex Mono" in body:
            used |= {("IBM Plex Mono", 400), ("IBM Plex Mono", 500)}
        style = (f"<style>{font_faces(used)}\ntext.h{{paint-order:stroke;stroke:{values['paper']};stroke-width:5px;stroke-linejoin:round;}}</style>")
        body = body.replace('<svg class="uml" viewBox="0 0 816 548"', '<svg class="uml" width="816" height="548" viewBox="0 0 816 548"', 1)
        body = body.replace(">", ">" + style, 1)
        target = OUT / f"{slide['file']}.svg"
        target.write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + body + "\n", encoding="utf-8", newline="\n")
        print(f"{target.name} {target.stat().st_size // 1024} KB")


if __name__ == "__main__":
    module = load_diagrams()
    token_text = build(module)
    code = check()
    if "--check-only" not in sys.argv:
        code = render(module) or code
        standalone_svgs(module, token_text)
    sys.exit(code)
