"""Run `pqbind demo` and record its output line by line with a monotonic timestamp per line.

Usage:
    python -I scripts/demo-gif/capture.py PATH_TO_PQBIND_EXE [--out-dir docs/media]

Writes docs/media/demo.transcript.json (lines with seconds since the process started) and
docs/media/demo.transcript.txt (the plain text). The output of the demo is stored exactly as
printed; nothing is edited, reordered or added. The demo's exit code is stored in the JSON.
Standard library only.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", help="path to the pqbind executable")
    parser.add_argument("--out-dir", default=str(ROOT / "docs" / "media"))
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    command = [args.binary, "demo"]

    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    lines = []
    for raw in iter(process.stdout.readline, b""):
        stamp = time.monotonic() - started
        text = raw.decode("utf-8").rstrip("\r\n")
        lines.append({"t": round(stamp, 4), "text": text})
    exit_code = process.wait()
    elapsed = time.monotonic() - started

    document = {
        "command": "pqbind demo",
        "exit_code": exit_code,
        "duration_seconds": round(elapsed, 4),
        "lines": lines,
    }
    (out_dir / "demo.transcript.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    (out_dir / "demo.transcript.txt").write_text(
        "".join(line["text"] + "\n" for line in lines), encoding="utf-8", newline="\n"
    )
    print(f"captured {len(lines)} lines in {elapsed:.2f} s, exit code {exit_code}")
    return 0 if exit_code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
