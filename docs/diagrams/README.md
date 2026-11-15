# Architecture diagrams

Eight UML 2.5 slides of how pqbind works, each drawn from the code. `diagrams.html` shows all eight in a browser and works
offline. Each PNG is 1280x720 at device scale 2 (2560x1440). Each SVG is the diagram panel on its own, with the colors
resolved and the fonts embedded.

| File | UML kind | What it shows | Source files it reflects |
|---|---|---|---|
| `01-components.png` | Component (`cmp`) | The crates as components: `pqbind-crypto`, the `pqbind` core and its quinn, rustls and iroh adapters (with their Cargo features), `pqbind-cli` and the application. Shows the provided and required interfaces (`connect`, `accept`, `ClientRegistry`, `FrameIo`, the transport connections) and the outside libraries. | `Cargo.toml`, `crates/*/Cargo.toml`, `crates/pqbind/src/lib.rs`, `frame.rs`, `adapters/` |
| `02-handshake-sequence.png` | Sequence (`sd`) | One connection: the transport handshake, both ends reading the exporter, HELLO, the two server checks, the refused and accepted branches, and application data. | `crates/pqbind/src/handshake.rs`, `proof.rs`, `binding.rs`, `adapters/quinn.rs` |
| `03-classical-break.png` | Sequence (`sd`) | An attacker with the server's TLS key and Ed25519 half. TLS completes, and `connect` returns `Err(ServerIdentity)`. | `crates/pqbind/tests/attack_stolen_classical_key.rs`, `handshake.rs`, `THREAT_MODEL.md` |
| `04-relay.png` | Sequence (`sd`) | A man in the middle with two connections and two exporter values. The relayed proof fails and both ends are refused. | `crates/pqbind/src/lib.rs` (relay example), `tests/handshake_memory.rs`, `pqbind-cli` demo scenario d |
| `05-core-types.png` | Class (`class`) | The public types with their main members, dependencies, realizations and compositions. | `crates/pqbind/src/identity.rs`, `binding.rs`, `proof.rs`, `trust.rs`, `frame.rs`, `handshake.rs`, `error.rs` |
| `06-handshake-states.png` | State machine (`stm`) | The client (`connect`) and server (`accept`) state machines, with `event [guard] / action` transitions. | `crates/pqbind/src/handshake.rs`, `frame.rs` |
| `07-proof-format.png` | Class (`class`), as byte fields | The signed transcript fields and their sizes, what both halves sign, the hybrid key and signature layouts, and the three frames. | `crates/pqbind/src/proof.rs`, `handshake.rs`, `frame.rs`, `crates/pqbind-crypto/src/hybrid.rs`, `suite.rs` |
| `08-trust-deployment.png` | Deployment (`dep`) | Both devices and what each holds, the post-quantum link, and enrollment, which happens outside pqbind. | `crates/pqbind/src/trust.rs`, `identity.rs`, `handshake.rs`, `THREAT_MODEL.md` |

## Regenerate

```
python -I docs/diagrams/src/render.py
```

- Needs Python 3 (standard library only) and Google Chrome at `C:\Program Files\Google\Chrome\Application\chrome.exe`.
  Chrome runs headless with a fresh profile each time.
- The fonts are DM Sans and IBM Plex Mono as woff2 files. They are read from the folder in `PQBIND_FONTS_DIR`, which must
  have `dm-sans/` and `ibm-plex-mono/` subfolders. If the variable is unset, the default is
  `C:\dev\vaultscribe\packages\fonts\files`. The font files are not stored in this repository.
- Before the screenshots, the builder checks the layout in Chrome. It prints one line per problem and exits 1 if it finds
  any: text overlapping text, text crossing a line or covering a shape, text leaving its box, text outside the panel or
  the page, or a column that overflows. Run `--check-only` to skip the screenshots.

Sources: `src/uml.py` (the UML primitives), `src/diagrams.py` (the eight diagrams and the slide table with titles,
callouts and legends), `src/slides.src.html` (the slide template) and `src/tokens.css` (the colors).
