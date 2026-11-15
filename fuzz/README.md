# Fuzz targets

Five [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) targets for the parts of pqbind that read bytes from a peer or from
disk. This directory is its own cargo workspace (it has an empty `[workspace]` table), so a normal `cargo build` or `cargo test` of
the repository never builds it, and it needs a nightly toolchain.

## What each target asserts

| Target | Input goes to | What must hold |
|---|---|---|
| `public_identity` | `PublicIdentity::from_bytes` | Never panics. A key that parses is in its canonical encoding (it re-encodes to the same bytes), and its pin round-trips through hex. |
| `pin_hex` | `Pin::from_hex` | Never panics. Exactly 96 hex digits (either case) are accepted and nothing else, and an accepted pin prints back as the lowercase text. |
| `enrollment_list` | `MemoryRegistry::decode` | Never panics. A list that decodes re-encodes to the same bytes, and every client it lists is enrolled. A well-formed list built from the input always decodes. |
| `server_hello` | `pqbind::accept`, first frame from the peer | Never panics and never returns `Ok`. The peer is sent exactly one frame, the single-byte `REFUSED` frame. |
| `client_reply` | `pqbind::connect`, reply from the peer | Never panics and never returns `Ok`. The client sent exactly one frame, a HELLO of 7320 bytes, and nothing else. |

Four targets take a flag and bytes. With the flag clear the bytes are used as they are. With it set the bytes are first shaped so they
get past the cheap checks (the suite identifier and length of a key, the shape of a HELLO or SERVER_PROOF frame with a real public key,
a well-formed registry list), which is how the input reaches the proof check and the key checks behind them. `pin_hex` takes plain
bytes.

The shared helpers (a scripted `FrameIo`, fixed identities, a runtime) are in `src/lib.rs`.

## Run them

You need a nightly toolchain and `cargo install cargo-fuzz`. From this directory:

```text
cargo +nightly fuzz build --fuzz-dir .
cargo +nightly fuzz run server_hello --fuzz-dir . -- -max_total_time=30
```

Replace `server_hello` with any of the five target names in the table above. The corpus goes to `corpus/<target>` and a crash to
`artifacts/<target>`; both are ignored by git.

### On Windows (MSVC)

The nightly toolchain from rustup does not ship the AddressSanitizer runtime for `x86_64-pc-windows-msvc`, so build with
`-s none` (no sanitizer). Code that is safe Rust, as everything here is, loses little. That build still fails to link with
`undefined symbol: __start___sancov_cntrs`, because on Windows the coverage section markers come from a compiler-rt object. LLVM's
Windows release has it inside `clang_rt.asan_static_runtime_thunk-x86_64.lib`. Extract that one object and link it (use a path
without spaces, because `RUSTFLAGS` splits on them):

```text
llvm-ar x "C:\Program Files\LLVM\lib\clang\23\lib\windows\clang_rt.asan_static_runtime_thunk-x86_64.lib" sanitizer_coverage_win_sections.cpp.obj
set RUSTFLAGS=-C link-arg=C:\path\without\spaces\sanitizer_coverage_win_sections.cpp.obj
cargo +nightly fuzz run server_hello --fuzz-dir . -s none -- -max_total_time=30
```

Do not link the whole thunk library: it also defines `malloc`, which then clashes with the C runtime.

## What has been run

All five targets were built and each was run for 30 seconds on Windows with the commands above (no sanitizer, coverage guided) on
2026-11-15. None found a crash or a failed assertion. This is a smoke run, not a campaign: thirty seconds is enough to show the targets
build, reach the checks they are meant to reach, and hold their assertions on the inputs they found, and it is not evidence that the
parsers are free of faults. Run them for hours before relying on them, and add the interesting inputs to a checked-in corpus if you
want regression coverage.

The final lines of each run (executions, coverage in edges and features, and corpus size):

| Target | Executions in 30 s | `cov` | `ft` | Corpus |
|---|---|---|---|---|
| `public_identity` | 44,574 | 198 | 236 | 21 inputs |
| `pin_hex` | 27,092,463 | 31 | 44 | 12 inputs |
| `enrollment_list` | 15,664 | 539 | 1122 | 75 inputs |
| `server_hello` | 77,821 | 544 | 645 | 5 inputs |
| `client_reply` | 1,946 | 760 | 899 | 6 inputs |

`client_reply` is slow because every execution makes the client sign its HELLO with ML-DSA-87.
