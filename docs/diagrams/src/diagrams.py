"""The eight pqbind architecture diagrams, and the slide table that frames them.

Every box, arrow and message follows the code in crates/: the handshake in crates/pqbind/src/handshake.rs, the
proof in proof.rs, the types in identity.rs, binding.rs, trust.rs, frame.rs and error.rs, the adapters in
crates/pqbind/src/adapters/, and the hybrid encodings in crates/pqbind-crypto/src/hybrid.rs and suite.rs.
"""
import math

from uml import (ACC, ACCI, ACCS, AMB, AMBS, INK, INK2, INK3, LINE2, MONO, PAPER, RAISED, RAISED2, REC, RECS, SANS,
                 activation, anchor, artifact, ball, cls_box, comp_icon, component, cube, diamond, external, final,
                 flow, fragment, frame, group, head_triangle, initial, interaction_use, legend, life_head, life_line,
                 line, msg, note, path, port, rect, self_msg, socket, state_box, svg, text)

DASH = "7 5"


def components(kind, name, leg):
    """cmp: the crates as components, with their provided and required interfaces (Cargo.toml, lib.rs, adapters/)."""
    o = frame(kind, name)
    o += component(32, 44, 220, 56, "Application", "«component»", RAISED2, LINE2)
    o += component(300, 44, 200, 56, "pqbind-cli", "«crate»", ACCS, ACC, opacity=.6, sw=1.5)
    crate = rect(24, 150, 552, 250, 3, ACCS, ACC, 1.7, None, .5, cls="bxr") + comp_icon(555, 157, ACC)
    crate += text(290, 170, "«crate»", 13.5, "middle", INK2) + text(290, 189, "pqbind", 16, "middle", weight=600)
    o += group(crate)
    o += component(44, 206, 232, 176, "core", "«component»", RAISED, LINE2)
    for i, part in enumerate(["handshake", "proof", "trust", "identity", "binding", "frame"]):
        o += component(54 + (i % 2) * 112, 256 + (i // 2) * 40, 104, 32, part, stereo=None, fill=PAPER, size=14, icon=False)
    # the application requires connect and accept; the core provides them (delegated through a port on the crate)
    o += line(70, 100, 70, 113, wire=True) + socket(70, 125, math.pi / 2) + ball(70, 125)
    o += line(70, 132, 70, 145, wire=True) + port(70, 150) + line(70, 155, 70, 206, wire=True)
    o += text(88, 129, "connect, accept", 13.5, fill=INK2)
    # the application provides ClientRegistry; the core requires it
    o += line(230, 100, 230, 118, wire=True) + ball(230, 125) + socket(230, 125, -math.pi / 2)
    o += line(230, 137, 230, 145, wire=True) + port(230, 150) + line(230, 155, 230, 206, wire=True)
    o += text(248, 129, "ClientRegistry", 13.5, fill=INK2)
    # pqbind-cli uses the crate with two adapter features on
    o += flow([(400, 100), (400, 149)], INK3, 1.5, DASH) + text(410, 121, "«use»", 13.5, fill=INK2)
    o += text(410, 139, "{quinn, rustls}", 12.5, fill=ACCI, font=MONO)
    # the adapters provide FrameIo (a StreamFrames over one stream) and require their transport
    adapters = [("quinn adapter", "quinn", "Connection", "quinn"), ("rustls adapter", "rustls", "TlsStream", "rustls"),
                ("iroh adapter", "iroh", "Connection", "iroh")]
    for i, (label, feature, iface, lib) in enumerate(adapters):
        y = 196 + i * 66
        yc = y + 29
        o += component(400, y, 160, 58, label, stereo=None, fill=PAPER, size=14.5, sub="{feature = " + feature + "}")
        o += line(384, yc, 400, yc, wire=True)
        o += line(560, yc, 571, yc, wire=True) + port(576, yc) + line(581, yc, 616, yc, wire=True)
        o += socket(628, yc, 0) + ball(628, yc) + line(635, yc, 680, yc, wire=True)
        o += text(628, yc - 18, iface, 13, "middle", INK2)
        o += external(680, y, 120, 58, lib)
    o += line(384, 225, 384, 357, wire=True) + line(276, 291, 352, 291, wire=True)
    o += socket(364, 291, 0) + ball(364, 291) + line(371, 291, 384, 291, wire=True)
    o += text(324, 274, "FrameIo", 13.5, "middle", INK2) + text(324, 318, "StreamFrames", 13, "middle", INK2)
    # the crypto crate and the libraries under it
    o += component(44, 420, 220, 88, "pqbind-crypto", "«crate»", ACCS, ACC, opacity=.6, sw=1.5)
    o += text(144, 478, "Ed25519 + ML-DSA-87,", 13, "middle", INK2) + text(144, 495, "HKDF-SHA384, SHA-384", 13, "middle", INK2)
    o += flow([(150, 382), (150, 419)], INK3, 1.5, DASH) + text(160, 414, "«use»", 13.5, fill=INK2)
    o += external(330, 418, 156, 42, "ed25519-dalek") + external(330, 466, 156, 42, "ml-dsa")
    o += flow([(264, 439), (329, 439)], INK3, 1.5, DASH) + flow([(264, 487), (329, 487)], INK3, 1.5, DASH)
    o += note(512, 420, 288, 62, ["Each adapter is behind its own Cargo", "feature, off by default, so the core", "depends on no transport."])
    o += anchor(560, 420, 520, 387)
    o += legend(leg)
    return svg(o)


def handshake_sequence(kind, name, leg):
    """sd: one connection, from the transport handshake to application data (handshake.rs, adapters/quinn.rs)."""
    a, c, t, s, r = 76, 246, 410, 574, 730
    o = frame(kind, name)
    o += life_head(a, 38, 128, ": Application") + life_head(c, 38, 140, "client : pqbind") + life_head(t, 38, 128, ": Transport")
    o += life_head(s, 38, 140, "server : pqbind") + life_head(r, 38, 148, ": ClientRegistry")
    for x in (a, c, t, s, r):
        o += life_line(x, 70, 518)
    o += interaction_use(20, 76, 636, 40, ["TLS 1.3 or QUIC handshake", "post-quantum hybrid key exchange, classical authentication"], 14)
    o += activation(a, 136, 515) + activation(c, 140, 482) + activation(s, 142, 444) + activation(r, 264, 286)
    o += msg(a + 6, c - 6, 140, "open(conn, app_label)", "sync")
    o += self_msg(c, 146, "read exporter", dy=12) + self_msg(s, 146, "read exporter", side=-1, dy=12)
    o += msg(a + 6, c - 6, 184, "connect(server_pin)", "sync")
    o += self_msg(c, 190, "prove(Client, transcript)", dy=12)
    o += msg(c + 6, s - 6, 230, "HELLO: key + proof, 7,320 B", color=ACC)
    o += self_msg(s, 238, "verify(Client proof)", side=-1, dy=12)
    o += msg(s + 6, r - 6, 264, "is_enrolled(key, id)", "sync")
    o += msg(r - 6, s + 6, 286, "bool", "reply")
    o += text(548, 280, "both checks always run", 13.5, "end", INK2, italic=True, halo=True)
    o += fragment(18, 298, 642, 194, "alt", [(262, 318, "[proof fails or key not enrolled]", REC),
                                             (262, 400, "[proof verifies and key enrolled]", ACCI)], sep=380)
    o += msg(s - 6, c + 6, 342, "REFUSED: one byte, 0x03", color=REC)
    o += msg(c - 6, a + 6, 364, "Err(Refused)", "reply", color=REC)
    o += text(556, 368, "accept returns Err(Refused)", 13.5, "end", REC, halo=True)
    o += self_msg(s, 406, "prove(Server, transcript)", side=-1, dy=12)
    o += msg(s - 6, c + 6, 444, "SERVER_PROOF: key + proof, 7,320 B", color=ACC)
    o += self_msg(c, 452, "check pin, verify proof", dy=12)
    o += msg(c - 6, a + 6, 482, "Ok(Established)", "reply")
    o += msg(a + 6, t, 511, "application data", color=ACC, lab_x=330)
    o += legend(leg)
    return svg(o)


def classical_break(kind, name, leg):
    """sd: an attacker with the server's TLS key and Ed25519 half (tests/attack_stolen_classical_key.rs)."""
    a, c, t, m = 106, 266, 440, 620
    o = frame(kind, name)
    o += life_head(a, 38, 128, ": Application") + life_head(c, 38, 140, "client : pqbind") + life_head(t, 38, 128, ": Transport")
    o += life_head(m, 38, 150, "m : Impersonator", fill=RECS, stroke=REC)
    for x in (a, c, t, m):
        o += life_line(x, 70, 436)
    o += interaction_use(20, 76, 676, 40, ["TLS 1.3 or QUIC handshake completes", "m presents the server certificate, signed with the stolen key"],
                         14, RECS, REC)
    o += activation(a, 136, 414) + activation(c, 140, 410) + activation(m, 144, 300)
    o += msg(a + 6, c - 6, 140, "open(conn, app_label)", "sync")
    o += self_msg(c, 146, "read exporter", dy=12) + self_msg(m, 146, "read exporter", side=-1, dy=12)
    o += msg(a + 6, c - 6, 182, "connect(server_pin)", "sync")
    o += self_msg(c, 188, "prove(Client, transcript)", dy=12)
    o += msg(c + 6, m - 6, 226, "HELLO: key + proof", color=ACC)
    o += self_msg(m, 234, "Ed25519 half: stolen key", side=-1, dy=12)
    o += self_msg(m, 262, "ML-DSA-87 half: another key", side=-1, dy=12, color=REC, fill=REC)
    o += msg(m - 6, c + 6, 300, "SERVER_PROOF: the real key, a forged proof", color=REC)
    o += self_msg(c, 308, "pin matches: the key is public", dy=12)
    o += self_msg(c, 336, "verify: the ML-DSA-87 half fails", dy=12, color=REC, fill=REC)
    o += fragment(18, 362, 482, 68, "break", [(278, 382, "[proof does not verify]", REC)])
    o += msg(c - 6, a + 6, 410, "Err(ServerIdentity)", "reply", color=REC)
    o += text(278, 416, "no application data is sent", 13.5, fill=INK2, halo=True)
    o += note(18, 446, 384, 62, ["m holds the server's TLS key and its Ed25519", "half. It lacks the ML-DSA-87 half, which comes",
                                 "from a seed it cannot recover."])
    o += note(418, 446, 382, 62, ["Whole-key theft is outside the model: an", "attacker with both halves is the server.",
                                  "The demo shows that case on purpose."])
    o += legend(leg)
    return svg(o)


def relay(kind, name, leg):
    """sd: a man in the middle between two connections (lib.rs relay example, demo scenario d)."""
    a, c, rl, s = 76, 236, 440, 680
    o = frame(kind, name)
    o += life_head(a, 38, 128, ": Application") + life_head(c, 38, 140, "client : pqbind")
    o += life_head(rl, 38, 120, "r : Relay", fill=RECS, stroke=REC) + life_head(s, 38, 140, "server : pqbind")
    for x in (a, c, rl, s):
        o += life_line(x, 70, 430)
    o += interaction_use(150, 78, 330, 38, "connection A: TLS 1.3 handshake", 14)
    o += interaction_use(380, 124, 420, 38, "connection B: TLS 1.3 handshake", 14)
    o += activation(a, 186, 414) + activation(c, 186, 410) + activation(rl, 274, 382) + activation(s, 194, 354)
    o += msg(a + 6, c - 6, 190, "connect(server_pin)", "sync")
    o += self_msg(c, 198, "read exporter A", dy=12) + self_msg(s, 198, "read exporter B", side=-1, dy=12)
    o += self_msg(c, 232, "prove(Client, A)", dy=12)
    o += msg(c + 6, rl - 6, 274, "HELLO: proof over A", color=ACC)
    o += msg(rl + 6, s - 6, 304, "HELLO, copied unchanged", color=REC)
    o += self_msg(s, 312, "verify over B: fails", side=-1, dy=12, color=REC, fill=REC)
    o += msg(s - 6, rl + 6, 354, "REFUSED", color=REC)
    o += msg(rl - 6, c + 6, 382, "REFUSED, copied back", color=REC)
    o += text(668, 378, "accept returns Err(Refused)", 13.5, "end", REC, halo=True)
    o += msg(c - 6, a + 6, 410, "Err(Refused)", "reply", color=REC)
    o += note(18, 444, 470, 62, ["Each leg has its own exporter value, so a proof", "made on leg A does not verify on leg B. A replayed",
                                 "proof fails the same way."])
    o += note(504, 444, 296, 62, ["In the demo the relay even holds", "the server's TLS key, and it still", "cannot pass."])
    o += legend(leg)
    return svg(o)


def core_types(kind, name, leg):
    """class: the public types of the pqbind crate (identity.rs, binding.rs, proof.rs, trust.rs, frame.rs, handshake.rs, error.rs)."""
    c1, c2, c3, c4 = 16, 214, 416, 644
    w1, w2, w3, w4 = 164, 168, 194, 156
    r1, r2, r3, r4 = 44, 176, 312, 420
    o = frame(kind, name)
    b, _ = cls_box(c1, r1, w1, "PublicIdentity", ["+ from_bytes(bytes)", "+ as_bytes(): &[u8]", "+ pin(): Pin"]); o += b
    b, _ = cls_box(c1, r2, w1, "HybridIdentity", ["+ generate()", "+ from_seed(seed)", "+ public(): PublicIdentity", "+ pin(): Pin"],
                   fill=ACCS, stroke=ACC); o += b
    b, _ = cls_box(c1, r3, w1, "Error", ["Refused", "ServerIdentity", "ProofInvalid", "Malformed", "Io", "Crypto", "InvalidInput", "Unsupported"],
                   "«enumeration»", step=15.5); o += b
    b, _ = cls_box(c2, r1, w2, "FrameIo", ["+ binding(): &Binding", "+ send(frame)", "+ recv(): Vec<u8>"], "«interface»"); o += b
    b, _ = cls_box(c2, r2, w2, "handshake", ["+ connect(…, server_pin)", "+ accept(…, registry)"], "«utility»"); o += b
    b, _ = cls_box(c2, r3, w2, "Established", ["+ peer_key()", "+ peer_id()"]); o += b
    b, _ = cls_box(c2, r4, w2, "MemoryRegistry", ["+ enroll(enrollment)", "+ revoke(key, id): bool", "+ encode(), decode()"]); o += b
    b, _ = cls_box(c3, r1, w3, "StreamFrames<R, W>", ["+ new(r, w, binding)", "+ with_timeout(d)", "+ into_parts(): (R, W)"]); o += b
    b, _ = cls_box(c3, r2, w3, "Transcript", ["+ binding: &Binding", "+ client_id: &PeerId", "+ server_id: &PeerId", "+ client_pin: &Pin",
                                               "+ server_pin: &Pin"], step=16); o += b
    b, _ = cls_box(c3, r3, w3, "ClientRegistry", ["+ is_enrolled(key, id): bool"], "«interface»"); o += b
    b, _ = cls_box(c3, r4, w3, "Enrollment", ["+ key: PublicIdentity", "+ peer_id: PeerId", "+ enrolled_at_unix_millis: i64"]); o += b
    b, _ = cls_box(c4, r1, w4, "Binding", ["+ new(label, exporter)", "+ derive(label, export)", "+ app_label(): &[u8]", "+ exporter(): &[u8; 64]"],
                   fill=ACCS, stroke=ACC); o += b
    b, _ = cls_box(c4, r2, w4, "Pin", ["+ of(key): Pin", "+ as_bytes(): &[u8; 48]", "+ to_hex(), from_hex()"]); o += b
    b, _ = cls_box(c4, r3, w4, "PeerId", ["+ new(bytes)", "+ anonymous()", "+ of_certificate(der)"]); o += b
    b, _ = cls_box(c4, r4, w4, "Role", ["Client", "Server"], "«enumeration»"); o += b
    # dependencies
    o += flow([(98, r2), (98, 128.5)], INK3, 1.5, DASH) + text(106, 158, "«create»", 13, fill=INK2, italic=True)
    o += flow([(298, r2), (298, 144.5)], INK3, 1.5, DASH)
    o += flow([(c2, 218), (c1 + w1 + 1, 218)], INK3, 1.5, DASH)
    o += flow([(c2 + w2, 218), (c3 - 1, 218)], INK3, 1.5, DASH)
    o += flow([(298, 259), (298, r3 - 1)], INK3, 1.5, DASH)
    o += flow([(232, 259), (168, r3 - 1)], INK3, 1.5, DASH)
    o += flow([(362, 259), (440, r3 - 1)], INK3, 1.5, DASH)
    # realizations: the hollow triangle at the interface
    o += line(c3, 86, c2 + w2 + 13, 86, INK2, 1.4, DASH, wire=True) + head_triangle(c2 + w2, 86, math.pi)
    o += line(374, r4, 437.5, 386.5, INK2, 1.4, DASH, wire=True) + head_triangle(446, 379.5, math.atan2(379.5 - r4, 446 - 374))
    # compositions: the filled diamond at the whole
    o += diamond(c3 + w3, 86, 0) + line(c3 + w3 + 18, 86, c4, 86, INK2, 1.4, wire=True) + text(c4 - 7, 79, "1", 13, "end", INK2)
    o += diamond(c2 + w2, 462, 0) + line(c2 + w2 + 18, 462, c3, 462, INK2, 1.4, wire=True) + text(c3 - 3, 453, "0..*", 13, "end", INK2)
    o += legend(leg)
    return svg(o)


def handshake_states(kind, name, leg):
    """stm: the client (connect) and server (accept) state machines of handshake.rs."""
    o = frame(kind, name)
    o += line(418, 40, 418, 472, LINE2, 1.3, "6 5")
    o += text(402, 56, "Client: connect()", 14.5, "end", INK2, 600) + text(800, 56, "Server: accept()", 14.5, "end", INK2, 600)
    # client
    x, w, cx = 24, 200, 124
    o += initial(cx, 58) + flow([(cx, 66), (cx, 81)])
    o += state_box(x, 82, w, 90, "Proving", ["entry / build transcript", "do / prove(Client)"])
    o += flow([(cx, 172), (cx, 203)]) + text(cx + 10, 193, "/ send HELLO", 14, fill=INK, weight=500)
    o += state_box(x, 204, w, 68, "AwaitingReply", ["do / recv()"])
    o += flow([(x + w, 238), (382, 238)], REC) + final(394, 238)
    o += text(303, 230, "recv REFUSED", 14, "middle", REC, 500) + text(303, 256, "/ Err(Refused)", 14, "middle", REC, 500)
    o += flow([(cx, 272), (cx, 315)], ACC, 1.8) + text(cx + 10, 298, "recv SERVER_PROOF", 14, fill=INK, weight=500)
    o += state_box(x, 316, w, 90, "CheckingServer", ["do / check the pin", "do / verify(Server proof)"], ACCS, ACC)
    o += flow([(x + w, 360), (382, 360)], REC) + final(394, 360)
    o += text(303, 352, "[else]", 14, "middle", REC, 500) + text(303, 378, "/ Err(ServerIdentity)", 14, "middle", REC, 500)
    o += flow([(cx, 406), (cx, 448)], ACC, 1.8) + final(cx, 460)
    o += text(cx + 10, 424, "[pin and proof pass]", 14, fill=ACCI, weight=500) + text(cx + 10, 442, "/ Ok(Established)", 14, fill=ACCI, weight=500)
    # server
    x, w, cx = 444, 206, 547
    o += initial(cx, 58) + flow([(cx, 66), (cx, 81)])
    o += state_box(x, 82, w, 68, "AwaitingHello", ["do / recv()"])
    o += flow([(cx, 150), (cx, 181)]) + text(cx + 10, 171, "recv frame", 14, fill=INK, weight=500)
    o += state_box(x, 182, w, 110, "CheckingHello", ["do / check shape, parse key", "do / verify(Client proof)", "do / is_enrolled(key, id)"], ACCS, ACC)
    o += flow([(x + w, 237), (774, 237)], REC) + final(786, 237)
    o += text(712, 229, "[else]", 14, "middle", REC, 500) + text(712, 255, "/ send REFUSED", 14, "middle", REC, 500)
    o += flow([(cx, 292), (cx, 335)], ACC, 1.8)
    o += text(cx + 10, 310, "[proof verifies", 14, fill=ACCI, weight=500) + text(cx + 10, 327, "and key enrolled]", 14, fill=ACCI, weight=500)
    o += state_box(x, 336, w, 90, "Proving", ["entry / prove(Server)", "exit / send SERVER_PROOF"])
    o += flow([(cx, 426), (cx, 448)], ACC, 1.8) + final(cx, 460)
    o += text(cx + 10, 441, "/ Ok(Established)", 14, fill=ACCI, weight=500)
    o += note(24, 482, 560, 30, ["Any other reply ends in Err(Malformed); a transport failure or a timeout, in Err(Io)."])
    o += legend(leg)
    return svg(o)


def _cells(x, y, h, cells, size=13):
    """A row of byte fields: (name, length, width, kind) with kind neutral, pq (ML-DSA-87) or cl (Ed25519)."""
    fills = {"neutral": (RAISED2, LINE2), "pq": (ACCS, ACC), "cl": (AMBS, AMB)}
    out = ""
    for label, length, w, kind in cells:
        fill, stroke = fills[kind]
        body = rect(x, y, w, h, 0, fill, stroke, 1.3, cls="bxr")
        if length is None:
            body += text(x + w / 2, y + h / 2 + 5, label, size, "middle", INK, 500, font=MONO if label.startswith("0x") else SANS)
        else:
            body += text(x + w / 2, y + h / 2 - 3, label, size, "middle", INK, 500)
            body += text(x + w / 2, y + h / 2 + 14, length, 12, "middle", ACCI, font=MONO)
        out += group(body)
        x += w
    return out


def _row_label(y, h, name, total):
    return (text(16, y + h / 2 - 3, name, 13.5, fill=INK, weight=600)
            + text(16, y + h / 2 + 14, total, 12, fill=ACCI, font=MONO))


def proof_format(kind, name, leg):
    """class: the signed transcript, what the hybrid key signs, the key and signature encodings and the frames
    (proof.rs transcript_bytes, pqbind-crypto hybrid.rs signed_bytes and to_bytes, handshake.rs frames)."""
    o = frame(kind, name)
    x0 = 140
    # the transcript: role label | u8 len, app label | u16 len, client id | u16 len, server id | client pin | server pin | exporter
    o += _row_label(50, 42, "Transcript", "per role")
    o += _cells(x0, 50, 42, [("role label", "23", 82, "neutral"), ("len", "u8", 32, "neutral"), ("app label", "1..255", 80, "neutral"),
                             ("len", "u16", 36, "neutral"), ("client id", "0..1024", 76, "neutral"), ("len", "u16", 36, "neutral"),
                             ("server id", "0..1024", 76, "neutral"), ("client pin", "48", 80, "neutral"), ("server pin", "48", 80, "neutral"),
                             ("exporter", "64", 82, "neutral")])
    o += path(f"M{x0} 96 L{x0} 102 L800 102 L800 96", INK3, 1.3)
    o += flow([(670, 102), (670, 135)], INK3, 1.5) + text(680, 124, "SHA-512 of all of it", 13, fill=INK2)
    # what both halves sign: label | SHA-512(transcript)
    o += _row_label(136, 40, "Signed bytes", "109 B")
    o += _cells(x0, 136, 40, [("hybrid label", "45", 400, "neutral"), ("SHA-512 of the transcript", "64", 260, "neutral")])
    o += path(f"M{x0} 180 L{x0} 186 L800 186 L800 180", INK3, 1.3)
    o += flow([(309, 186), (309, 219)], AMB, 1.6) + text(319, 208, "Ed25519 signs", 13, fill=AMB, weight=500)
    o += flow([(597, 186), (597, 219)], ACC, 1.6) + text(607, 208, "ML-DSA-87 signs", 13, fill=ACCI, weight=500)
    # the signature and the public key, aligned
    o += _row_label(220, 40, "Hybrid signature", "4,693 B")
    o += _cells(x0, 220, 40, [("suite id", "2", 84, "neutral"), ("Ed25519 signature", "64", 170, "cl"), ("ML-DSA-87 signature", "4,627", 406, "pq")])
    o += _row_label(274, 40, "Hybrid public key", "2,626 B")
    o += _cells(x0, 274, 40, [("suite id", "2", 84, "neutral"), ("Ed25519 key", "32", 170, "cl"), ("ML-DSA-87 key", "2,592", 406, "pq")])
    o += path(f"M{x0} 318 L{x0} 324 L800 324 L800 318", INK3, 1.3)
    o += text(470, 341, "pin = SHA-384 of all 2,626 bytes, 48 B", 13, "middle", INK2)
    # the frames
    rows = [("HELLO", "7,320 B", "0x01"), ("SERVER_PROOF", "7,320 B", "0x02")]
    for i, (label, total, tag) in enumerate(rows):
        y = 356 + i * 40
        o += _row_label(y, 34, label, total)
        o += _cells(x0, y, 34, [(tag, None, 84, "neutral"), ("public key, 2,626", None, 254, "neutral"), ("proof, 4,693", None, 322, "neutral")])
    o += _row_label(436, 34, "REFUSED", "1 B")
    o += _cells(x0, 436, 34, [("0x03", None, 84, "neutral")])
    o += text(x0 + 98, 458, "the only reply a refused client gets", 13, fill=INK2)
    o += note(x0, 480, 660, 30, ["Each frame travels as a u32 big-endian length and the bytes, at most 16 KiB."])
    o += legend(leg)
    return svg(o)


def trust_deployment(kind, name, leg):
    """dep: where trust lives (trust.rs, identity.rs, THREAT_MODEL.md enrollment and first contact)."""
    o = frame(kind, name)
    for x, node, env, items in ((20, "Client device", "Your application", [("pqbind", None), ("Identity seed", "32 B, secret"), ("Server pin", "48 B")]),
                                (514, "Server", "Your service", [("pqbind", None), ("Identity seed", "32 B, secret"), ("Enrolled clients", "key + transport id")])):
        o += cube(x, 64, 270, 290, "«device»", node, ACCS, ACC, opacity=.55)
        o += cube(x + 16, 116, 238, 222, "«executionEnvironment»", env, PAPER, LINE2, d=8)
        o += artifact(x + 28, 168, 214, 42, items[0][0])
        o += artifact(x + 28, 216, 214, 56, items[1][0], items[1][1])
        o += artifact(x + 28, 278, 214, 56, items[2][0], items[2][1])
    # the transport link
    o += line(302, 160, 514, 160, ACC, 2.8, wire=True)
    o += text(408, 110, "«QUIC or TLS 1.3»", 14, "middle", weight=600)
    o += text(408, 128, "post-quantum key exchange", 13, "middle", INK2)
    o += text(408, 150, "HELLO, SERVER_PROOF", 12.5, "middle", ACCI, font=MONO)
    o += text(308, 178, "1..*", 13, fill=INK2) + text(508, 178, "1", 13, "end", INK2)
    o += note(318, 196, 180, 79, ["Keys that arrive here", "are checked against", "enrollment, never", "trusted for arriving."])
    o += anchor(408, 196, 408, 161)
    # enrollment, out of band
    o += cube(296, 414, 212, 72, "«out of band»", "Enrollment", AMBS, AMB, opacity=.8)
    o += text(402, 472, "QR code, admin, ticket", 13, "middle", INK2)
    o += line(296, 444, 155, 355, AMB, 2, "6 4", wire=True) + line(520, 432, 649, 355, AMB, 2, "6 4", wire=True)
    o += text(232, 392, "server pin", 13.5, fill=AMB, weight=500)
    o += text(606, 392, "client key + transport id", 13.5, fill=AMB, weight=500)
    o += text(402, 506, "outside pqbind", 14, "middle", AMB, 600)
    o += legend(leg)
    return svg(o)


def c(s):
    return f"<code>{s}</code>"


SLIDES = [
    {"file": "01-components", "kind": "cmp", "section": "Architecture", "frame": ("cmp", "pqbind workspace"), "draw": components,
     "title": "Small core, swappable transports.",
     "legend": [("zone", "pqbind crates"), ("neutral", "Your application"), ("outside", "Outside library")],
     "sources": "Cargo.toml, crates/*/Cargo.toml, crates/pqbind/src/lib.rs, frame.rs, adapters/",
     "shows": "The crates as components, their provided and required interfaces, and the libraries under them",
     "callouts": [("Core", f"handshake, proof and trust, generic over {c('FrameIo')}, so it names no transport."),
                  ("Adapters", "quinn, rustls and iroh, each behind its own Cargo feature, off by default."),
                  ("Exporter", f"Adapters read it through {c('Binding::derive')}, which fixes label and context."),
                  ("Crypto", "pqbind-crypto wraps ed25519-dalek and ml-dsa. Nothing home-grown."),
                  ("Your part", f"Supply a {c('ClientRegistry')}, the enrolled keys and the server pin."),
                  ("CLI", "pqbind-cli: demo, keygen, serve, verify and probe.")]},
    {"file": "02-handshake-sequence", "kind": "sd", "section": "Handshake", "frame": ("sd", "One connection"), "draw": handshake_sequence,
     "title": "One proof, bound to one connection.",
     "legend": [("pq", "Carries a hybrid proof"), ("red", "Refused")],
     "sources": "crates/pqbind/src/handshake.rs, proof.rs, binding.rs, adapters/quinn.rs",
     "shows": "One connection from the transport handshake to application data, with the refused and accepted branches",
     "callouts": [("Exporter", f"64 bytes from this session, label {c('EXPORTER-pqbind-v1')}."),
                  ("Proof", "Signs the role, app label, both transport ids, both pins and the exporter."),
                  ("Server checks", "The proof and the enrollment are both checked, so timing tells nothing."),
                  ("Refusal", "One REFUSED byte for every failure. The reason stays on the server."),
                  ("Order", "The server proves itself only after the client has passed."),
                  ("Data", f"Neither end sends application data until its call returns {c('Ok')}.")]},
    {"file": "03-classical-break", "kind": "sd", "section": "Threat model", "frame": ("sd", "Stolen classical keys"), "draw": classical_break,
     "title": "A classical break is not enough.",
     "legend": [("pq", "Bound to this connection"), ("red", "Forged or refused"), ("outside", "Passes on stolen classical keys")],
     "sources": "crates/pqbind/tests/attack_stolen_classical_key.rs, handshake.rs connect, THREAT_MODEL.md",
     "shows": "An impersonator with the server's TLS key and Ed25519 half; TLS completes, pqbind refuses",
     "callouts": [("Attacker", "Holds the server's TLS key and Ed25519 half, as a quantum computer could."),
                  ("Transport", "The certificate check passes, so TLS alone accepts the attacker."),
                  ("Pin", "Passes too. The real public key is public."),
                  ("Proof", "The ML-DSA-87 half cannot be forged, so the proof does not verify."),
                  ("Result", f"{c('connect')} returns {c('Err(ServerIdentity)')} before any data."),
                  ("Tested", "attack_stolen_classical_key.rs runs it, with a positive control.")]},
    {"file": "04-relay", "kind": "sd", "section": "Threat model", "frame": ("sd", "Relay between two connections"), "draw": relay,
     "title": "A relay sees two different connections.",
     "legend": [("pq", "Proof over exporter A"), ("red", "Copied or refused")],
     "sources": "crates/pqbind/src/lib.rs (relay example), tests/handshake_memory.rs, pqbind-cli demo scenario d",
     "shows": "A man in the middle with two connections and two exporter values; the relayed proof fails and both ends are refused",
     "callouts": [("Two legs", "The relay ends one connection and opens another."),
                  ("Exporters", "Each leg has its own exporter value."),
                  ("Copied", "A relayed HELLO carries a proof over exporter A."),
                  ("Server", f"The proof fails on leg B: REFUSED, then {c('Err(Refused)')}."),
                  ("Client", f"The relayed refusal ends {c('connect')} with {c('Err(Refused)')}."),
                  ("Replay", "An old proof fails the same way: it signs another session.")]},
    {"file": "05-core-types", "kind": "class", "section": "Public API", "frame": ("class", "pqbind public types"), "draw": core_types,
     "title": "A handful of types carry the whole protocol.",
     "legend": [("zone", "Holds a secret: prints nothing, wiped on drop")],
     "sources": "crates/pqbind/src/identity.rs, binding.rs, proof.rs, trust.rs, frame.rs, handshake.rs, error.rs",
     "shows": "The public types with their main members, dependencies, realizations and compositions",
     "callouts": [("Secrets", f"{c('HybridIdentity')} and {c('Binding')} print nothing and wipe on drop."),
                  ("Public data", f"{c('PublicIdentity')}, {c('Pin')} and {c('PeerId')} are safe to log."),
                  ("Pin", "SHA-384 of the whole 2,626-byte key: 48 bytes."),
                  ("PeerId", "What the transport authenticated: a certificate hash or an iroh node id."),
                  ("Registry", f"Implement {c('ClientRegistry')} over any store. {c('MemoryRegistry')} is included."),
                  ("Errors", "No variant carries key, proof or identity bytes.")]},
    {"file": "06-handshake-states", "kind": "stm", "section": "Handshake", "frame": ("stm", "connect and accept"), "draw": handshake_states,
     "title": "The server proves itself only after the client passes.",
     "legend": [("zone", "Checks run here"), ("pq", "Accepted path"), ("red", "Refused or failed")],
     "sources": "crates/pqbind/src/handshake.rs (connect, accept, check_hello), frame.rs",
     "shows": "The client and server state machines with events, guards and actions",
     "callouts": [("Client", "Proves first, then accepts only the pinned key with a valid proof."),
                  ("Server", "Proves itself only after both checks pass."),
                  ("Both checks", "verify and is_enrolled run whatever the first one answered."),
                  ("Refusal", f"One REFUSED byte on the wire. {c('Refused')} or {c('Malformed')} locally."),
                  ("Timeouts", "Every step has a time limit, 30 seconds by default."),
                  ("Data", f"Application data waits for {c('Ok')} on both ends.")]},
    {"file": "07-proof-format", "kind": "class", "section": "Wire format", "frame": ("class", "Transcript, proof and frames"), "draw": proof_format,
     "title": "Every byte that is signed, and every byte that is sent.",
     "legend": [("amber", "Ed25519 half"), ("zone", "ML-DSA-87 half"), ("neutral", "Labels, lengths and framing")],
     "sources": "crates/pqbind/src/proof.rs, handshake.rs, frame.rs, crates/pqbind-crypto/src/hybrid.rs, suite.rs",
     "shows": "The signed transcript fields, what both halves sign, the key and signature layouts and the three frames",
     "callouts": [("Role label", f"{c('pqbind/proof/client/v1')} or server, ending in a zero byte."),
                  ("Identities", "Client then server, each with a u16 length, so the boundary cannot move."),
                  ("Exporter", "64 bytes unique to this session. Another connection gives another value."),
                  ("Both halves", "Each signs the 45-byte label and the SHA-512 of the transcript."),
                  ("Suite", f"{c('0x0201')} opens each key and signature. No classical-only suite exists."),
                  ("Frames", "The largest is 7,320 bytes, under the 16&nbsp;KiB limit.")]},
    {"file": "08-trust-deployment", "kind": "dep", "section": "Trust model", "frame": ("dep", "Where trust comes from"), "draw": trust_deployment,
     "title": "Trust comes from enrollment, never from the connection.",
     "legend": [("zone", "Holds a secret seed"), ("pq", "Post-quantum transport"), ("oob", "Enrollment, outside pqbind")],
     "sources": "crates/pqbind/src/trust.rs, identity.rs, handshake.rs, THREAT_MODEL.md",
     "shows": "The two devices, the artifacts each holds, the post-quantum link and the out-of-band enrollment",
     "callouts": [("Enrolled", "A client key counts only with the transport id it was enrolled from."),
                  ("Pinned", "The client holds the SHA-384 pin of the server's whole key."),
                  ("Sent", "Keys in HELLO and SERVER_PROOF are checked, never trusted for arriving."),
                  ("Seed", "One 32-byte seed per end makes both halves. Seal it in your key store."),
                  ("First contact", "Delivering the pin and the key is up to you, before any connection."),
                  ("Revoke", "Take the key out of the registry. The next accept refuses it.")]},
]


def draw(slide):
    kind, name = slide["frame"]
    return slide["draw"](kind, name, slide["legend"])
