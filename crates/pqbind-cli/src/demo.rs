// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run the attack demonstration: real QUIC or TLS connections on 127.0.0.1 where attackers who hold classical keys still fail the hybrid proof.
//!
//! [`run_scenarios`] is the engine: it runs every scenario and returns a [`Report`] a test can inspect. [`run`] prints that report as a
//! story and a summary table, and exits 0 only when every scenario behaved as expected, so the demo is also a self test.

use std::process::ExitCode;

use pqbind::proof::{self, Role, Transcript};
use pqbind::{ClientRegistry, Enrollment, Error, Established, FrameIo, HybridIdentity, MemoryRegistry, PeerId, Pin, PublicIdentity};
use pqbind_crypto::hybrid::PUBLIC_KEY_LEN;
use pqbind_crypto::random::random_array;

use crate::cert::Tls;
use crate::common::{CliError, CliResult, Transport, now_millis, short_pin};
use crate::net::{Link, Raw, loopback_pair};

/// The application label the demo's peers use.
const LABEL: &[u8] = b"pqbind-demo/v1";

/// The first byte of the frames the attackers build by hand (the same values the handshake uses).
const HELLO: u8 = 0x01;
const SERVER_PROOF: u8 = 0x02;
const REFUSED: u8 = 0x03;

/// The arguments of `pqbind demo`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The transport to run the demo over.
    #[arg(long, value_enum, default_value_t = Transport::Quic)]
    pub transport: Transport,
}

/// What a scenario's end must do for the scenario to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    /// The handshake returns `Ok`.
    Accept,
    /// The handshake returns this error.
    Reject(Error),
}

fn got_text(got: &Result<(), Error>) -> String {
    match got {
        Ok(()) => "Ok".to_owned(),
        Err(error) => format!("Err({error:?})"),
    }
}

fn meets(want: Want, got: &Result<(), Error>) -> bool {
    match want {
        Want::Accept => got.is_ok(),
        Want::Reject(error) => *got == Err(error),
    }
}

/// How one scenario ended.
#[derive(Debug, Clone)]
pub struct ScenarioResult {
    /// A short id: `a`, `b1`, `b2`, `c`, `d`, `e`, `f1` or `f2`.
    pub id: &'static str,
    /// What the scenario is called.
    pub title: &'static str,
    /// Who holds what, in plain words.
    pub story: &'static str,
    /// What should happen, in one sentence.
    pub expected: String,
    /// What should happen, as handshake results.
    pub expected_short: String,
    /// What happened, as handshake results.
    pub observed_short: String,
    /// What happened, line by line.
    pub observed: Vec<String>,
    /// How the client end of the pqbind handshake ended, when a real client ran one.
    #[cfg_attr(not(test), allow(dead_code))]
    pub client: Option<Result<(), Error>>,
    /// How the server end of the pqbind handshake ended, when a real server ran one.
    #[cfg_attr(not(test), allow(dead_code))]
    pub server: Option<Result<(), Error>>,
    /// Whether the scenario behaved as expected.
    pub passed: bool,
    /// A sentence to print after the verdict (the limit scenarios use it).
    pub note: Option<&'static str>,
}

/// Every scenario of one demo run.
#[derive(Debug, Clone)]
pub struct Report {
    /// The transport the scenarios ran over.
    pub transport: Transport,
    /// The scenarios in the order they ran.
    pub scenarios: Vec<ScenarioResult>,
}

impl Report {
    /// Whether every scenario behaved as expected.
    pub fn all_passed(&self) -> bool {
        !self.scenarios.is_empty() && self.scenarios.iter().all(|scenario| scenario.passed)
    }

    /// The scenario with this id.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn find(&self, id: &str) -> Option<&ScenarioResult> {
        self.scenarios.iter().find(|scenario| scenario.id == id)
    }
}

/// What a scenario is and what it must show.
struct Spec {
    id: &'static str,
    title: &'static str,
    story: &'static str,
    expect: &'static str,
    client_name: &'static str,
    server_name: &'static str,
    client: Option<Want>,
    server: Option<Want>,
    note: Option<&'static str>,
}

fn outcomes_text(client: Option<&Result<(), Error>>, server: Option<&Result<(), Error>>, names: (&str, &str)) -> String {
    let mut parts = Vec::new();
    if let Some(got) = client {
        parts.push(format!("{} {}", names.0, got_text(got)));
    }
    if let Some(got) = server {
        parts.push(format!("{} {}", names.1, got_text(got)));
    }
    parts.join(", ")
}

fn conclude(
    spec: &Spec,
    client: Option<Result<(), Error>>,
    server: Option<Result<(), Error>>,
    mut observed: Vec<String>,
    consistent: bool,
) -> ScenarioResult {
    let matches = |want: Option<Want>, got: &Option<Result<(), Error>>| match (want, got) {
        (None, _) => true,
        (Some(want), Some(got)) => meets(want, got),
        (Some(_), None) => false,
    };
    let passed = matches(spec.client, &client) && matches(spec.server, &server) && consistent;
    let names = (spec.client_name, spec.server_name);
    let wanted_client = spec.client.map(|want| if want == Want::Accept { Ok(()) } else { Err(want_error(want)) });
    let wanted_server = spec.server.map(|want| if want == Want::Accept { Ok(()) } else { Err(want_error(want)) });
    let expected_short = outcomes_text(wanted_client.as_ref(), wanted_server.as_ref(), names);
    let observed_short = outcomes_text(client.as_ref(), server.as_ref(), names);
    observed.insert(0, observed_short.clone());
    ScenarioResult {
        id: spec.id,
        title: spec.title,
        story: spec.story,
        expected: spec.expect.to_owned(),
        expected_short,
        observed_short,
        observed,
        client,
        server,
        passed,
        note: spec.note,
    }
}

/// The error a `Want::Reject` names (only used to print the wanted result in the same form as an observed one).
const fn want_error(want: Want) -> Error {
    match want {
        Want::Reject(error) => error,
        Want::Accept => Error::Refused,
    }
}

/// The people and keys of one demo run. Every key is made fresh from the operating system random source.
struct Cast {
    server_seed: [u8; 32],
    client_seed: [u8; 32],
    attacker_seed: [u8; 32],
    server: HybridIdentity,
    client: HybridIdentity,
    outsider: HybridIdentity,
    attacker: HybridIdentity,
    tls: Tls,
}

impl Cast {
    fn new() -> CliResult<Self> {
        let server_seed: [u8; 32] = random_array()?;
        let client_seed: [u8; 32] = random_array()?;
        let attacker_seed: [u8; 32] = random_array()?;
        Ok(Self {
            server: HybridIdentity::from_seed(&server_seed)?,
            client: HybridIdentity::from_seed(&client_seed)?,
            attacker: HybridIdentity::from_seed(&attacker_seed)?,
            outsider: HybridIdentity::generate()?,
            server_seed,
            client_seed,
            attacker_seed,
            tls: Tls::generate()?,
        })
    }

    /// A registry that enrolls `key`, for the transport identity of a client that presents no certificate.
    fn registry_with(key: &HybridIdentity) -> MemoryRegistry {
        let registry = MemoryRegistry::new();
        registry.enroll(Enrollment { key: key.public(), peer_id: PeerId::anonymous(), enrolled_at_unix_millis: now_millis() });
        registry
    }
}

/// What an attacker did, and what keeps its connection open until the scenario is over.
struct Attack {
    outcome: CliResult<()>,
    note: Option<String>,
    _link: Option<Link>,
}

impl Attack {
    fn failed(error: impl Into<CliError>) -> Self {
        Self { outcome: Err(error.into()), note: None, _link: None }
    }

    fn line(&self, done: &str) -> String {
        match &self.outcome {
            Ok(()) => done.to_owned(),
            Err(error) => format!("the attacker's own code failed: {error}"),
        }
    }
}

/// How one honest or real-code end of a handshake ended, and what keeps its connection open until the scenario is over.
struct Ended {
    result: Result<Established, Error>,
    _link: Option<Link>,
}

impl Ended {
    fn outcome(&self) -> Result<(), Error> {
        self.result.as_ref().map(|_| ()).map_err(|error| *error)
    }
}

async fn client_end(raw: Raw, me: &HybridIdentity, server_pin: &Pin) -> Ended {
    match raw.client_frames(LABEL).await {
        Err(error) => Ended { result: Err(error), _link: None },
        Ok(mut link) => {
            let result = pqbind::connect(&mut link.frames, me, &PeerId::anonymous(), &link.peer, server_pin).await;
            Ended { result, _link: Some(link) }
        }
    }
}

async fn server_end(raw: Raw, me: &HybridIdentity, own_id: &PeerId, registry: &dyn ClientRegistry) -> Ended {
    match raw.server_frames(LABEL).await {
        Err(error) => Ended { result: Err(error), _link: None },
        Ok(mut link) => {
            let result = pqbind::accept(&mut link.frames, me, own_id, &link.peer, registry).await;
            Ended { result, _link: Some(link) }
        }
    }
}

/// What an attacker can build: a hybrid proof whose Ed25519 half comes from `ed_seed` and whose ML-DSA half comes from `ml_dsa_seed`.
/// It rebuilds the signed bytes with the library's own public functions, so it signs exactly what a real proof signs.
fn forged_proof(role: Role, ed_seed: &[u8; 32], ml_dsa_seed: &[u8; 32], transcript: &Transcript<'_>) -> CliResult<Vec<u8>> {
    let signed = pqbind_crypto::hybrid::signed_bytes(&proof::transcript_bytes(role, transcript));
    let classical = pqbind_crypto::sign::SigningKey::from_seed(ed_seed).sign(&signed);
    let post_quantum = pqbind_crypto::hybrid::ml_dsa_key_of_seed(ml_dsa_seed)?.sign(&signed)?;
    let mut out = pqbind_crypto::suite::SignatureSuite::Ed25519MlDsa87.id().to_be_bytes().to_vec();
    out.extend_from_slice(&classical.to_bytes());
    out.extend_from_slice(post_quantum.as_bytes());
    Ok(out)
}

/// The server impersonator: it holds the server's TLS key and Ed25519 key, not its ML-DSA key.
async fn forge_as_server(raw: Raw, cast: &Cast) -> Attack {
    let mut link = match raw.server_frames(LABEL).await {
        Ok(link) => link,
        Err(error) => return Attack::failed(error),
    };
    let outcome = forge_server_reply(&mut link, cast).await;
    Attack { outcome, note: None, _link: Some(link) }
}

async fn forge_server_reply(link: &mut Link, cast: &Cast) -> CliResult<()> {
    let hello = link.frames.recv().await.map_err(|_| CliError::new("the client sent no HELLO"))?;
    let key_bytes = match (hello.first(), hello.get(1..1 + PUBLIC_KEY_LEN)) {
        (Some(&HELLO), Some(bytes)) => bytes,
        _ => return Err(CliError::new("the first frame is not a HELLO")),
    };
    let client_pin = PublicIdentity::from_bytes(key_bytes)?.pin();
    let server_pin = cast.server.pin();
    let server_id = cast.tls.id();
    let proof = {
        let transcript = Transcript {
            binding: link.frames.binding(),
            client_id: &link.peer,
            server_id: &server_id,
            client_pin: &client_pin,
            server_pin: &server_pin,
        };
        forged_proof(Role::Server, &cast.server_seed, &cast.attacker_seed, &transcript)?
    };
    // The server's public key is public, so the attacker presents the real one, which carries the real pin.
    let mut frame = vec![SERVER_PROOF];
    frame.extend_from_slice(cast.server.public().as_bytes());
    frame.extend_from_slice(&proof);
    link.frames.send(&frame).await.map_err(|_| CliError::new("the forged reply could not be sent"))
}

/// The client impersonator: it holds an enrolled client's Ed25519 key, not its ML-DSA key.
async fn forge_as_client(raw: Raw, cast: &Cast) -> Attack {
    let mut link = match raw.client_frames(LABEL).await {
        Ok(link) => link,
        Err(error) => return Attack::failed(error),
    };
    let (outcome, note) = match forge_client_hello(&mut link, cast).await {
        Ok(reply) => (
            Ok(()),
            Some(if reply == [REFUSED] {
                "the server answered with the single REFUSED frame".to_owned()
            } else {
                "the server sent something else".to_owned()
            }),
        ),
        Err(error) => (Err(error), None),
    };
    Attack { outcome, note, _link: Some(link) }
}

async fn forge_client_hello(link: &mut Link, cast: &Cast) -> CliResult<Vec<u8>> {
    let client_pin = cast.client.pin();
    let server_pin = cast.server.pin();
    let client_id = PeerId::anonymous();
    let proof = {
        let transcript = Transcript {
            binding: link.frames.binding(),
            client_id: &client_id,
            server_id: &link.peer,
            client_pin: &client_pin,
            server_pin: &server_pin,
        };
        forged_proof(Role::Client, &cast.client_seed, &cast.attacker_seed, &transcript)?
    };
    let mut frame = vec![HELLO];
    frame.extend_from_slice(cast.client.public().as_bytes());
    frame.extend_from_slice(&proof);
    link.frames.send(&frame).await.map_err(|_| CliError::new("the forged HELLO could not be sent"))?;
    link.frames.recv().await.map_err(|_| CliError::new("the server closed without answering"))
}

/// The relay: it terminates TLS for the client with the stolen certificate key, opens its own connection to the real server and copies
/// frames between the two. It never runs pqbind `accept` or `connect`.
async fn relay(inbound: Raw, outbound: Raw) -> Attack {
    let mut from_client = match inbound.server_frames(LABEL).await {
        Ok(link) => link,
        Err(error) => return Attack::failed(error),
    };
    let mut to_server = match outbound.client_frames(LABEL).await {
        Ok(link) => link,
        Err(error) => return Attack { outcome: Err(error.into()), note: None, _link: Some(from_client) },
    };
    let copied = copy_two_frames(&mut from_client, &mut to_server).await;
    let (outcome, note) = match copied {
        Ok(sizes) => (
            Ok(()),
            Some(format!(
                "the relay copied the client's frame ({} byte(s)) to the server and the server's answer ({} byte(s)) back",
                sizes.0, sizes.1
            )),
        ),
        Err(error) => (Err(error), None),
    };
    Attack { outcome, note, _link: Some(from_client) }
}

async fn copy_two_frames(from_client: &mut Link, to_server: &mut Link) -> CliResult<(usize, usize)> {
    let lost = |_| CliError::new("a relayed frame was lost");
    let hello = from_client.frames.recv().await.map_err(lost)?;
    to_server.frames.send(&hello).await.map_err(lost)?;
    let reply = to_server.frames.recv().await.map_err(lost)?;
    from_client.frames.send(&reply).await.map_err(lost)?;
    Ok((hello.len(), reply.len()))
}

fn attack_line(attack: &Attack, done: &str) -> Vec<String> {
    let mut lines = vec![attack.line(done)];
    if let Some(note) = &attack.note {
        lines.push(note.clone());
    }
    lines
}

/// Whether an end that succeeded authenticated the key with `pin` (an end that failed has nothing to check, and its `Want` fails the scenario).
fn saw_pin(ended: &Ended, pin: &Pin) -> bool {
    ended.result.as_ref().map_or(true, |established| established.peer_key().pin() == *pin)
}

async fn honest(transport: Transport, cast: &Cast) -> CliResult<ScenarioResult> {
    let spec = Spec {
        id: "a",
        title: "Honest pair",
        story: "A client and a server, each with its own hybrid key. The client has pinned the server's key and the server has enrolled the client's key. No attacker is involved.",
        expect: "both ends complete the pqbind handshake over the real connection",
        client_name: "client",
        server_name: "server",
        client: Some(Want::Accept),
        server: Some(Want::Accept),
        note: None,
    };
    let (client_raw, server_raw) = loopback_pair(transport, &cast.tls).await?;
    let registry = Cast::registry_with(&cast.client);
    let server_pin = cast.server.pin();
    let client_pin = cast.client.pin();
    let server_id = cast.tls.id();
    let (client, server) =
        tokio::join!(client_end(client_raw, &cast.client, &server_pin), server_end(server_raw, &cast.server, &server_id, &registry));
    // Each end must have authenticated the right key: the client the pinned server key, the server the enrolled client key.
    let client_saw_server = saw_pin(&client, &server_pin);
    let server_saw_client = saw_pin(&server, &client_pin);
    let details = vec![
        format!("server pin {} (pinned by the client, proved by the server)", short_pin(&server_pin)),
        format!("client pin {} (enrolled by the server, proved by the client)", short_pin(&client_pin)),
        format!("each end authenticated the key it expected: {}", client_saw_server && server_saw_client),
    ];
    Ok(conclude(&spec, Some(client.outcome()), Some(server.outcome()), details, client_saw_server && server_saw_client))
}

async fn server_impersonator(transport: Transport, cast: &Cast) -> CliResult<ScenarioResult> {
    let spec = Spec {
        id: "b1",
        title: "Classical break: an attacker impersonates the server",
        story: "The attacker holds the server's TLS certificate key (so the TLS handshake completes and the client's certificate check passes) and the server's Ed25519 key, but NOT its ML-DSA key. It answers the client's HELLO with the server's real public key and a forged proof.",
        expect: "the client refuses the server: it cannot prove the pinned key",
        client_name: "client",
        server_name: "attacker",
        client: Some(Want::Reject(Error::ServerIdentity)),
        server: None,
        note: None,
    };
    let (client_raw, attacker_raw) = loopback_pair(transport, &cast.tls).await?;
    let server_pin = cast.server.pin();
    let (client, attack) = tokio::join!(client_end(client_raw, &cast.client, &server_pin), forge_as_server(attacker_raw, cast));
    let mut details = vec!["the TLS handshake completed, so the transport alone would have trusted the attacker".to_owned()];
    details.extend(attack_line(&attack, "the attacker sent the server's real public key and a proof with a forged ML-DSA half"));
    Ok(conclude(&spec, Some(client.outcome()), None, details, attack.outcome.is_ok()))
}

async fn server_lookalike(transport: Transport, cast: &Cast) -> CliResult<ScenarioResult> {
    let spec = Spec {
        id: "b2",
        title: "Classical break: the attacker runs the real pqbind code",
        story: "Same attacker, same stolen TLS key, but now it runs the real pqbind accept code with its own hybrid identity instead of forging a proof. The client's proof names the pinned server key, which the attacker does not hold.",
        expect: "the client is refused: its proof does not verify for the attacker's key",
        client_name: "client",
        server_name: "attacker",
        client: Some(Want::Reject(Error::Refused)),
        server: Some(Want::Reject(Error::Refused)),
        note: None,
    };
    let (client_raw, attacker_raw) = loopback_pair(transport, &cast.tls).await?;
    let registry = Cast::registry_with(&cast.client);
    let server_pin = cast.server.pin();
    let server_id = cast.tls.id();
    let (client, attacker) =
        tokio::join!(client_end(client_raw, &cast.client, &server_pin), server_end(attacker_raw, &cast.attacker, &server_id, &registry));
    let details = vec![format!(
        "the attacker's own key has pin {} and the client pinned {}",
        short_pin(&cast.attacker.pin()),
        short_pin(&server_pin)
    )];
    Ok(conclude(&spec, Some(client.outcome()), Some(attacker.outcome()), details, true))
}

async fn client_impersonator(transport: Transport, cast: &Cast) -> CliResult<ScenarioResult> {
    let spec = Spec {
        id: "c",
        title: "Classical break: an attacker impersonates an enrolled client",
        story: "The attacker holds an enrolled client's Ed25519 key but NOT its ML-DSA key. It connects to the real server and sends the client's real public key with a forged proof.",
        expect: "the server refuses the attacker",
        client_name: "attacker",
        server_name: "server",
        client: None,
        server: Some(Want::Reject(Error::Refused)),
        note: None,
    };
    let (attacker_raw, server_raw) = loopback_pair(transport, &cast.tls).await?;
    let registry = Cast::registry_with(&cast.client);
    let server_id = cast.tls.id();
    let (attack, server) = tokio::join!(forge_as_client(attacker_raw, cast), server_end(server_raw, &cast.server, &server_id, &registry));
    let details = attack_line(&attack, "the attacker sent the client's real public key and a proof with a forged ML-DSA half");
    Ok(conclude(&spec, None, Some(server.outcome()), details, attack.outcome.is_ok()))
}

async fn relay_attack(transport: Transport, cast: &Cast) -> CliResult<ScenarioResult> {
    let spec = Spec {
        id: "d",
        title: "Relay: a man in the middle copies frames between two connections",
        story: "The attacker holds the TLS key, so it terminates TLS for the client, opens its own connection to the real server and copies the pqbind frames between them. The client's proof was made over the exporter value of the first connection, which is not the connection the server sees.",
        expect: "the server refuses the relayed proof, and the client is told it was refused",
        client_name: "client",
        server_name: "server",
        client: Some(Want::Reject(Error::Refused)),
        server: Some(Want::Reject(Error::Refused)),
        note: None,
    };
    let (client_raw, inbound) = loopback_pair(transport, &cast.tls).await?;
    let (outbound, server_raw) = loopback_pair(transport, &cast.tls).await?;
    let registry = Cast::registry_with(&cast.client);
    let server_pin = cast.server.pin();
    let server_id = cast.tls.id();
    let (client, attack, server) = tokio::join!(
        client_end(client_raw, &cast.client, &server_pin),
        relay(inbound, outbound),
        server_end(server_raw, &cast.server, &server_id, &registry)
    );
    let mut details = vec!["both TLS legs completed; the relay never ran pqbind accept or connect".to_owned()];
    details.extend(attack_line(&attack, "the relay forwarded frames"));
    Ok(conclude(&spec, Some(client.outcome()), Some(server.outcome()), details, attack.outcome.is_ok()))
}

async fn not_enrolled(transport: Transport, cast: &Cast) -> CliResult<ScenarioResult> {
    let spec = Spec {
        id: "e",
        title: "A client that was never enrolled",
        story: "A client with a perfectly valid hybrid key that the server has never enrolled. Its proof is genuine, but the server only trusts keys it enrolled beforehand.",
        expect: "the server refuses it, with the same single answer it gives for every refusal",
        client_name: "client",
        server_name: "server",
        client: Some(Want::Reject(Error::Refused)),
        server: Some(Want::Reject(Error::Refused)),
        note: None,
    };
    let (client_raw, server_raw) = loopback_pair(transport, &cast.tls).await?;
    let registry = Cast::registry_with(&cast.client);
    let server_pin = cast.server.pin();
    let server_id = cast.tls.id();
    let (client, server) =
        tokio::join!(client_end(client_raw, &cast.outsider, &server_pin), server_end(server_raw, &cast.server, &server_id, &registry));
    let details = vec![format!("the outsider's pin {} is not on the server's list", short_pin(&cast.outsider.pin()))];
    Ok(conclude(&spec, Some(client.outcome()), Some(server.outcome()), details, true))
}

async fn stolen_client_key(transport: Transport, cast: &Cast) -> CliResult<ScenarioResult> {
    let spec = Spec {
        id: "f1",
        title: "LIMIT: the whole client key is stolen",
        story: "The attacker holds BOTH halves of an enrolled client's key (the whole seed), so it can sign anything the client can.",
        expect: "the server accepts the attacker, because to the server it is the client",
        client_name: "attacker",
        server_name: "server",
        client: Some(Want::Accept),
        server: Some(Want::Accept),
        note: Some(
            "pqbind cannot help once a whole private key is stolen: whoever holds it is that peer. This is outside its threat model (THREAT_MODEL.md, \"Compromise of a private key\"), so the right answer here is that the attacker is accepted.",
        ),
    };
    let thief = HybridIdentity::from_seed(&cast.client_seed)?;
    let (attacker_raw, server_raw) = loopback_pair(transport, &cast.tls).await?;
    let registry = Cast::registry_with(&cast.client);
    let server_pin = cast.server.pin();
    let server_id = cast.tls.id();
    let (attacker, server) =
        tokio::join!(client_end(attacker_raw, &thief, &server_pin), server_end(server_raw, &cast.server, &server_id, &registry));
    let details = vec!["the server authenticated the thief as the enrolled client".to_owned()];
    Ok(conclude(&spec, Some(attacker.outcome()), Some(server.outcome()), details, true))
}

async fn stolen_server_key(transport: Transport, cast: &Cast) -> CliResult<ScenarioResult> {
    let spec = Spec {
        id: "f2",
        title: "LIMIT: the whole server key and its TLS key are stolen",
        story: "The attacker holds the server's TLS certificate key AND both halves of its hybrid key, and answers the client the way the real server would.",
        expect: "the client accepts the attacker, because it holds everything that proves the server",
        client_name: "client",
        server_name: "attacker",
        client: Some(Want::Accept),
        server: Some(Want::Accept),
        note: Some(
            "pqbind cannot help once a whole private key is stolen: whoever holds it is that peer. This is outside its threat model (THREAT_MODEL.md, \"Compromise of a private key\"), so the right answer here is that the attacker is accepted.",
        ),
    };
    let thief = HybridIdentity::from_seed(&cast.server_seed)?;
    let (client_raw, attacker_raw) = loopback_pair(transport, &cast.tls).await?;
    let registry = Cast::registry_with(&cast.client);
    let server_pin = cast.server.pin();
    let server_id = cast.tls.id();
    let (client, attacker) =
        tokio::join!(client_end(client_raw, &cast.client, &server_pin), server_end(attacker_raw, &thief, &server_id, &registry));
    let details = vec!["the client authenticated the thief as the pinned server".to_owned()];
    Ok(conclude(&spec, Some(client.outcome()), Some(attacker.outcome()), details, true))
}

/// Run every scenario over `transport`, calling `on_done` after each one, and return the report. An `Err` means the demo itself could not
/// run (for example no loopback socket), not that a scenario failed.
pub async fn run_scenarios(transport: Transport, mut on_done: impl FnMut(&ScenarioResult)) -> CliResult<Report> {
    let cast = Cast::new()?;
    let mut scenarios = Vec::new();
    for step in ["a", "b1", "b2", "c", "d", "e", "f1", "f2"] {
        let result = match step {
            "a" => honest(transport, &cast).await?,
            "b1" => server_impersonator(transport, &cast).await?,
            "b2" => server_lookalike(transport, &cast).await?,
            "c" => client_impersonator(transport, &cast).await?,
            "d" => relay_attack(transport, &cast).await?,
            "e" => not_enrolled(transport, &cast).await?,
            "f1" => stolen_client_key(transport, &cast).await?,
            _ => stolen_server_key(transport, &cast).await?,
        };
        on_done(&result);
        scenarios.push(result);
    }
    Ok(Report { transport, scenarios })
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn print_paragraph(label: &str, text: &str) {
    for (index, line) in wrap(text, 84).iter().enumerate() {
        let head = if index == 0 { label } else { "" };
        println!("    {head:<10}{line}");
    }
}

fn print_scenario(result: &ScenarioResult) {
    println!("[{}] {}", result.id, result.title);
    print_paragraph("Story:", result.story);
    print_paragraph("Expected:", &format!("{} ({})", result.expected, result.expected_short));
    for (index, line) in result.observed.iter().enumerate() {
        print_paragraph(if index == 0 { "Observed:" } else { "" }, line);
    }
    print_paragraph("Verdict:", if result.passed { "as expected" } else { "NOT AS EXPECTED" });
    if let Some(note) = result.note {
        print_paragraph("Note:", note);
    }
    println!();
}

fn print_summary(report: &Report) {
    println!("Summary (transport: {})", report.transport.name());
    println!("{:<4}{:<70}{:<46}{:<46}{}", "ID", "Scenario", "Expected", "Observed", "Verdict");
    for scenario in &report.scenarios {
        println!(
            "{:<4}{:<70}{:<46}{:<46}{}",
            scenario.id,
            scenario.title,
            scenario.expected_short,
            scenario.observed_short,
            if scenario.passed { "as expected" } else { "NOT AS EXPECTED" }
        );
    }
    println!();
    let failed = report.scenarios.iter().filter(|scenario| !scenario.passed).count();
    if failed == 0 {
        println!("All {} scenarios behaved as expected.", report.scenarios.len());
    } else {
        println!("{failed} of {} scenarios did NOT behave as expected.", report.scenarios.len());
    }
}

/// Run `pqbind demo`.
pub async fn run(args: Args) -> ExitCode {
    println!("pqbind demo (transport: {}; everything stays on 127.0.0.1)", args.transport.name());
    println!();
    for line in wrap(
        "A client and a server talk over a connection that already exists. After the transport handshake each signs the connection's own TLS exporter value, both transport identities and both key pins with a hybrid Ed25519 + ML-DSA-87 key. Assume a quantum attacker has broken everything classical: the TLS certificate key and the Ed25519 half of every pqbind key. The scenarios below run each attack for real and show what stops it, and the one thing that cannot be stopped.",
        96,
    ) {
        println!("{line}");
    }
    println!();
    match run_scenarios(args.transport, print_scenario).await {
        Ok(report) => {
            print_summary(&report);
            if report.all_passed() { ExitCode::SUCCESS } else { ExitCode::from(1) }
        }
        Err(error) => {
            eprintln!("pqbind demo: the demo could not run: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use pqbind::Error;

    use super::{Report, run_scenarios};
    use crate::common::Transport;

    async fn report(transport: Transport) -> Report {
        let mut seen = Vec::new();
        let report = run_scenarios(transport, |scenario| seen.push(scenario.id)).await.expect("the demo runs");
        assert_eq!(seen, ["a", "b1", "b2", "c", "d", "e", "f1", "f2"], "every scenario ran in order and was reported as it finished");
        report
    }

    fn assert_every_outcome(report: &Report) {
        let get = |id: &str| report.find(id).unwrap_or_else(|| panic!("scenario {id}"));
        // a: the honest pair.
        assert_eq!((get("a").client, get("a").server), (Some(Ok(())), Some(Ok(()))));
        // b1: forged server proof, the client refuses it as a server identity failure.
        assert_eq!(get("b1").client, Some(Err(Error::ServerIdentity)));
        // b2: the real accept code with the attacker's own key refuses the client, and the client sees a refusal.
        assert_eq!((get("b2").client, get("b2").server), (Some(Err(Error::Refused)), Some(Err(Error::Refused))));
        // c: the forged client proof is refused by the real server.
        assert_eq!(get("c").server, Some(Err(Error::Refused)));
        // d: the relayed proof is refused by the server, and the client is told.
        assert_eq!((get("d").client, get("d").server), (Some(Err(Error::Refused)), Some(Err(Error::Refused))));
        // e: not enrolled.
        assert_eq!((get("e").client, get("e").server), (Some(Err(Error::Refused)), Some(Err(Error::Refused))));
        // f: the whole key is accepted, and the report says it is the limit.
        for id in ["f1", "f2"] {
            assert_eq!((get(id).client, get(id).server), (Some(Ok(())), Some(Ok(()))), "{id}");
            assert!(get(id).note.is_some_and(|note| note.contains("outside its threat model")), "{id}");
        }
        for scenario in &report.scenarios {
            assert!(scenario.passed, "{} did not behave as expected: {scenario:?}", scenario.id);
            assert!(!scenario.observed.is_empty() && !scenario.expected.is_empty());
        }
        assert!(report.all_passed());
        assert!(
            report.scenarios.iter().all(|scenario| !scenario.title.contains('\u{2014}') && !scenario.story.contains('\u{2014}')),
            "no em dashes"
        );
    }

    #[tokio::test]
    async fn over_quic_every_scenario_behaves_as_expected() {
        assert_every_outcome(&report(Transport::Quic).await);
    }

    #[tokio::test]
    async fn over_tls_every_scenario_behaves_as_expected() {
        assert_every_outcome(&report(Transport::Tls).await);
    }

    #[test]
    fn a_report_with_a_failed_scenario_is_not_a_pass() {
        let empty = Report { transport: Transport::Quic, scenarios: Vec::new() };
        assert!(!empty.all_passed(), "an empty report is not a pass");
    }
}
