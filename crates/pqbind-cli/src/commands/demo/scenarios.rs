// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Define the eight demo scenarios: who holds what, what must happen, and the code that runs each one over a real connection.
//!
//! Every scenario is a function that returns a boxed future. The boxing is deliberate: each scenario holds two or three handshakes
//! and their connections, and an async state machine that large would otherwise sit on the stack of the thread that polls it.

use std::future::Future;
use std::pin::Pin;

use pqbind::{Error, HybridIdentity};

use super::attackers::{forge_as_client, forge_as_server, relay};
use super::cast::Cast;
use super::ends::{client_end, server_end};
use super::report::{ScenarioResult, Spec, Want, conclude};
use crate::common::{CliResult, Transport, short_pin};
use crate::transport::loopback_pair;

/// The future of one scenario.
pub type ScenarioFuture<'a> = Pin<Box<dyn Future<Output = CliResult<ScenarioResult>> + 'a>>;

/// One scenario, as a function.
pub type Scenario = for<'a> fn(Transport, &'a Cast) -> ScenarioFuture<'a>;

/// The scenarios in the order they run: `a`, `b1`, `b2`, `c`, `d`, `e`, `f1`, `f2`.
pub const ALL: [Scenario; 8] =
    [honest, server_impersonator, server_lookalike, client_impersonator, relay_attack, not_enrolled, stolen_client_key, stolen_server_key];

/// The note under both limit scenarios.
const LIMIT_NOTE: &str = "pqbind cannot help once a whole private key is stolen: whoever holds it is that peer. This is outside its threat model (THREAT_MODEL.md, \"Compromise of a whole private key\"), so the right answer here is that the attacker is accepted.";

/// Put a scenario's future on the heap. Taking `impl Future` (instead of boxing at the call site) also tells the compiler the error type.
fn boxed<'a>(future: impl Future<Output = CliResult<ScenarioResult>> + 'a) -> ScenarioFuture<'a> {
    Box::pin(future)
}

fn honest<'a>(transport: Transport, cast: &'a Cast) -> ScenarioFuture<'a> {
    boxed(async move {
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
        let client_saw_server = client.saw_pin(&server_pin);
        let server_saw_client = server.saw_pin(&client_pin);
        let details = vec![
            format!("server pin {} (pinned by the client, proved by the server)", short_pin(&server_pin)),
            format!("client pin {} (enrolled by the server, proved by the client)", short_pin(&client_pin)),
            format!("each end authenticated the key it expected: {}", client_saw_server && server_saw_client),
        ];
        Ok(conclude(&spec, Some(client.outcome()), Some(server.outcome()), details, client_saw_server && server_saw_client))
    })
}

fn server_impersonator<'a>(transport: Transport, cast: &'a Cast) -> ScenarioFuture<'a> {
    boxed(async move {
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
        details.extend(attack.lines("the attacker sent the server's real public key and a proof with a forged ML-DSA half"));
        Ok(conclude(&spec, Some(client.outcome()), None, details, attack.outcome.is_ok()))
    })
}

fn server_lookalike<'a>(transport: Transport, cast: &'a Cast) -> ScenarioFuture<'a> {
    boxed(async move {
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
        let (client, attacker) = tokio::join!(
            client_end(client_raw, &cast.client, &server_pin),
            server_end(attacker_raw, &cast.attacker, &server_id, &registry)
        );
        let details = vec![format!(
            "the attacker's own key has pin {} and the client pinned {}",
            short_pin(&cast.attacker.pin()),
            short_pin(&server_pin)
        )];
        Ok(conclude(&spec, Some(client.outcome()), Some(attacker.outcome()), details, true))
    })
}

fn client_impersonator<'a>(transport: Transport, cast: &'a Cast) -> ScenarioFuture<'a> {
    boxed(async move {
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
        let (attack, server) =
            tokio::join!(forge_as_client(attacker_raw, cast), server_end(server_raw, &cast.server, &server_id, &registry));
        let details = attack.lines("the attacker sent the client's real public key and a proof with a forged ML-DSA half");
        Ok(conclude(&spec, None, Some(server.outcome()), details, attack.outcome.is_ok()))
    })
}

fn relay_attack<'a>(transport: Transport, cast: &'a Cast) -> ScenarioFuture<'a> {
    boxed(async move {
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
        details.extend(attack.lines("the relay forwarded frames"));
        Ok(conclude(&spec, Some(client.outcome()), Some(server.outcome()), details, attack.outcome.is_ok()))
    })
}

fn not_enrolled<'a>(transport: Transport, cast: &'a Cast) -> ScenarioFuture<'a> {
    boxed(async move {
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
    })
}

fn stolen_client_key<'a>(transport: Transport, cast: &'a Cast) -> ScenarioFuture<'a> {
    boxed(async move {
        let spec = Spec {
            id: "f1",
            title: "LIMIT: the whole client key is stolen",
            story: "The attacker holds BOTH halves of an enrolled client's key (the whole seed), so it can sign anything the client can.",
            expect: "the server accepts the attacker, because to the server it is the client",
            client_name: "attacker",
            server_name: "server",
            client: Some(Want::Accept),
            server: Some(Want::Accept),
            note: Some(LIMIT_NOTE),
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
    })
}

fn stolen_server_key<'a>(transport: Transport, cast: &'a Cast) -> ScenarioFuture<'a> {
    boxed(async move {
        let spec = Spec {
            id: "f2",
            title: "LIMIT: the whole server key and its TLS key are stolen",
            story: "The attacker holds the server's TLS certificate key AND both halves of its hybrid key, and answers the client the way the real server would.",
            expect: "the client accepts the attacker, because it holds everything that proves the server",
            client_name: "client",
            server_name: "attacker",
            client: Some(Want::Accept),
            server: Some(Want::Accept),
            note: Some(LIMIT_NOTE),
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
    })
}
