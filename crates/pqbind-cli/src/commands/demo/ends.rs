// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run one honest end (or real-code end) of the pqbind handshake over a connection, and say how it ended.

use pqbind::{ClientRegistry, Error, Established, HybridIdentity, PeerId, Pin};

use super::LABEL;
use crate::transport::{Link, Raw};

/// How one honest or real-code end of a handshake ended, and what keeps its connection open until the scenario is over.
pub struct Ended {
    pub result: Result<Established, Error>,
    _link: Option<Link>,
}

impl Ended {
    /// How the handshake ended, without the established session.
    pub fn outcome(&self) -> Result<(), Error> {
        self.result.as_ref().map(|_| ()).map_err(|error| *error)
    }

    /// Whether an end that succeeded authenticated the key with `pin` (an end that failed has nothing to check, and its `Want` fails the scenario).
    pub fn saw_pin(&self, pin: &Pin) -> bool {
        self.result.as_ref().map_or(true, |established| established.peer_key().pin() == *pin)
    }
}

/// The client end: connect to a server whose key has the pin `server_pin`.
pub async fn client_end(raw: Raw, me: &HybridIdentity, server_pin: &Pin) -> Ended {
    match raw.client_frames(LABEL).await {
        Err(error) => Ended { result: Err(error), _link: None },
        Ok(mut link) => {
            let result = pqbind::connect(&mut link.frames, me, &PeerId::anonymous(), &link.peer, server_pin).await;
            Ended { result, _link: Some(link) }
        }
    }
}

/// The server end: accept a client that `registry` enrolls.
pub async fn server_end(raw: Raw, me: &HybridIdentity, own_id: &PeerId, registry: &dyn ClientRegistry) -> Ended {
    match raw.server_frames(LABEL).await {
        Err(error) => Ended { result: Err(error), _link: None },
        Ok(mut link) => {
            let result = pqbind::accept(&mut link.frames, me, own_id, &link.peer, registry).await;
            Ended { result, _link: Some(link) }
        }
    }
}
