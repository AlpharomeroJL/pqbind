// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run every demo scenario in order over one transport and collect the results into a report.

use super::cast::Cast;
use super::report::{Report, ScenarioResult};
use super::scenarios::ALL;
use crate::common::{CliResult, Transport};

/// Run every scenario over `transport`, calling `on_done` after each one, and return the report. An `Err` means the demo itself could not
/// run (for example no loopback socket), not that a scenario failed.
pub async fn run_scenarios(transport: Transport, mut on_done: impl FnMut(&ScenarioResult)) -> CliResult<Report> {
    let cast = Cast::new()?;
    let mut scenarios = Vec::with_capacity(ALL.len());
    for scenario in ALL {
        let result = scenario(transport, &cast).await?;
        on_done(&result);
        scenarios.push(result);
    }
    Ok(Report { transport, scenarios })
}
