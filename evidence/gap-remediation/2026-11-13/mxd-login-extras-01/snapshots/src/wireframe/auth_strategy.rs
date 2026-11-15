//! Login authentication strategy selection for wireframe routing.
//!
//! All observed peers use the same default login authentication strategy.

use std::{future::Future, pin::Pin};

use crate::commands::{Command, CommandContext, CommandError};

/// Boxed future returned by [`AuthStrategy`] execution.
pub(crate) type AuthStrategyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), CommandError>> + Send + 'a>>;

/// Strategy abstraction for login authentication command execution.
pub(crate) trait AuthStrategy: Send + Sync {
    /// Execute login command processing for the selected strategy.
    fn authenticate<'a>(
        &self,
        command: Command,
        context: CommandContext<'a>,
    ) -> AuthStrategyFuture<'a>;
}

/// Shared default strategy used by all current peers.
#[derive(Debug, Default)]
pub(crate) struct DefaultAuthStrategy;

impl AuthStrategy for DefaultAuthStrategy {
    fn authenticate<'a>(
        &self,
        command: Command,
        context: CommandContext<'a>,
    ) -> AuthStrategyFuture<'a> {
        Box::pin(async move { command.process_with_outbound(context).await })
    }
}

/// Return the selected auth strategy label for diagnostics and tests.
#[must_use]
pub(crate) const fn auth_strategy_label() -> &'static str { "default" }

static DEFAULT_AUTH_STRATEGY: DefaultAuthStrategy = DefaultAuthStrategy;

/// Select the default login auth strategy.
#[must_use]
pub(crate) fn default_auth_strategy() -> &'static dyn AuthStrategy { &DEFAULT_AUTH_STRATEGY }

#[cfg(test)]
mod tests {
    //! Tests for this module.
    use rstest::rstest;

    use super::auth_strategy_label;
    #[rstest]
    fn auth_strategy_label_matches_default() {
        assert_eq!(auth_strategy_label(), "default");
    }
}
