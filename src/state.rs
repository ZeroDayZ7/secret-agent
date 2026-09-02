use std::sync::{Arc, RwLock};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    Starting,
    Bootstrapping,
    Ready,
    Refreshing,
    Degraded,
    Fatal,
    ShuttingDown,
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone)]
pub struct AgentStateMachine {
    inner: Arc<RwLock<AgentState>>,
}

impl AgentStateMachine {
    pub fn new() -> Self {
        let initial = AgentState::Starting;
        tracing::info!(state = %initial, "🤖 Maszyna stanów zainicjalizowana");
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    pub fn current(&self) -> AgentState {
        *self.inner.read().expect("agent state lock poisoned")
    }

    pub fn set(&self, next: AgentState) {
        let mut guard = self.inner.write().expect("agent state lock poisoned");
        let prev = *guard;
        *guard = next;

        if prev != next {
            tracing::debug!(
                from = %prev,
                to = %next,
                "🔄 Zmiana stanu agenta: [{}] ──> [{}]",
                prev,
                next
            );
        }
    }

    pub fn transition(&self, next: AgentState) -> Result<AgentState, String> {
        let current = self.current();
        let valid = matches!(
            (current, next),
            (AgentState::Starting, AgentState::Bootstrapping)
                | (AgentState::Starting, AgentState::Ready)
                | (AgentState::Starting, AgentState::Degraded)
                | (AgentState::Starting, AgentState::Fatal)
                | (AgentState::Starting, AgentState::ShuttingDown)
                | (AgentState::Bootstrapping, AgentState::Ready)
                | (AgentState::Bootstrapping, AgentState::Refreshing)
                | (AgentState::Bootstrapping, AgentState::Degraded)
                | (AgentState::Bootstrapping, AgentState::Fatal)
                | (AgentState::Bootstrapping, AgentState::ShuttingDown)
                | (AgentState::Ready, AgentState::Refreshing)
                | (AgentState::Ready, AgentState::Degraded)
                | (AgentState::Ready, AgentState::Fatal)
                | (AgentState::Ready, AgentState::ShuttingDown)
                | (AgentState::Refreshing, AgentState::Ready)
                | (AgentState::Refreshing, AgentState::Degraded)
                | (AgentState::Refreshing, AgentState::Fatal)
                | (AgentState::Refreshing, AgentState::ShuttingDown)
                | (AgentState::Degraded, AgentState::Refreshing)
                | (AgentState::Degraded, AgentState::Ready)
                | (AgentState::Degraded, AgentState::Fatal)
                | (AgentState::Degraded, AgentState::ShuttingDown)
                | (AgentState::Fatal, AgentState::ShuttingDown)
                | (AgentState::ShuttingDown, AgentState::ShuttingDown)
        );

        if !valid {
            let err_msg = format!(
                "Nieprawidłowe przejście stanu: [{}] ──x [{}]",
                current, next
            );
            tracing::error!(from = %current, to = %next, "❌ {}", err_msg);
            return Err(err_msg);
        }

        self.set(next);
        Ok(next)
    }

    #[allow(dead_code)]
    pub fn is_ready(&self) -> bool {
        matches!(self.current(), AgentState::Ready | AgentState::Refreshing)
    }

    #[allow(dead_code)]
    pub fn is_uds_accepted(&self) -> bool {
        self.is_ready()
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentState, AgentStateMachine};

    #[test]
    fn transitions_are_valid() {
        let machine = AgentStateMachine::new();
        assert!(machine.transition(AgentState::Bootstrapping).is_ok());
        assert!(machine.transition(AgentState::Ready).is_ok());
        assert!(machine.transition(AgentState::Refreshing).is_ok());
        assert!(machine.transition(AgentState::Ready).is_ok());
    }

    #[test]
    fn invalid_transition_is_rejected() {
        let machine = AgentStateMachine::new();
        assert!(machine.transition(AgentState::Refreshing).is_err());
    }
}
