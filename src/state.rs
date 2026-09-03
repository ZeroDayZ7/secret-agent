use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    Starting = 0,
    Bootstrapping = 1,
    Ready = 2,
    Refreshing = 3,
    Degraded = 4,
    Fatal = 5,
    ShuttingDown = 6,
}

impl std::fmt::Debug for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AgentState::Starting => "Starting",
            AgentState::Bootstrapping => "Bootstrapping",
            AgentState::Ready => "Ready",
            AgentState::Refreshing => "Refreshing",
            AgentState::Degraded => "Degraded",
            AgentState::Fatal => "Fatal",
            AgentState::ShuttingDown => "ShuttingDown",
        };
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone)]
pub struct AgentStateMachine {
    inner: Arc<AtomicU8>,
}

impl AgentStateMachine {
    pub fn new() -> Self {
        let initial = AgentState::Starting;
        tracing::info!(state = %initial, "🤖 Maszyna stanów zainicjalizowana");
        Self {
            inner: Arc::new(AtomicU8::new(initial as u8)),
        }
    }

    fn from_u8(v: u8) -> AgentState {
        match v {
            1 => AgentState::Bootstrapping,
            2 => AgentState::Ready,
            3 => AgentState::Refreshing,
            4 => AgentState::Degraded,
            5 => AgentState::Fatal,
            6 => AgentState::ShuttingDown,
            _ => AgentState::Starting,
        }
    }

    pub fn current(&self) -> AgentState {
        let v = self.inner.load(Ordering::SeqCst);
        Self::from_u8(v)
    }

    pub fn set(&self, next: AgentState) {
        let prev = self.current();
        self.inner.store(next as u8, Ordering::SeqCst);

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
        loop {
            let current_u8 = self.inner.load(Ordering::SeqCst);
            let current = Self::from_u8(current_u8);

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

            // Attempt CAS
            match self.inner.compare_exchange(
                current_u8,
                next as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    tracing::debug!(from = %current, to = %next, "🔄 CAS state transition ok");
                    return Ok(next);
                }
                Err(actual) => {
                    // someone changed the state concurrently; retry loop
                    let _ = actual;
                    continue;
                }
            }
        }
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
