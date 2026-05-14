//! Capability trait + registry.
//!
//! Each capability handles one Veriguard "validation surface" (e.g.
//! `http_attack` for §3 边界, `pcap_replay` for §4 流量, `command_inject` /
//! `implant_drop` for §5 主机).  Capabilities implement a single
//! [`Capability::execute`] entry point that takes a [`Task`] and returns a
//! [`TaskResult`].
//!
//! The [`Registry`] maps a `task.capability` string to the registered
//! [`Capability`] implementation.  Construct it once at startup, register
//! every capability the agent supports, and pass it to
//! [`crate::transport::poll::Poller::run`] as a [`TaskDispatcher`].

use std::collections::HashMap;

use crate::transport::poll::{Task, TaskDispatcher, TaskResult};

pub mod command_inject;
pub mod http_attack;
pub mod implant_drop;
pub mod pcap_replay;

#[allow(unused_imports)]
pub use command_inject::CommandInjectCapability;
#[allow(unused_imports)]
pub use http_attack::HttpAttackCapability;
#[allow(unused_imports)]
pub use implant_drop::ImplantDropCapability;
#[allow(unused_imports)]
pub use pcap_replay::PcapReplayCapability;

/// A single Veriguard validation capability.
///
/// Implementations must be `Send + Sync` so the [`Registry`] can hand out
/// shared references from inside the (single-threaded today, but
/// future-proofed) poll loop.
pub trait Capability: Send + Sync {
    /// Stable name used by the platform to route a task here.  Examples:
    /// `"http_attack"`, `"pcap_replay"`, `"command_inject"`, `"implant_drop"`.
    fn name(&self) -> &str;

    /// Execute `task` and return a [`TaskResult`].  Must not panic; report
    /// failures via `TaskResult { status: "FAILED", ... }`.
    fn execute(&self, task: &Task) -> TaskResult;
}

/// In-process map of capability name → implementation.
///
/// Cheap to construct; expensive resources (HTTP clients, subprocess
/// managers) should live on the individual [`Capability`] implementations,
/// not here, so registration is just a pointer move.
pub struct Registry {
    caps: HashMap<String, Box<dyn Capability>>,
}

impl Registry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self {
            caps: HashMap::new(),
        }
    }

    /// Register `cap` under its [`Capability::name`].  A second `register`
    /// with the same name replaces the previous entry (last-write-wins) —
    /// this is intentional so that a startup wiring file can swap in a test
    /// double without complicated ordering rules.
    pub fn register(&mut self, cap: Box<dyn Capability>) {
        self.caps.insert(cap.name().to_string(), cap);
    }

    /// Look up a capability by name.  Returns `None` if no capability has
    /// been registered under that name.
    pub fn get(&self, name: &str) -> Option<&dyn Capability> {
        self.caps.get(name).map(|c| c.as_ref())
    }

    /// Sorted list of registered capability names.  Sorted output makes the
    /// startup log line deterministic across runs.
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.caps.keys().cloned().collect();
        v.sort();
        v
    }

    /// Number of registered capabilities.
    pub fn len(&self) -> usize {
        self.caps.len()
    }

    /// `true` when no capabilities are registered.
    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskDispatcher for Registry {
    fn execute(&self, task: &Task) -> TaskResult {
        match self.get(&task.capability) {
            Some(cap) => cap.execute(task),
            None => TaskResult {
                status: "FAILED".to_string(),
                exit_code: 1,
                stdout: None,
                stderr: None,
                started_at: None,
                finished_at: None,
                error_message: Some(format!(
                    "no capability registered for {:?}",
                    task.capability
                )),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-test capability that records the tasks it was asked to execute.
    struct MockCapability {
        my_name: &'static str,
        outcome: TaskResult,
    }

    impl Capability for MockCapability {
        fn name(&self) -> &str {
            self.my_name
        }

        fn execute(&self, _task: &Task) -> TaskResult {
            self.outcome.clone()
        }
    }

    fn ok_result(tag: &str) -> TaskResult {
        TaskResult {
            status: "SUCCESS".to_string(),
            exit_code: 0,
            stdout: Some(tag.to_string()),
            stderr: None,
            started_at: None,
            finished_at: None,
            error_message: None,
        }
    }

    fn mock_task(capability: &str) -> Task {
        Task {
            task_id: "t-1".to_string(),
            capability: capability.to_string(),
            injector_type: "x".to_string(),
            payload: "{}".to_string(),
            expectations: vec![],
        }
    }

    #[test]
    fn test_registry_names_returns_sorted_list() {
        let mut r = Registry::new();
        r.register(Box::new(MockCapability {
            my_name: "pcap_replay",
            outcome: ok_result("p"),
        }));
        r.register(Box::new(MockCapability {
            my_name: "http_attack",
            outcome: ok_result("h"),
        }));
        r.register(Box::new(MockCapability {
            my_name: "implant_drop",
            outcome: ok_result("i"),
        }));
        assert_eq!(
            r.names(),
            vec!["http_attack", "implant_drop", "pcap_replay"]
        );
    }

    #[test]
    fn test_registry_get_returns_some_for_registered() {
        let mut r = Registry::new();
        r.register(Box::new(MockCapability {
            my_name: "x",
            outcome: ok_result("x"),
        }));
        assert!(r.get("x").is_some());
    }

    #[test]
    fn test_registry_get_returns_none_for_missing() {
        let r = Registry::new();
        assert!(r.get("missing").is_none());
    }

    #[test]
    fn test_registry_register_replaces_existing() {
        let mut r = Registry::new();
        r.register(Box::new(MockCapability {
            my_name: "x",
            outcome: ok_result("first"),
        }));
        r.register(Box::new(MockCapability {
            my_name: "x",
            outcome: ok_result("second"),
        }));
        assert_eq!(r.len(), 1, "second register overwrites first");

        let result = r.get("x").unwrap().execute(&mock_task("x"));
        assert_eq!(result.stdout.as_deref(), Some("second"));
    }

    #[test]
    fn test_registry_dispatcher_routes_to_capability() {
        let mut r = Registry::new();
        r.register(Box::new(MockCapability {
            my_name: "http_attack",
            outcome: ok_result("dispatched"),
        }));
        let result = r.execute(&mock_task("http_attack"));
        assert_eq!(result.status, "SUCCESS");
        assert_eq!(result.stdout.as_deref(), Some("dispatched"));
    }

    #[test]
    fn test_registry_dispatcher_returns_failed_for_unknown_capability() {
        let r = Registry::new();
        let result = r.execute(&mock_task("definitely_not_registered"));
        assert_eq!(result.status, "FAILED");
        assert_eq!(result.exit_code, 1);
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("definitely_not_registered"));
    }

    #[test]
    fn test_registry_default_is_empty() {
        let r = Registry::default();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.names().is_empty());
    }
}
