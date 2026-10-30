//! 仅容量测试使用：区分连接句柄终态与同一目标会话的后续关闭通知。
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

pub struct TerminalCollector {
    targets: BTreeMap<u64, String>,
    completed: BTreeSet<u64>,
}

impl TerminalCollector {
    pub fn new(targets: BTreeMap<u64, String>) -> Self {
        assert!(
            targets
                .iter()
                .all(|(handle, session)| *handle != 0 && !session.is_empty())
        );
        Self {
            targets,
            completed: BTreeSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.completed.len()
    }

    pub fn observe(&mut self, kind: u32, status: u32, connection: u64, payload: &[u8]) -> bool {
        if kind != 7 {
            return false;
        }
        if connection != 0 {
            if !self.targets.contains_key(&connection) {
                return false;
            }
            self.completed.insert(connection);
            return true;
        }
        // DP_CLOSED=5 是公开 C ABI 状态；其他零句柄事件不能借此获得豁免。
        if status != 5 {
            return false;
        }
        let Ok(value) = serde_json::from_slice::<Value>(payload) else {
            return false;
        };
        let Some(session) = value.get("session_id").and_then(Value::as_str) else {
            return false;
        };
        // 仅认可本轮已请求终止的非空会话；绝不把零句柄计作连接终态。
        !session.is_empty() && self.targets.values().any(|target| target == session)
    }
}
