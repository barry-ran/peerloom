//! 无网络的容量收集器回归；独立 target 不改变 ffi_scale 的单 ignored 用例清单。
#[path = "support/terminal_collector.rs"]
mod terminal_collector;

use std::collections::BTreeMap;
use terminal_collector::TerminalCollector;

fn collector() -> TerminalCollector {
    TerminalCollector::new(BTreeMap::from([
        (11, "target-a".into()),
        (12, "target-b".into()),
    ]))
}

#[test]
fn target_session_notice_never_counts_or_replaces_a_handle() {
    let mut collector = collector();
    for _ in 0..100 {
        for status in [5, 255] {
            assert!(collector.observe(7, status, 0, br#"{"session_id":"target-a"}"#));
        }
    }
    assert_eq!(collector.len(), 0);
    assert!(collector.observe(7, 255, 11, b""));
    assert_eq!(collector.len(), 1);
    assert!(collector.observe(7, 255, 0, br#"{"session_id":"target-b"}"#));
    assert_eq!(collector.len(), 1);
    assert!(collector.observe(7, 5, 12, b""));
    assert_eq!(collector.len(), 2);
}

#[test]
fn twenty_original_handles_are_required_despite_zero_and_duplicate_notifications() {
    let targets = (1..=20)
        .map(|handle| (handle, format!("target-{handle}")))
        .collect();
    let mut collector = TerminalCollector::new(targets);
    for handle in 1..=20 {
        let payload = format!("{{\"session_id\":\"target-{handle}\"}}");
        for status in [5, 255] {
            assert!(collector.observe(7, status, 0, payload.as_bytes()));
        }
    }
    assert_eq!(collector.len(), 0);
    for handle in 1..=20 {
        assert!(collector.observe(7, 5, handle, b""));
        assert!(collector.observe(7, 5, handle, b""));
        assert_eq!(collector.len(), handle as usize);
    }
}

#[test]
fn zero_handle_requires_nonempty_exact_target_session() {
    let mut collector = collector();
    for payload in [
        b"".as_slice(),
        b"not-json",
        b"null",
        b"[]",
        b"{}",
        br#"{"session_id":null}"#,
        br#"{"session_id":5}"#,
        br#"{"session_id":""}"#,
        br#"{"session_id":"sibling"}"#,
        br#"{"session_id":"unknown"}"#,
        br#"{"session_id":"target-a-suffix"}"#,
    ] {
        for status in [5, 255] {
            assert!(!collector.observe(7, status, 0, payload));
        }
        assert_eq!(collector.len(), 0);
    }
}

#[test]
fn other_kind_status_or_non_target_handle_is_rejected() {
    let mut collector = collector();
    let payload = br#"{"session_id":"target-a"}"#;
    for status in [0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 254, 256, u32::MAX] {
        assert!(!collector.observe(7, status, 0, payload));
    }
    for kind in [0, 1, 5, 6, 9, 13, u32::MAX] {
        for status in [5, 255] {
            assert!(!collector.observe(kind, status, 0, payload));
            assert!(!collector.observe(kind, status, 11, payload));
        }
    }
    for status in [5, 255] {
        assert!(!collector.observe(7, status, 13, payload));
        assert!(!collector.observe(7, status, u64::MAX, payload));
    }
    assert_eq!(collector.len(), 0);
}

#[test]
fn terminal_notice_statuses_match_the_public_c_header() {
    for definition in [
        "#define DP_CLOSED UINT32_C(5)",
        "#define DP_INTERNAL UINT32_C(255)",
    ] {
        assert!(
            include_str!("../include/device_sdk.h")
                .lines()
                .any(|line| line == definition)
        );
    }
}

#[test]
fn tail_predicate_accepts_only_target_zero_notices_without_counting() {
    let mut collector = collector();
    let payload = br#"{"session_id":"target-a"}"#;
    for status in [5, 255] {
        assert!(collector.is_target_zero_notice(7, status, 0, payload));
        assert_eq!(collector.len(), 0);
    }
    assert!(collector.observe(7, 5, 11, b""));
    assert!(collector.observe(7, 255, 12, b""));
    for status in [5, 255] {
        assert!(collector.is_target_zero_notice(7, status, 0, payload));
        for handle in [11, 12, 13, u64::MAX] {
            assert!(!collector.is_target_zero_notice(7, status, handle, payload));
        }
        for kind in [0, 1, 5, 6, 9, 13, u32::MAX] {
            assert!(!collector.is_target_zero_notice(kind, status, 0, payload));
        }
        for invalid in [
            b"".as_slice(),
            b"{",
            b"null",
            br#"{"session_id":""}"#,
            br#"{"session_id":"sibling"}"#,
            br#"{"session_id":"unknown"}"#,
        ] {
            assert!(!collector.is_target_zero_notice(7, status, 0, invalid));
        }
    }
    for status in [0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 254, 256, u32::MAX] {
        assert!(!collector.is_target_zero_notice(7, status, 0, payload));
    }
    assert_eq!(collector.len(), 2);
}
