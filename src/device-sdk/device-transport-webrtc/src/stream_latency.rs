//! Estimates SDK send-to-parse latency; never a capture/render or exact one-way metric.
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

pub fn now_us() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_micros()
        .min(u64::MAX as u128 - 1) as u64
        + 1
}
const SYNC_TTL_US: u64 = 10_000_000;
/// Last actual DATA-chunk timing, not a probe RTT divided by two.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChannelLatencyStats {
    pub available: bool,
    pub rx_delay_us: u64,
    pub uncertainty_us: u64,
    pub sample_age_ms: u64,
    pub sample_count: u64,
}
#[derive(Default)]
struct State {
    offset: i128,
    rtt: u64,
    synced: u64,
    received: u64,
    delay: u64,
    sample_count: u64,
    valid_data: bool,
}
#[derive(Clone, Default)]
pub struct LatencyMonitor(Arc<Mutex<State>>);
impl LatencyMonitor {
    pub fn snapshot(&self) -> ChannelLatencyStats {
        self.snapshot_at(now_us())
    }
    fn snapshot_at(&self, now: u64) -> ChannelLatencyStats {
        let Ok(s) = self.0.lock() else {
            return ChannelLatencyStats::default();
        };
        // Conservative 100 ppm drift allowance, in addition to asymmetric-path RTT/2.
        let uncertainty = s.rtt.div_ceil(2).saturating_add(
            now.saturating_sub(s.synced)
                .saturating_add(s.delay)
                .div_ceil(10_000),
        );
        ChannelLatencyStats {
            available: s.synced != 0 && s.valid_data && now.saturating_sub(s.synced) <= SYNC_TTL_US,
            rx_delay_us: s.delay,
            uncertainty_us: uncertainty,
            sample_age_ms: if s.received == 0 {
                u64::MAX
            } else {
                now.saturating_sub(s.received) / 1000
            },
            sample_count: s.sample_count,
        }
    }
    pub(crate) fn synchronize(&self, t1: u64, t2: u64, t3: u64, t4: u64) {
        if t1 == 0 || t2 == 0 || t4 < t1 || t3 < t2 {
            return;
        }
        let Some(rtt) = (t4 - t1).checked_sub(t3 - t2) else {
            return;
        };
        if rtt > SYNC_TTL_US {
            return;
        }
        let Ok(mut s) = self.0.lock() else {
            return;
        };
        if s.synced == 0 || t4.saturating_sub(s.synced) > SYNC_TTL_US / 2 || rtt <= s.rtt {
            s.valid_data = false;
            s.offset = ((t2 as i128 - t1 as i128) + (t3 as i128 - t4 as i128)) / 2;
            s.rtt = rtt;
            s.synced = t4;
        }
    }
    pub(crate) fn received(&self, sent: u64, received: u64) {
        let Ok(mut s) = self.0.lock() else {
            return;
        };
        s.sample_count = s.sample_count.saturating_add(1);
        s.received = received;
        let delay = received as i128 + s.offset - sent as i128;
        s.valid_data = sent != 0 && s.synced != 0 && delay >= 0 && delay <= u64::MAX as i128;
        s.delay = if s.valid_data { delay as u64 } else { 0 };
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_data_with_offset_and_asymmetry_bound() {
        let m = LatencyMonitor::default();
        // Remote clock is +1000 us; path is 20 us each, remote processing 10 us.
        m.synchronize(100, 1120, 1130, 150);
        m.received(1200, 220);
        let s = m.snapshot_at(220);
        assert!(s.available);
        assert_eq!(s.rx_delay_us, 20);
        assert!(s.uncertainty_us >= 20);
        assert_eq!(s.sample_count, 1);
        assert!(!m.snapshot_at(11_000_000).available);
    }
    #[test]
    fn asymmetric_path_estimate_stays_within_reported_budget() {
        let m = LatencyMonitor::default();
        // True remote offset +1000, forward=10, reverse=90, processing=5.
        m.synchronize(100, 1110, 1115, 205);
        // Actual receive leg 90. Offset estimate is biased by -40.
        m.received(1300, 390);
        let s = m.snapshot_at(390);
        assert!(s.available);
        assert_eq!(s.rx_delay_us, 50);
        assert!(90u64.abs_diff(s.rx_delay_us) <= s.uncertainty_us);
    }
    #[test]
    fn high_rtt_exposes_uncertainty_instead_of_hiding_weak_networks() {
        let m = LatencyMonitor::default();
        m.synchronize(100, 110, 115, 300_105);
        m.received(400_000, 550_040);
        let s = m.snapshot_at(550_040);
        assert!(s.available);
        assert!(s.uncertainty_us >= 150_000);
    }
    #[test]
    fn four_second_admission_backlog_is_not_hidden_or_clamped() {
        let m = LatencyMonitor::default();
        m.synchronize(100, 1120, 1130, 150);
        m.received(1200, 4_000_220);
        let s = m.snapshot_at(4_000_220);
        assert!(s.available);
        assert_eq!(s.rx_delay_us, 4_000_020);
        assert!(s.uncertainty_us >= 420);
    }
    #[test]
    fn no_sync_invalid_or_negative_samples_are_unavailable() {
        let m = LatencyMonitor::default();
        m.received(10, 20);
        assert!(!m.snapshot_at(20).available);
        m.synchronize(100, 100, 200, 150); // impossible remote processing > total RTT
        assert!(!m.snapshot_at(150).available);
        m.synchronize(100, 1120, 1130, 150);
        m.received(9000, 200);
        assert!(!m.snapshot_at(200).available);
    }
}
