//! Explicit test-feature-only phase timing. No application-controlled strings.
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Phase {
    OfferCreate,
    OfferSetLocal,
    OfferGather,
    OfferDone,
    GatherLock,
    GatherWait,
    GatherReadLocal,
    GatherValidate,
    GatherDone,
}

pub(crate) struct Trace {
    phase: Phase,
    started: Instant,
}
impl Trace {
    pub(crate) fn new(phase: Phase) -> Self {
        eprintln!("PeerloomTestDiag offer phase={phase:?} action=begin");
        Self {
            phase,
            started: Instant::now(),
        }
    }
    pub(crate) fn enter(&mut self, phase: Phase) {
        eprintln!(
            "PeerloomTestDiag offer phase={:?} elapsed_ms={} next={phase:?}",
            self.phase,
            self.started.elapsed().as_millis()
        );
        self.phase = phase;
        self.started = Instant::now();
    }
}
impl Drop for Trace {
    fn drop(&mut self) {
        eprintln!(
            "PeerloomTestDiag offer phase={:?} elapsed_ms={} action=exit",
            self.phase,
            self.started.elapsed().as_millis()
        );
    }
}
