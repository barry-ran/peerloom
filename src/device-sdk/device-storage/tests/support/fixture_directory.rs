//! Exclusive, test-only directories; clocks are not assumed to distinguish threads.
use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn new_directory() -> io::Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    create_in(&std::env::temp_dir(), stamp)
}

fn create_in(parent: &Path, stamp: u128) -> io::Result<PathBuf> {
    let sequence = SEQUENCE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| io::Error::other("fixture sequence exhausted"))?;
    create_exact(parent, stamp, sequence)
}

fn create_exact(parent: &Path, stamp: u128, sequence: u64) -> io::Result<PathBuf> {
    let path = parent.join(format!(
        "peerloom-dpapi-{}-{stamp}-{sequence}",
        std::process::id()
    ));
    // Never adopt or remove a pre-existing path, and never retry a storage operation.
    std::fs::create_dir(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        sync::{Arc, Barrier},
        thread,
    };

    struct Owned(PathBuf);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn identical_clock_tick_is_unique_across_concurrent_fixtures() {
        // The former PID + timestamp expression aliases at this fixed clock tick.
        let old_name = || format!("peerloom-dpapi-{}-{}", std::process::id(), 7);
        let root = Owned(new_directory().unwrap());
        let old_path = root.0.join(old_name());
        std::fs::create_dir(&old_path).unwrap();
        assert_eq!(
            std::fs::create_dir(root.0.join(old_name()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        std::fs::remove_dir(old_path).unwrap();
        let barrier = Arc::new(Barrier::new(64));
        let handles: Vec<_> = (0..64)
            .map(|_| {
                let parent = root.0.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    create_in(&parent, 7).unwrap()
                })
            })
            .collect();
        let paths: HashSet<_> = handles
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect();
        assert_eq!(paths.len(), 64);
        assert!(paths.iter().all(|path| path.is_dir()));
        assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 64);
    }

    #[test]
    fn occupied_path_is_rejected_without_adoption_or_deletion() {
        let root = Owned(new_directory().unwrap());
        let occupied = create_exact(&root.0, 9, 1).unwrap();
        std::fs::write(occupied.join("owner-marker"), b"original").unwrap();
        let error = create_exact(&root.0, 9, 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(occupied.join("owner-marker")).unwrap(),
            b"original"
        );
    }
}
