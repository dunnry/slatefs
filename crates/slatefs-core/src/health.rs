use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::Notify;

use crate::error::{Error, Result, is_fenced_slatedb_error};
use crate::vfs::{FsError, FsResult};

pub(crate) struct VolumeHealth {
    fsid: Option<u64>,
    dead: AtomicBool,
    fencing_events: AtomicU64,
    degraded: AtomicBool,
    storage_errors: AtomicU64,
    dead_notify: Notify,
}

impl VolumeHealth {
    pub(crate) fn new(fsid: Option<u64>) -> Self {
        Self {
            fsid,
            dead: AtomicBool::new(false),
            fencing_events: AtomicU64::new(0),
            degraded: AtomicBool::new(false),
            storage_errors: AtomicU64::new(0),
            dead_notify: Notify::new(),
        }
    }

    pub(crate) fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    pub(crate) fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    pub(crate) fn writer_fencing_events(&self) -> u64 {
        self.fencing_events.load(Ordering::Relaxed)
    }

    pub(crate) fn storage_errors(&self) -> u64 {
        self.storage_errors.load(Ordering::Relaxed)
    }

    pub(crate) fn ensure_live(&self) -> FsResult<()> {
        if self.is_dead() {
            Err(FsError::Io)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn wait_dead(&self) {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
        while !self.is_dead() {
            tokio::select! {
                _ = self.dead_notify.notified() => {}
                _ = tick.tick() => {}
            }
        }
    }

    pub(crate) fn mark_fenced(&self) {
        if !self.dead.swap(true, Ordering::AcqRel) {
            self.fencing_events.fetch_add(1, Ordering::Relaxed);
            match self.fsid {
                Some(fsid) => {
                    tracing::error!(
                        fsid = %format!("{:016x}", fsid),
                        "volume fenced by newer SlateDB writer; marking export dead"
                    );
                }
                None => {
                    tracing::error!(
                        "block volume fenced by newer SlateDB writer; marking export dead"
                    );
                }
            }
            self.dead_notify.notify_waiters();
        }
    }

    pub(crate) fn mark_degraded(&self, error: &str) {
        let errors = self.storage_errors.fetch_add(1, Ordering::Relaxed) + 1;
        match self.fsid {
            Some(fsid) => {
                if !self.degraded.swap(true, Ordering::AcqRel) {
                    tracing::warn!(
                        fsid = %format!("{:016x}", fsid),
                        storage_errors = errors,
                        error = %error,
                        "volume degraded after storage error"
                    );
                } else {
                    tracing::debug!(
                        fsid = %format!("{:016x}", fsid),
                        storage_errors = errors,
                        error = %error,
                        "volume storage error while degraded"
                    );
                }
            }
            None => {
                if !self.degraded.swap(true, Ordering::AcqRel) {
                    tracing::warn!(
                        storage_errors = errors,
                        error,
                        "block volume degraded after storage error"
                    );
                } else {
                    tracing::debug!(
                        storage_errors = errors,
                        error,
                        "block volume storage error while degraded"
                    );
                }
            }
        }
    }

    pub(crate) fn note_storage_error(&self, error: &slatedb::Error) {
        if is_fenced_slatedb_error(error) {
            self.mark_fenced();
        } else {
            self.mark_degraded(&error.to_string());
        }
    }

    pub(crate) fn note_core_error(&self, error: &Error) {
        match error {
            Error::SlateDb(error) => self.note_storage_error(error),
            Error::ObjectStore(_) | Error::Crypto(_) | Error::Codec(_) | Error::Io(_) => {
                self.mark_degraded(&error.to_string());
            }
            Error::NotFound { .. }
            | Error::AlreadyExists { .. }
            | Error::Invalid { .. }
            | Error::Config(_) => {}
        }
    }

    pub(crate) fn map_storage<T>(
        &self,
        result: std::result::Result<T, slatedb::Error>,
    ) -> FsResult<T> {
        if self.is_dead() {
            return Err(FsError::Io);
        }
        match result {
            Ok(value) => {
                self.ensure_live()?;
                Ok(value)
            }
            Err(error) => {
                self.note_storage_error(&error);
                Err(FsError::from(error))
            }
        }
    }

    pub(crate) fn map_core<T>(&self, result: Result<T>) -> FsResult<T> {
        if self.is_dead() {
            return Err(FsError::Io);
        }
        match result {
            Ok(value) => {
                self.ensure_live()?;
                Ok(value)
            }
            Err(error) => {
                self.note_core_error(&error);
                Err(FsError::from(error))
            }
        }
    }
}
