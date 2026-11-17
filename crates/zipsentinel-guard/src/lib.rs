//! Resource guard: centralized enforcement of time, byte, entry, and depth
//! budgets. All enforcement paths return [`ZSError::LimitExceeded`] or
//! [`ZSError::Timeout`] — never a panic or silent truncation.

use std::io::{self, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};
use zipsentinel_core::{ResourceLimits, ZSError};

/// Tracks consumption against a [`ResourceLimits`] budget.
#[derive(Debug)]
pub struct ResourceGuard {
    limits: ResourceLimits,
    started: Instant,
    output_bytes: u64,
    uncompressed_bytes: u64,
    entries_processed: u64,
}

impl ResourceGuard {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            output_bytes: 0,
            uncompressed_bytes: 0,
            entries_processed: 0,
        }
    }

    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Fails with [`ZSError::Timeout`] when the wall-clock budget is spent.
    pub fn check_time(&self) -> Result<(), ZSError> {
        if self.started.elapsed() > self.limits.max_time {
            Err(ZSError::Timeout)
        } else {
            Ok(())
        }
    }

    /// Accounts `n` bytes of archive output (compressed side).
    pub fn consume_output(&mut self, n: u64) -> Result<(), ZSError> {
        self.output_bytes = self
            .output_bytes
            .checked_add(n)
            .ok_or_else(|| ZSError::LimitExceeded {
                limit: "output byte counter".to_string(),
                observed: u64::MAX.to_string(),
            })?;
        if self.output_bytes > self.limits.max_output_bytes {
            return Err(ZSError::LimitExceeded {
                limit: format!("max_output_bytes <= {}", self.limits.max_output_bytes),
                observed: self.output_bytes.to_string(),
            });
        }
        Ok(())
    }

    /// Accounts `n` bytes of uncompressed payload actually produced/consumed.
    pub fn consume_uncompressed(&mut self, n: u64) -> Result<(), ZSError> {
        self.check_time()?;
        self.uncompressed_bytes = self
            .uncompressed_bytes
            .checked_add(n)
            .ok_or_else(|| ZSError::LimitExceeded {
                limit: "uncompressed byte counter".to_string(),
                observed: u64::MAX.to_string(),
            })?;
        if self.uncompressed_bytes > self.limits.max_uncompressed_total {
            return Err(ZSError::LimitExceeded {
                limit: format!(
                    "max_uncompressed_total <= {}",
                    self.limits.max_uncompressed_total
                ),
                observed: self.uncompressed_bytes.to_string(),
            });
        }
        Ok(())
    }

    /// Enforces the per-entry uncompressed ceiling.
    pub fn check_entry_size(&self, n: u64) -> Result<(), ZSError> {
        if n > self.limits.max_entry_uncompressed {
            return Err(ZSError::LimitExceeded {
                limit: format!(
                    "max_entry_uncompressed <= {}",
                    self.limits.max_entry_uncompressed
                ),
                observed: n.to_string(),
            });
        }
        Ok(())
    }

    /// Registers one processed entry; fails past `max_entries`.
    pub fn consume_entry(&mut self) -> Result<(), ZSError> {
        self.entries_processed += 1;
        if self.entries_processed > self.limits.max_entries {
            return Err(ZSError::LimitExceeded {
                limit: format!("max_entries <= {}", self.limits.max_entries),
                observed: self.entries_processed.to_string(),
            });
        }
        Ok(())
    }

    pub fn entries_processed(&self) -> u64 {
        self.entries_processed
    }

    /// Fails when `depth` exceeds `max_depth`. Callers pass the nesting level
    /// they are about to enter (0 = top-level archive).
    pub fn check_depth(&self, depth: u32) -> Result<(), ZSError> {
        if depth > self.limits.max_depth {
            return Err(ZSError::LimitExceeded {
                limit: format!("max_depth <= {}", self.limits.max_depth),
                observed: depth.to_string(),
            });
        }
        Ok(())
    }

    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    pub fn uncompressed_bytes(&self) -> u64 {
        self.uncompressed_bytes
    }
}

/// An [`io::Write`] + [`io::Seek`] adapter that enforces output-byte and
/// time budgets while bytes flow through it.
pub struct GuardedWriter<W> {
    inner: W,
    guard: ResourceGuard,
    written: u64,
    check_every: u64,
}

impl<W> GuardedWriter<W> {
    pub fn new(inner: W, limits: ResourceLimits) -> Self {
        Self {
            inner,
            guard: ResourceGuard::new(limits),
            written: 0,
            check_every: 64 * 1024,
        }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    pub fn guard(&self) -> &ResourceGuard {
        &self.guard
    }

    pub fn guard_mut(&mut self) -> &mut ResourceGuard {
        &mut self.guard
    }

    pub fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl<W: Write> Write for GuardedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.guard.check_time().map_err(io::Error::other)?;
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        if self.written % self.check_every == 0 || n == buf.len() {
            self.guard
                .consume_output(self.written)
                .map_err(io::Error::other)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Seek> Seek for GuardedWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}
