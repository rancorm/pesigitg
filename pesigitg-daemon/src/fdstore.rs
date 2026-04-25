// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! systemd FDSTORE plumbing for AF_XDP socket + UMEM memfd handoff.
//!
//! On graceful shutdown via SIGUSR2 the daemon hands each worker's
//! AF_XDP sockfd and UMEM memfd to systemd's per-service FD store.
//! The next daemon invocation reads them back via `LISTEN_FDS` /
//! `LISTEN_FDNAMES` and rehydrates them into [`AdoptedSocket`]s
//! instead of cold-creating, which preserves all kernel state
//! (UMEM registration, ring allocations, bind) across the restart.
//!
//! [`AdoptedSocket`]: crate::xdp_adopt::AdoptedSocket
//!
//! Naming convention: each AF_XDP queue contributes two FDs under
//! the names `pesigitg-q{queue_id}-sock` and `pesigitg-q{queue_id}-umem`.
//! The pair is matched on receipt by stripping the suffix and
//! parsing the queue id.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result};
use log::{debug, warn};
use sd_notify::NotifyState;

const SOCK_SUFFIX: &str = "-sock";
const UMEM_SUFFIX: &str = "-umem";
const NAME_PREFIX: &str = "pesigitg-q";

fn sock_name(queue_id: u32) -> String {
    format!("{NAME_PREFIX}{queue_id}{SOCK_SUFFIX}")
}

fn umem_name(queue_id: u32) -> String {
    format!("{NAME_PREFIX}{queue_id}{UMEM_SUFFIX}")
}

/// Match an FDSTORE name against the convention. Returns
/// `(queue_id, kind)` where `kind` is "sock" or "umem", or `None` if
/// the name doesn't fit our scheme.
fn parse_name(name: &str) -> Option<(u32, FdKind)> {
    let body = name.strip_prefix(NAME_PREFIX)?;
    if let Some(qid) = body.strip_suffix(SOCK_SUFFIX) {
        Some((qid.parse().ok()?, FdKind::Sock))
    } else if let Some(qid) = body.strip_suffix(UMEM_SUFFIX) {
        Some((qid.parse().ok()?, FdKind::Umem))
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FdKind {
    Sock,
    Umem,
}

/// FDs inherited from systemd's per-service FD store, paired by
/// queue id. Sockfd and UMEM memfd come together; orphans of either
/// kind are discarded with a warning.
#[derive(Default)]
pub struct InheritedFds {
    pub by_queue: HashMap<u32, (OwnedFd, OwnedFd)>,
}

impl InheritedFds {
    pub fn is_empty(&self) -> bool {
        self.by_queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_queue.len()
    }
}

/// Read inherited FDs from systemd. Returns an empty set if
/// `LISTEN_FDS` is unset (cold boot — no handoff). Errors only on
/// truly broken state (`LISTEN_PID` mismatch, malformed env).
pub fn inherit_from_systemd() -> Result<InheritedFds> {
    let entries =
        sd_notify::listen_fds_with_names(true).context("listen_fds_with_names from systemd")?;

    let mut socks: HashMap<u32, OwnedFd> = HashMap::new();
    let mut umems: HashMap<u32, OwnedFd> = HashMap::new();

    for (raw_fd, name) in entries {
        // SAFETY: each fd was just produced by listen_fds (which
        // verified LISTEN_PID and set CLOEXEC); this is the sole owner.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        match parse_name(&name) {
            Some((qid, FdKind::Sock)) => {
                if socks.insert(qid, fd).is_some() {
                    warn!("duplicate sockfd from FDSTORE for queue {qid}, replacing");
                }
            }
            Some((qid, FdKind::Umem)) => {
                if umems.insert(qid, fd).is_some() {
                    warn!("duplicate UMEM fd from FDSTORE for queue {qid}, replacing");
                }
            }
            None => {
                warn!("FDSTORE entry with unrecognised name '{name}' — dropping");
                // fd is dropped here, closing it.
            }
        }
    }

    let mut by_queue = HashMap::new();
    for (qid, sock) in socks {
        if let Some(umem) = umems.remove(&qid) {
            by_queue.insert(qid, (sock, umem));
        } else {
            warn!("FDSTORE has sockfd for queue {qid} but no matching UMEM — dropping");
        }
    }
    if !umems.is_empty() {
        let orphan: Vec<u32> = umems.keys().copied().collect();
        warn!("FDSTORE has UMEM fds with no sockfd, dropping queues={orphan:?}");
    }

    debug!(
        "inherited {} AF_XDP queue(s) from systemd FDSTORE",
        by_queue.len()
    );

    Ok(InheritedFds { by_queue })
}

/// Hand a batch of (sockfd, umem_fd) pairs to systemd's FDSTORE,
/// each with a per-queue name so the next invocation can match
/// them up. Drops the OwnedFds after sending — systemd `dup`s them
/// via `SCM_RIGHTS`, so closing our copies doesn't drop the kernel
/// references.
///
/// Returns the count of queues actually exported. If no
/// `NOTIFY_SOCKET` is set (running outside systemd), this is a
/// silent no-op and returns 0.
pub fn export_to_systemd(fds: Vec<(u32, OwnedFd, OwnedFd)>) -> Result<usize> {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        debug!("FDSTORE export skipped: NOTIFY_SOCKET unset (not running under systemd)");
        return Ok(0);
    }

    let mut exported = 0;
    for (qid, sock, umem) in fds {
        send_one(qid, &sock, &umem).with_context(|| format!("FDSTORE export for queue {qid}"))?;
        exported += 1;
        // Explicit drop is implicit at end of iteration; comment
        // for the reader: the fds close here, but systemd already
        // dup'd them and holds its own copy.
        drop(sock);
        drop(umem);
    }
    Ok(exported)
}

fn send_one(queue_id: u32, sock: &OwnedFd, umem: &OwnedFd) -> Result<()> {
    let sock_name = sock_name(queue_id);
    let umem_name = umem_name(queue_id);

    // FDNAME applies to all FDs in a single sd_notify message, so we
    // send the sock and umem in separate messages with their own names.
    let sock_borrow = unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    sd_notify::notify_with_fds(
        false,
        &[NotifyState::FdStore, NotifyState::FdName(&sock_name)],
        &[sock_borrow],
    )
    .context("notify_with_fds(sock)")?;

    let umem_borrow = unsafe { BorrowedFd::borrow_raw(umem.as_raw_fd()) };
    sd_notify::notify_with_fds(
        false,
        &[NotifyState::FdStore, NotifyState::FdName(&umem_name)],
        &[umem_borrow],
    )
    .context("notify_with_fds(umem)")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_parses_round_trip() {
        for qid in [0u32, 1, 7, 64, 4095] {
            assert_eq!(parse_name(&sock_name(qid)), Some((qid, FdKind::Sock)));
            assert_eq!(parse_name(&umem_name(qid)), Some((qid, FdKind::Umem)));
        }
    }

    #[test]
    fn name_rejects_garbage() {
        assert_eq!(parse_name(""), None);
        assert_eq!(parse_name("pesigitg-q"), None);
        assert_eq!(parse_name("pesigitg-qabc-sock"), None);
        assert_eq!(parse_name("pesigitg-q5-other"), None);
        assert_eq!(parse_name("foo-q5-sock"), None);
    }
}
