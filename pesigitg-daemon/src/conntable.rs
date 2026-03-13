//! Per-worker connection table for fallback routing of unroutable QUIC CIDs.
//!
//! When a packet's Connection ID cannot be decoded (e.g. a client-generated
//! Initial CID), the connection table provides stickiness by mapping the
//! flow's 4-tuple (and optionally the raw DCID) to a backend server chosen
//! via consistent hashing.
//!
//! Each AF_XDP worker thread owns its own table -- no cross-thread sharing
//! is needed because RSS/flow director pins flows to NIC queues.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

/// TTL for connection table entries.
///
/// Entries live long enough to cover the QUIC handshake (typically 1-2 RTTs)
/// until the server's CID-encoded response reaches the client and subsequent
/// packets use a routable, server-generated CID.
const ENTRY_TTL: Duration = Duration::from_secs(5);

/// How often to sweep expired entries from the table.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// Pre-allocated capacity for each hash map. Sized above expected peak
/// concurrent handshakes so the maps never resize during normal operation.
const INITIAL_CAPACITY: usize = 8192;

/// 4-tuple flow identifier.
#[derive(Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Raw DCID key for NAT rebinding resilience.
///
/// Stores up to 20 bytes (maximum QUIC Connection ID length).
/// If a client retransmits its Initial from a different source IP (NAT
/// rebinding during handshake), the 4-tuple changes but the DCID stays
/// the same. This index ensures the retransmit reaches the same backend.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct DcidKey {
    len: u8,
    bytes: [u8; 20],
}

impl DcidKey {
    pub fn from_slice(dcid: &[u8]) -> Self {
        let mut bytes = [0u8; 20];
        let len = dcid.len().min(20);
        bytes[..len].copy_from_slice(&dcid[..len]);
        DcidKey {
            len: len as u8,
            bytes,
        }
    }
}

struct Entry {
    mac: [u8; 6],
    expires: Instant,
}

impl Entry {
    fn new(mac: [u8; 6]) -> Self {
        Entry {
            mac,
            expires: Instant::now() + ENTRY_TTL,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires
    }
}

/// Per-worker connection table with 4-tuple and DCID indexes.
pub struct ConnectionTable {
    by_flow: FxHashMap<FlowKey, Entry>,
    by_dcid: FxHashMap<DcidKey, Entry>,
    last_sweep: Instant,
}

impl ConnectionTable {
    pub fn new() -> Self {
        ConnectionTable {
            by_flow: FxHashMap::with_capacity_and_hasher(INITIAL_CAPACITY, Default::default()),
            by_dcid: FxHashMap::with_capacity_and_hasher(INITIAL_CAPACITY, Default::default()),
            last_sweep: Instant::now(),
        }
    }

    /// Look up a MAC address by 4-tuple, falling back to DCID.
    pub fn lookup(&self, flow: &FlowKey, dcid: Option<&DcidKey>) -> Option<[u8; 6]> {
        if let Some(entry) = self.by_flow.get(flow) {
            if !entry.is_expired() {
                return Some(entry.mac);
            }
        }

        if let Some(key) = dcid {
            if let Some(entry) = self.by_dcid.get(key) {
                if !entry.is_expired() {
                    return Some(entry.mac);
                }
            }
        }

        None
    }

    /// Record a fallback routing decision in both indexes.
    pub fn insert(&mut self, flow: FlowKey, dcid: Option<DcidKey>, mac: [u8; 6]) {
        self.by_flow.insert(flow, Entry::new(mac));
        if let Some(key) = dcid {
            self.by_dcid.insert(key, Entry::new(mac));
        }
    }

    /// Record a DCID -> server mapping from a successfully CID-routed packet.
    ///
    /// This enables NAT rebinding resilience: if the client's source IP
    /// changes mid-handshake, the DCID still maps to the correct server.
    pub fn record_dcid(&mut self, dcid: DcidKey, mac: [u8; 6]) {
        self.by_dcid.insert(dcid, Entry::new(mac));
    }

    /// Evict expired entries if the sweep interval has elapsed.
    pub fn maybe_sweep(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        self.by_flow.retain(|_, e| !e.is_expired());
        self.by_dcid.retain(|_, e| !e.is_expired());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_lookup_by_flow() {
        let mut table = ConnectionTable::new();
        let flow = FlowKey {
            src_addr: "10.0.0.1".parse().unwrap(),
            dst_addr: "10.0.1.10".parse().unwrap(),
            src_port: 12345,
            dst_port: 443,
        };

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        table.insert(flow, None, mac);

        let lookup_flow = FlowKey {
            src_addr: "10.0.0.1".parse().unwrap(),
            dst_addr: "10.0.1.10".parse().unwrap(),
            src_port: 12345,
            dst_port: 443,
        };

        assert_eq!(table.lookup(&lookup_flow, None), Some(mac));
    }

    #[test]
    fn lookup_by_dcid_fallback() {
        let mut table = ConnectionTable::new();
        let dcid = DcidKey::from_slice(&[0x01, 0x02, 0x03]);

        table.insert(
            FlowKey {
                src_addr: "10.0.0.1".parse().unwrap(),
                dst_addr: "10.0.1.10".parse().unwrap(),
                src_port: 12345,
                dst_port: 443,
            },
            Some(DcidKey::from_slice(&[0x01, 0x02, 0x03])),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05],
        );

        // Different 4-tuple, same DCID -> still resolves
        let other_flow = FlowKey {
            src_addr: "10.0.0.99".parse().unwrap(),
            dst_addr: "10.0.1.10".parse().unwrap(),
            src_port: 54321,
            dst_port: 443,
        };

        assert_eq!(table.lookup(&other_flow, Some(&dcid)), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05]));
    }

    #[test]
    fn record_dcid_from_cid_route() {
        let mut table = ConnectionTable::new();
        let dcid = DcidKey::from_slice(&[0xaa, 0xbb]);

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03];
        table.record_dcid(dcid, mac);

        let lookup_dcid = DcidKey::from_slice(&[0xaa, 0xbb]);
        let unrelated_flow = FlowKey {
            src_addr: "10.0.0.1".parse().unwrap(),
            dst_addr: "10.0.1.10".parse().unwrap(),
            src_port: 9999,
            dst_port: 443,
        };

        assert_eq!(table.lookup(&unrelated_flow, Some(&lookup_dcid)), Some(mac));
    }

    #[test]
    fn lookup_miss_returns_none() {
        let table = ConnectionTable::new();
        let flow = FlowKey {
            src_addr: "10.0.0.1".parse().unwrap(),
            dst_addr: "10.0.1.10".parse().unwrap(),
            src_port: 12345,
            dst_port: 443,
        };

        assert_eq!(table.lookup(&flow, None), None);
    }

    #[test]
    fn dcid_key_equality() {
        let a = DcidKey::from_slice(&[0x01, 0x02, 0x03]);
        let b = DcidKey::from_slice(&[0x01, 0x02, 0x03]);
        let c = DcidKey::from_slice(&[0x01, 0x02, 0x04]);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
