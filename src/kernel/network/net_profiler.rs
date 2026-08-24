//! src/kernel/network/net_profiler.rs
//!
//! Network stack operation counters, gated behind `cfg(feature = "net_profiler")`.
//! When the feature is disabled, every method is a no-op and `NetProfiler` is
//! a zero-sized type so the field in `NetworkStack` costs zero bytes.
//!
//! Uses `AtomicU64` with `Relaxed` ordering to avoid lock contention on the
//! data path.

use core::fmt;
#[cfg(feature = "net_profiler")]
use core::sync::atomic::{AtomicU64, Ordering};

/// Point-in-time snapshot of all network stack profiler counters.
/// Always available even when profiling is compiled out (returns all zeros).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetProfilerSnapshot {
    pub arp_lookups: u64,
    pub arp_misses: u64,
    pub arp_resolves_sent: u64,
    pub arp_resolves_timeout: u64,
    pub arp_packets_rx: u64,
    pub tcp_segments_rx: u64,
    pub tcp_segments_tx: u64,
    pub tcp_bytes_rx: u64,
    pub tcp_bytes_tx: u64,
    pub tcp_retransmits: u64,
    pub tcp_retransmit_bytes: u64,
    pub tcp_connects: u64,
    pub tcp_connects_failed: u64,
    pub tcp_close_initiated: u64,
    pub tcp_duplicate_acks: u64,
    pub udp_datagrams_rx: u64,
    pub udp_datagrams_tx: u64,
    pub udp_dropped: u64,
    pub icmp_echo_replies: u64,
    pub icmp_unreachable: u64,
    pub ipv4_packets_rx: u64,
    pub ipv4_packets_tx: u64,
    pub ipv4_checksum_errors: u64,
    pub ipv6_packets_rx: u64,
    pub ipv6_packets_tx: u64,
    pub ipv6_fragment_reassembled: u64,
    pub fragment_errors: u64,
    pub nat_translations: u64,
    pub poll_iterations: u64,
    pub poll_rx_empty: u64,
    pub poll_errors: u64,
    /// Cumulative profiler tick events, usable as a relative latency proxy.
    pub elapsed_ticks: u64,
}

/// Network stack profiler.  When `feature = "net_profiler"` is disabled this is
/// a zero-sized type and every method compiles to a no-op.
#[derive(Default)]
pub struct NetProfiler {
    #[cfg(feature = "net_profiler")]
    inner: NetProfilerInner,
}

#[cfg(feature = "net_profiler")]
#[derive(Default)]
struct NetProfilerInner {
    arp_lookups: AtomicU64,
    arp_misses: AtomicU64,
    arp_resolves_sent: AtomicU64,
    arp_resolves_timeout: AtomicU64,
    arp_packets_rx: AtomicU64,
    tcp_segments_rx: AtomicU64,
    tcp_segments_tx: AtomicU64,
    tcp_bytes_rx: AtomicU64,
    tcp_bytes_tx: AtomicU64,
    tcp_retransmits: AtomicU64,
    tcp_retransmit_bytes: AtomicU64,
    tcp_connects: AtomicU64,
    tcp_connects_failed: AtomicU64,
    tcp_close_initiated: AtomicU64,
    tcp_duplicate_acks: AtomicU64,
    udp_datagrams_rx: AtomicU64,
    udp_datagrams_tx: AtomicU64,
    udp_dropped: AtomicU64,
    icmp_echo_replies: AtomicU64,
    icmp_unreachable: AtomicU64,
    ipv4_packets_rx: AtomicU64,
    ipv4_packets_tx: AtomicU64,
    ipv4_checksum_errors: AtomicU64,
    ipv6_packets_rx: AtomicU64,
    ipv6_packets_tx: AtomicU64,
    ipv6_fragment_reassembled: AtomicU64,
    fragment_errors: AtomicU64,
    nat_translations: AtomicU64,
    poll_iterations: AtomicU64,
    poll_rx_empty: AtomicU64,
    poll_errors: AtomicU64,
    elapsed_ticks: AtomicU64,
    /// Monotonically increasing tick sequence for relative timing.
    tick_seq: AtomicU64,
}

impl NetProfiler {
    /// Return a point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> NetProfilerSnapshot {
        #[cfg(feature = "net_profiler")]
        {
            NetProfilerSnapshot {
                arp_lookups: self.inner.arp_lookups.load(Ordering::Relaxed),
                arp_misses: self.inner.arp_misses.load(Ordering::Relaxed),
                arp_resolves_sent: self.inner.arp_resolves_sent.load(Ordering::Relaxed),
                arp_resolves_timeout: self.inner.arp_resolves_timeout.load(Ordering::Relaxed),
                arp_packets_rx: self.inner.arp_packets_rx.load(Ordering::Relaxed),
                tcp_segments_rx: self.inner.tcp_segments_rx.load(Ordering::Relaxed),
                tcp_segments_tx: self.inner.tcp_segments_tx.load(Ordering::Relaxed),
                tcp_bytes_rx: self.inner.tcp_bytes_rx.load(Ordering::Relaxed),
                tcp_bytes_tx: self.inner.tcp_bytes_tx.load(Ordering::Relaxed),
                tcp_retransmits: self.inner.tcp_retransmits.load(Ordering::Relaxed),
                tcp_retransmit_bytes: self.inner.tcp_retransmit_bytes.load(Ordering::Relaxed),
                tcp_connects: self.inner.tcp_connects.load(Ordering::Relaxed),
                tcp_connects_failed: self.inner.tcp_connects_failed.load(Ordering::Relaxed),
                tcp_close_initiated: self.inner.tcp_close_initiated.load(Ordering::Relaxed),
                tcp_duplicate_acks: self.inner.tcp_duplicate_acks.load(Ordering::Relaxed),
                udp_datagrams_rx: self.inner.udp_datagrams_rx.load(Ordering::Relaxed),
                udp_datagrams_tx: self.inner.udp_datagrams_tx.load(Ordering::Relaxed),
                udp_dropped: self.inner.udp_dropped.load(Ordering::Relaxed),
                icmp_echo_replies: self.inner.icmp_echo_replies.load(Ordering::Relaxed),
                icmp_unreachable: self.inner.icmp_unreachable.load(Ordering::Relaxed),
                ipv4_packets_rx: self.inner.ipv4_packets_rx.load(Ordering::Relaxed),
                ipv4_packets_tx: self.inner.ipv4_packets_tx.load(Ordering::Relaxed),
                ipv4_checksum_errors: self.inner.ipv4_checksum_errors.load(Ordering::Relaxed),
                ipv6_packets_rx: self.inner.ipv6_packets_rx.load(Ordering::Relaxed),
                ipv6_packets_tx: self.inner.ipv6_packets_tx.load(Ordering::Relaxed),
                ipv6_fragment_reassembled: self
                    .inner
                    .ipv6_fragment_reassembled
                    .load(Ordering::Relaxed),
                fragment_errors: self.inner.fragment_errors.load(Ordering::Relaxed),
                nat_translations: self.inner.nat_translations.load(Ordering::Relaxed),
                poll_iterations: self.inner.poll_iterations.load(Ordering::Relaxed),
                poll_rx_empty: self.inner.poll_rx_empty.load(Ordering::Relaxed),
                poll_errors: self.inner.poll_errors.load(Ordering::Relaxed),
                elapsed_ticks: self.inner.elapsed_ticks.load(Ordering::Relaxed),
            }
        }
        #[cfg(not(feature = "net_profiler"))]
        {
            NetProfilerSnapshot::default()
        }
    }

    // ─── individual counter incrementers ───

    #[inline]
    pub fn inc_arp_lookups(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.arp_lookups.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_arp_misses(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.arp_misses.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_arp_resolves_sent(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.arp_resolves_sent.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_arp_resolves_timeout(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner
            .arp_resolves_timeout
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_tcp_segments_rx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.tcp_segments_rx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_tcp_segments_tx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.tcp_segments_tx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_tcp_retransmits(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.tcp_retransmits.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_tcp_connects(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.tcp_connects.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_tcp_connects_failed(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner
            .tcp_connects_failed
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_tcp_close_initiated(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner
            .tcp_close_initiated
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_udp_datagrams_rx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.udp_datagrams_rx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_udp_datagrams_tx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.udp_datagrams_tx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_udp_dropped(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.udp_dropped.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_icmp_echo_replies(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.icmp_echo_replies.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_icmp_unreachable(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.icmp_unreachable.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_poll_iterations(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.poll_iterations.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    // ─── new counters (P144) ───

    #[inline]
    pub fn inc_arp_packets_rx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.arp_packets_rx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn add_tcp_bytes_rx(&self, n: u64) {
        #[cfg(feature = "net_profiler")]
        self.inner.tcp_bytes_rx.fetch_add(n, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        {
            let _ = self;
            let _ = n;
        }
    }

    #[inline]
    pub fn add_tcp_bytes_tx(&self, n: u64) {
        #[cfg(feature = "net_profiler")]
        self.inner.tcp_bytes_tx.fetch_add(n, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        {
            let _ = self;
            let _ = n;
        }
    }

    #[inline]
    pub fn add_tcp_retransmit_bytes(&self, n: u64) {
        #[cfg(feature = "net_profiler")]
        self.inner
            .tcp_retransmit_bytes
            .fetch_add(n, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        {
            let _ = self;
            let _ = n;
        }
    }

    #[inline]
    pub fn inc_tcp_duplicate_acks(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner
            .tcp_duplicate_acks
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_ipv4_packets_rx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.ipv4_packets_rx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_ipv4_packets_tx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.ipv4_packets_tx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_ipv4_checksum_errors(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner
            .ipv4_checksum_errors
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_ipv6_packets_rx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.ipv6_packets_rx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_ipv6_packets_tx(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.ipv6_packets_tx.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_ipv6_fragment_reassembled(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner
            .ipv6_fragment_reassembled
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_fragment_errors(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.fragment_errors.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_nat_translations(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.nat_translations.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_poll_rx_empty(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.poll_rx_empty.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_poll_errors(&self) {
        #[cfg(feature = "net_profiler")]
        self.inner.poll_errors.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "net_profiler"))]
        let _ = self;
    }

    // ─── tick-based relative timing ───

    /// Return a monotonically increasing tick value for relative latency
    /// measurement.  Used with [`record_elapsed`] to accumulate a rough
    /// cost-per-operation signal.
    #[inline]
    pub fn tick(&self) -> u64 {
        #[cfg(feature = "net_profiler")]
        {
            self.inner.tick_seq.fetch_add(1, Ordering::Relaxed)
        }
        #[cfg(not(feature = "net_profiler"))]
        {
            let _ = self;
            0
        }
    }

    /// Record the number of profiler ticks elapsed since `start_tick`
    /// (obtained from a prior [`tick`] call).
    #[inline]
    pub fn record_elapsed(&self, start_tick: u64) {
        #[cfg(feature = "net_profiler")]
        {
            let now = self.tick();
            self.inner
                .elapsed_ticks
                .fetch_add(now.wrapping_sub(start_tick), Ordering::Relaxed);
        }
        #[cfg(not(feature = "net_profiler"))]
        {
            let _ = self;
            let _ = start_tick;
        }
    }
}

impl fmt::Debug for NetProfiler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetProfiler")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}
