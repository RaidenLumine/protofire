//! src/kernel/topology.rs
//! NUMA topology types and global topology manager.

pub type NodeId = u8;
pub const NUMA_NODE_NONE: NodeId = 0xFF;
pub const MAX_NUMA_NODES: usize = 8;

#[derive(Debug, Clone)]
pub struct NumaNode {
    pub id: NodeId,
    pub cpu_ids: alloc::vec::Vec<u32>,
    /// Inclusive memory ranges `(start, end_exclusive)` assigned to this node.
    pub memory_ranges: alloc::vec::Vec<(u64, u64)>,
}

#[derive(Debug)]
pub struct Topology {
    pub nodes: alloc::vec::Vec<NumaNode>,
    pub cpu_to_node: alloc::vec::Vec<NodeId>, // indexed by logical CPU ID
    /// Inter-node distance matrix (row-major, N x N); empty when unknown.
    pub distance_matrix: alloc::vec::Vec<alloc::vec::Vec<u8>>,
}

impl Default for Topology {
    fn default() -> Self {
        Self::new()
    }
}

impl Topology {
    pub const fn new() -> Self {
        Self {
            nodes: alloc::vec::Vec::new(),
            cpu_to_node: alloc::vec::Vec::new(),
            distance_matrix: alloc::vec::Vec::new(),
        }
    }
    pub fn is_numa(&self) -> bool {
        self.nodes.len() > 1
    }
    pub fn node_for_cpu(&self, cpu_id: u32) -> NodeId {
        self.cpu_to_node
            .get(cpu_id as usize)
            .copied()
            .unwrap_or(NUMA_NODE_NONE)
    }
}

// Global topology singleton
use crate::util::sync_unsafe_cell::SyncUnsafeCell;
use core::sync::atomic::AtomicBool;
static TOPOLOGY_INITIALIZED: AtomicBool = AtomicBool::new(false);
static GLOBAL_TOPOLOGY: SyncUnsafeCell<core::mem::MaybeUninit<Topology>> =
    SyncUnsafeCell::new(core::mem::MaybeUninit::uninit());

pub fn init(topology: Topology) {
    unsafe {
        *GLOBAL_TOPOLOGY.get() = core::mem::MaybeUninit::new(topology);
    }
    TOPOLOGY_INITIALIZED.store(true, core::sync::atomic::Ordering::Release);
}

pub fn global() -> Option<&'static Topology> {
    if TOPOLOGY_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        Some(unsafe { (*GLOBAL_TOPOLOGY.get()).assume_init_ref() })
    } else {
        None
    }
}
