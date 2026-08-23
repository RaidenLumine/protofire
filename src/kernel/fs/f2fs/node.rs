//! src/kernel/fs/f2fs/node.rs
//! F2FS NAT (Node Address Table) operations: NID lookup, allocation, free,
//! and inode read/write helpers.

use crate::{Error, Result};

use super::constants::*;
use super::types::*;
use super::F2fsFs;

impl F2fsFs {
    /// Allocate a new NID by scanning forward from `next_nid`.
    ///
    /// Returns the newly allocated NID.  The corresponding NAT entry is
    /// marked with `block_addr = 0xFFFF_FFFF` (NEW_ADDR) to reserve the
    /// NID until its inode block is actually written.
    pub(crate) fn nat_alloc_nid(&self) -> Result<u32> {
        let mut next = self.next_nid.lock();
        let nat = self.nat_cache.lock();
        let total = nat.entries.len() as u32;

        // Scan from next_nid upward looking for a free NID.
        let start = *next;
        loop {
            if *next >= total {
                *next = F2FS_NID_ROOT + 1;
            }
            let nid = *next;
            *next += 1;

            if let Some(entry) = nat.entries.get(nid as usize) {
                if entry.block_addr == F2FS_NULL_ADDR {
                    drop(nat);
                    // Reserve this NID.
                    self.nat_update(nid, F2FS_NEW_ADDR)?;
                    return Ok(nid);
                }
            }

            // Wrapped around — no free NIDs.
            if *next == start {
                break;
            }
        }

        Err(Error::DeviceError)
    }

    /// Free a NID — set its block address to 0.
    pub(crate) fn nat_free_nid(&self, nid: u32) -> Result<()> {
        self.nat_update(nid, F2FS_NULL_ADDR)?;
        // Update next_nid hint so this NID can be reused soon.
        let mut next = self.next_nid.lock();
        if nid < *next {
            *next = nid;
        }
        Ok(())
    }

    /// Update the NAT entry for `nid` to point to `block_addr`.
    ///
    /// The update goes to the in-memory cache immediately and is also
    /// recorded in `dirty_nat` for later checkpoint flush.
    pub(crate) fn nat_update(&self, nid: u32, block_addr: u32) -> Result<()> {
        // Update in-memory cache.
        {
            let mut nat = self.nat_cache.lock();
            if (nid as usize) < nat.entries.len() {
                nat.entries[nid as usize].block_addr = block_addr;
            } else {
                return Err(Error::NotFound);
            }
        }

        // Record as dirty for checkpoint flush.
        {
            let mut dirty = self.dirty_nat.lock();
            dirty.insert(
                nid,
                F2fsNatEntry {
                    block_addr,
                    ino: 0, // v1: parent tracking not used
                },
            );
        }

        Ok(())
    }
}
