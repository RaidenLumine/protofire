//! src/arch/aarch64/its.rs
//!
        cmd_queue_virt: cmd_virt,
        cmd_write_idx: 0,
        next_lpi: LPI_BASE,
        initialized: false,
        has_its: true,
        current_device_id: 0,
        _device_table: device_table,
        _collection_table: collection_table,
    }));
    let state = unsafe { &*state_ptr };

    // Configure the ITS command queue.
    its_write_64(state, GITS_CBASER, 0);
    // GITS_CBASER: phys_addr (bits [51:12]), SZ field (size in 4KB units - 1)
    let sz_field: u64 = ((CMD_QUEUE_SIZE / 4096) - 1) as u64;
    let cbaser = (cmd_phys as u64 & 0x0000_FFFF_FFFF_F000)
        | (sz_field & 0xFF)
        | (1 << 0); // VALID
    its_write_64(state, GITS_CBASER, cbaser);
    its_write_64(state, GITS_CWRITER, 0);

    // Configure the device table (GITS_BASER0).
    // Minimal: 1 device entry, each 16 bytes → 16 bytes total (1 page @ 4 KB).
    // Type = 0 (Device table), EntrySize = 16, PageSize = 4 KB, VALID.
    let baser0: u64 = (dt_phys as u64 & 0x0000_FFFF_FFFF_F000)
        | (0 << 32)        // Type = Device table (0)
        | (16 << 48)       // EntrySize = 16 bytes
        | (0 << 7)         // PageSize = 0 = 4 KB
        | (1 << 0);        // VALID
    its_write_64(state, GITS_BASER0, baser0);