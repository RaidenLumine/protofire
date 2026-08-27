//! tests/parsers/fuzz.rs
//!
//! In-tree deterministic parser fuzzing.
//!
//! Each harness feeds fixed-seed LCG random bytes (plus structure-aware
//! mutations) into a kernel parser and asserts the only possible outcomes
//! are clean `Err` / `None` returns or successful parses — never a panic or
//! out-of-bounds access.  The PRNG is fixed-seed, so any panic that fires
//! here reproduces exactly and is a genuine kernel bug to fix, not a flake.
//!
//! Coverage is targeted at the four entry-point families from the ROADMAP
//! tier-3 work: the ELF loader chain, the LUKS2 metadata scanners, the
//! network packet parsers, and the filesystem image-open paths.

use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::network::internet::ip::IpAddress;
use protofire::kernel::network::tls::record::CipherSuite;
use protofire::kernel::network::tls::record::TrafficKeys;
use protofire::user::elf::parse_elf64;
use protofire::user::program::plan_user_image_load;

// ── Simple PRNG ─────────────────────────────────────────────────────────────
// Same LCG used by tests/syscall/fuzz.rs, kept local so this binary is
// self-contained.

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6_364_136_223_846_793_005);
        self.state = self.state.wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 56) as u8
    }

    fn len(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next() as usize) % (max + 1)
    }
}

/// Random byte buffer with length drawn from `0..=max_len`.
fn random_bytes(rng: &mut Lcg, max_len: usize) -> Vec<u8> {
    let n = rng.len(max_len);
    (0..n).map(|_| rng.byte()).collect()
}

/// Flip a few random bytes in a reference buffer (structure-aware mutation).
fn mutate_in_place(buf: &mut [u8], rng: &mut Lcg) {
    if buf.is_empty() {
        return;
    }
    let flips = 1 + rng.len(8);
    for _ in 0..flips {
        let idx = (rng.next() as usize) % buf.len();
        buf[idx] ^= 1 << rng.len(7);
    }
}

/// Build a DHCPOFFER / DHCPACK seed message: a valid BOOTP header plus magic
/// cookie followed by a random-length options region.  Mutating only the
/// options region keeps the message past the header gate so the option
/// walker is exercised directly.
fn build_dhcp_seed(rng: &mut Lcg) -> Vec<u8> {
    // BOOTP_HEADER_SIZE (236) + 4 magic-cookie bytes + options.
    const HEADER: usize = 236;
    let options_len = rng.len(64);
    let mut msg = vec![0u8; HEADER + 4 + options_len];
    msg[0] = 2; // BOOTREPLY
    msg[16..20].copy_from_slice(&[10, 0, 0, 1]); // yiaddr
    msg[HEADER..HEADER + 4].copy_from_slice(&0x6382_5363u32.to_be_bytes());
    msg
}

// ── ELF loader ──────────────────────────────────────────────────────────────

/// Build a minimal valid ELF64 (ET_DYN) image with one executable PT_LOAD
/// segment.  Used as the seed for structure-aware mutation fuzzing so that
/// `parse_elf64` and `plan_user_image_load` are reached with meaningful
/// layouts rather than being rejected on the magic check.
fn build_seed_elf() -> Vec<u8> {
    let mut img = vec![0u8; 8192];
    // e_ident
    img[0] = 0x7f;
    img[1] = b'E';
    img[2] = b'L';
    img[3] = b'F';
    img[4] = 2; // ELFCLASS64
    img[5] = 1; // ELFDATA2LSB
    img[6] = 1; // EV_CURRENT
                // e_type = ET_DYN (3)
    img[16] = 3;
    // e_machine = EM_X86_64 (0x3e)
    img[18] = 0x3e;
    // e_version = 1
    img[20] = 1;
    // e_entry = 0x400000 (inside the PT_LOAD segment below)
    img[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
    // e_phoff = 64
    img[32..40].copy_from_slice(&64u64.to_le_bytes());
    // e_ehsize = 64
    img[52..54].copy_from_slice(&64u16.to_le_bytes());
    // e_phentsize = 56
    img[54..56].copy_from_slice(&56u16.to_le_bytes());
    // e_phnum = 1
    img[56..58].copy_from_slice(&1u16.to_le_bytes());
    // Program header (PT_LOAD, R|X), overlapping the file at offset 0x1000.
    let mut ph = vec![0u8; 56];
    // p_type = PT_LOAD (1)
    ph[0..4].copy_from_slice(&1u32.to_le_bytes());
    // p_flags = PF_R | PF_X (5)
    ph[4..8].copy_from_slice(&5u32.to_le_bytes());
    // p_offset = 0x1000
    ph[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    // p_vaddr = 0x400000
    ph[16..24].copy_from_slice(&0x400000u64.to_le_bytes());
    // p_paddr = 0 (already zeroed)
    // p_filesz = 0x200
    ph[32..40].copy_from_slice(&0x200u64.to_le_bytes());
    // p_memsz = 0x400
    ph[40..48].copy_from_slice(&0x400u64.to_le_bytes());
    // p_align = 0x1000
    ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
    img[64..120].copy_from_slice(&ph);
    img
}

fn exercise_elf_chain(bytes: &[u8]) {
    if let Ok(elf) = parse_elf64(bytes) {
        let _ = elf.load_segments();
        let _ = elf.load_segment_count();
        let _ = elf.entry_in_load_segment();
        let _ = plan_user_image_load(&elf);
    }
}

#[test]
fn fuzz_elf_loader_random_bytes() {
    let mut rng = Lcg::new(0xF0F0_1010);
    for _ in 0..3000 {
        let bytes = random_bytes(&mut rng, 4096);
        exercise_elf_chain(&bytes);
    }
}

#[test]
fn fuzz_elf_loader_structure_aware_mutations() {
    let mut rng = Lcg::new(0xF0F0_1011);
    let seed = build_seed_elf();
    for _ in 0..3000 {
        let mut bytes = seed.clone();
        mutate_in_place(&mut bytes, &mut rng);
        exercise_elf_chain(&bytes);
    }
}

// ── LUKS2 metadata scanners ────────────────────────────────────────────────

#[test]
fn fuzz_luks2_scanners() {
    use protofire::kernel::fs::luks2::base64_decode;
    use protofire::kernel::fs::luks2::json_find_object;
    use protofire::kernel::fs::luks2::json_find_string;
    use protofire::kernel::fs::luks2::parse_decimal;

    let keys: &[&str] = &[
        "config",
        "keyslots",
        "0",
        "kdf",
        "argon2id",
        "salt",
        "size",
        "offset",
        "iterations",
        "priority",
        "cipher",
        "hashing",
        "stripes",
        "key",
        "digest",
        "uuid",
        "enforce",
        "segments",
    ];

    let mut rng = Lcg::new(0xF0F0_2020);
    for _ in 0..5000 {
        let bytes = random_bytes(&mut rng, 2048);
        let _ = base64_decode(&bytes);
        let _ = parse_decimal(&bytes);
        for key in keys {
            let _ = json_find_string(&bytes, key);
            let _ = json_find_object(&bytes, key);
        }
    }
}

/// Feed random block images through the full `luks2_open` path (binary
/// header + JSON metadata + keyslot base64 decode).
#[test]
fn fuzz_luks2_open() {
    use protofire::kernel::fs::luks2::luks2_open;

    let mut rng = Lcg::new(0xF0F0_2021);
    for _ in 0..400 {
        let bytes = random_bytes(&mut rng, 4096);
        let dev = MemoryBlockDevice::new("fuzz-luks2", bytes, true);
        let _ = luks2_open(dev, b"passphrase");
    }
}

// ── Network packet parsers ─────────────────────────────────────────────────

/// Exercise a plain `&[u8] -> ...` parser over a batch of random buffers.
fn fuzz_byte_parser<F>(seed: u64, iterations: usize, max_len: usize, mut parser: F)
where
    F: FnMut(&[u8]),
{
    let mut rng = Lcg::new(seed);
    for _ in 0..iterations {
        let bytes = random_bytes(&mut rng, max_len);
        parser(&bytes);
    }
}

#[test]
fn fuzz_network_parsers() {
    use protofire::kernel::network::dhcp::parse_dhcp_reply;
    use protofire::kernel::network::dns::parse_a_record;
    use protofire::kernel::network::dns::parse_aaaa_record;
    use protofire::kernel::network::dns::parse_ptr_record;
    use protofire::kernel::network::internet::icmpv6::parse_icmpv6_error_info;
    use protofire::kernel::network::internet::icmpv6::parse_icmpv6_header;
    use protofire::kernel::network::internet::igmp::parse_igmp_message;
    use protofire::kernel::network::internet::ipv4::parse_ipv4_header;
    use protofire::kernel::network::internet::ipv4::parse_packet as parse_ipv4_packet;
    use protofire::kernel::network::internet::ipv6::parse_fragment_header;
    use protofire::kernel::network::internet::ipv6::parse_packet as parse_ipv6_packet;
    use protofire::kernel::network::ppp::parse_lcp_options;
    use protofire::kernel::network::ppp::parse_lcp_packet;
    use protofire::kernel::network::pppoe::parse_tags;
    use protofire::kernel::network::sctp::chunk::parse_init_params;
    use protofire::kernel::network::sctp::parse_common_header;
    use protofire::kernel::network::sctp::parse_sctp_packet;
    use protofire::kernel::network::tcp::parse_tcp_header;
    use protofire::kernel::network::tls::certificate::parse_x509_certificate;
    use protofire::kernel::network::tls::handshake::parse_plaintext_tls_record;
    use protofire::kernel::network::udp::parse_datagram;

    // Result-returning parsers (some with checksums that reject most random
    // input — the property under test is "never panic", not "parse").
    let simple = [
        ("ipv4_packet", 1500usize, 1512usize),
        ("ipv6_packet", 1500, 1512),
        ("tcp_header", 1500, 64),
        ("dns_a", 1500, 512),
        ("dns_aaaa", 1500, 512),
        ("dns_ptr", 1500, 512),
        ("sctp_common", 1500, 512),
        ("sctp_packet", 1500, 4096),
        ("sctp_init", 1500, 256),
        ("lcp_packet", 1500, 512),
        ("lcp_options", 1500, 256),
        ("icmpv6_header", 1500, 64),
        ("igmp", 1500, 64),
        ("udp", 1500, 512),
    ];
    for (name, iters, max) in simple {
        match name {
            "ipv4_packet" => fuzz_byte_parser(0xF0F0_3030, iters, max, |b| {
                let _ = parse_ipv4_packet(b);
            }),
            "ipv6_packet" => fuzz_byte_parser(0xF0F0_3031, iters, max, |b| {
                let _ = parse_ipv6_packet(b);
            }),
            "tcp_header" => fuzz_byte_parser(0xF0F0_3032, iters, max, |b| {
                let _ = parse_tcp_header(b);
            }),
            "dns_a" => fuzz_byte_parser(0xF0F0_3033, iters, max, |b| {
                let _ = parse_a_record(b);
            }),
            "dns_aaaa" => fuzz_byte_parser(0xF0F0_3034, iters, max, |b| {
                let _ = parse_aaaa_record(b);
            }),
            "dns_ptr" => fuzz_byte_parser(0xF0F0_3035, iters, max, |b| {
                let _ = parse_ptr_record(b);
            }),
            "sctp_common" => fuzz_byte_parser(0xF0F0_3036, iters, max, |b| {
                let _ = parse_common_header(b);
            }),
            "sctp_packet" => fuzz_byte_parser(0xF0F0_3037, iters, max, |b| {
                let _ = parse_sctp_packet(b);
            }),
            "sctp_init" => fuzz_byte_parser(0xF0F0_3038, iters, max, |b| {
                let _ = parse_init_params(b);
            }),
            "lcp_packet" => fuzz_byte_parser(0xF0F0_3039, iters, max, |b| {
                let _ = parse_lcp_packet(b);
            }),
            "lcp_options" => fuzz_byte_parser(0xF0F0_303A, iters, max, |b| {
                let _ = parse_lcp_options(b);
            }),
            "icmpv6_header" => fuzz_byte_parser(0xF0F0_303B, iters, max, |b| {
                let _ = parse_icmpv6_header(b);
            }),
            "igmp" => fuzz_byte_parser(0xF0F0_303C, iters, max, |b| {
                let _ = parse_igmp_message(b);
            }),
            "udp" => fuzz_byte_parser(0xF0F0_303D, iters, max, |b| {
                let _ = parse_datagram(b);
            }),
            _ => unreachable!(),
        }
    }

    // Slice / Vec-returning parsers (no Result wrapper).
    fuzz_byte_parser(0xF0F0_3040, 1500, 128, |b| {
        let _ = parse_ipv4_header(b);
    });
    fuzz_byte_parser(0xF0F0_3041, 1500, 128, |b| {
        let _ = parse_fragment_header(b);
    });
    fuzz_byte_parser(0xF0F0_3043, 1500, 512, |b| {
        let _ = parse_tags(b);
    });
    fuzz_byte_parser(0xF0F0_3044, 1500, 512, |b| {
        let _ = parse_icmpv6_error_info(b);
    });
    fuzz_byte_parser(0xF0F0_3045, 1500, 512, |b| {
        let _ = parse_x509_certificate(b);
    });

    // TLS plaintext record (no traffic keys needed).
    fuzz_byte_parser(0xF0F0_3046, 1500, 4096, |b| {
        let _ = parse_plaintext_tls_record(b);
    });

    // TLS encrypted record (needs a TrafficKeys value).
    fuzz_byte_parser(0xF0F0_3047, 1500, 4096, |b| {
        let mut keys = TrafficKeys::new(
            vec![0xAA; 16],
            [0u8; 12],
            vec![0xBB; 16],
            [0u8; 12],
            CipherSuite::Aes128GcmSha256,
        );
        let _ = protofire::kernel::network::tls::record::parse_tls_record(&mut keys, b);
    });

    // DCCP segment (needs source/destination addresses).
    let src = IpAddress::V4([10, 0, 0, 1]);
    let dst = IpAddress::V4([10, 0, 0, 2]);
    fuzz_byte_parser(0xF0F0_3048, 1500, 512, |b| {
        let _ = protofire::kernel::network::dccp::parse_segment(b, src, dst);
    });

    // DCCP options.
    fuzz_byte_parser(0xF0F0_3049, 1500, 256, |b| {
        let _ = protofire::kernel::network::dccp::options::parse_options(b);
    });

    // DHCP reply (magic-cookie checked, so mostly `None` on random input).
    fuzz_byte_parser(0xF0F0_304A, 4000, 512, |b| {
        let _ = parse_dhcp_reply(b);
    });
}

/// Structure-aware DHCP fuzz: keep a valid BOOTP header + magic cookie and
/// mutate only the options region.  This is what actually reaches the option
/// walker (`for_each_option`), whose truncated-length-octet indexing was the
/// out-of-bounds panic fixed alongside this harness.
#[test]
fn fuzz_dhcp_options_structure_aware() {
    use protofire::kernel::network::dhcp::parse_dhcp_reply;

    let mut rng = Lcg::new(0xF0F0_304B);
    for _ in 0..6000 {
        let mut msg = build_dhcp_seed(&mut rng);
        // Mutate the options region (everything after the magic cookie).
        let options_start = 236 + 4;
        if msg.len() > options_start {
            mutate_in_place(&mut msg[options_start..], &mut rng);
        }
        let _ = parse_dhcp_reply(&msg);
    }
}

// ── Filesystem image parsers ───────────────────────────────────────────────

#[test]
fn fuzz_fs_volume_opens() {
    use protofire::kernel::fs::btrfs::BtrfsVolume;
    use protofire::kernel::fs::erofs::EroFsVolume;
    use protofire::kernel::fs::iso9660::Iso9660Volume;
    use protofire::kernel::fs::ntfs::NtfsFs;
    use protofire::kernel::fs::squashfs::SquashfsVolume;

    let mut rng = Lcg::new(0xF0F0_4050);
    for _ in 0..400 {
        // Up to 256 KiB so btrfs's superblock at offset 0x10000 is readable.
        let bytes = random_bytes(&mut rng, 256 * 1024);
        let dev = MemoryBlockDevice::new("fuzz-fs", bytes, true);

        let _ = BtrfsVolume::open(vec![dev.clone()]);
        let _ = EroFsVolume::open(dev.clone());
        let _ = NtfsFs::new(dev.clone());
        let _ = SquashfsVolume::open(dev.clone());
        let _ = Iso9660Volume::open(dev.clone());
    }
}
