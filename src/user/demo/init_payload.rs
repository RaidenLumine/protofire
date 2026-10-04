//! src/user/demo/init_payload.rs
//!
//! The init program, as one macro that each architecture instantiates.
//!
//! The demo disk ships this program as `/system/init.elf`, and the kernel
//! spawns it at boot.  Its job is the distribution's half of the service
//! manager: list `/system/rc.d`, name each declaration file to the kernel
//! through `service_declare`, and ask for the services to be started.  The
//! kernel's half is the registry, the start order, the supervision and
//! `/service` — this program decides *which files declare the system*, not
//! *what they say*, which is the split the two syscalls exist for.  The kernel
//! reads the files itself, so what runs is the image's bytes and every service
//! is attributed to the file that declared it.
//!
//! It also performs the distribution's first install: the demo disk stages a
//! package in the download cache, and this program names it through
//! `install_package` so a boot exercises the whole path — read the package,
//! verify what it claims, write the app zone, make the version active — on the
//! machine rather than only in the host tests.
//!
//! Everything here is a syscall trap or a function in the same section: the
//! blob is copied out of the kernel image and run at another address, so an
//! absolute address or a call outside the section would name the kernel image's
//! copy of whatever it pointed at.  The invoking module supplies the section,
//! `init_address!`, the syscall runtime, and the entry point — see
//! [`crate::user::demo::init_payload_x86_64`].

/// Emit the init program into one payload section.
#[allow(unused_macros)]
macro_rules! define_init_payload {
    ($section:literal) => {
        /// Write one of the payload's own literals.
        macro_rules! init_message {
            ($literal:path) => {
                write_section_message(init_address!($literal), $literal.len())
            };
        }

        use core::mem::MaybeUninit;

        use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_KIND_OFFSET;
        use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET;
        use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET;
        use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_SIZE;
        use crate::user::shared::abi::fs::FILE_KIND_FILE;

        // The literals are `static` arrays rather than `const` slices because the
        // address of one of them is taken with `init_address!`, which needs an item
        // with an address — a `const` may be inlined and have none.  `b"…".len()` is
        // the length the array is declared with, so the two cannot disagree.

        /// Where a distribution's service declarations live.
        #[link_section = $section]
        static INIT_DECLARATION_DIR: [u8; b"/system/rc.d".len()] = *b"/system/rc.d";
        /// The package the distribution ships staged for its first install.
        ///
        /// The demo disk leaves a package in the download cache and this
        /// program installs it, so a boot shows the whole loop — read the
        /// package, verify what it claims, write the app zone, make the version
        /// active — instead of only the host tests showing it.
        #[link_section = $section]
        static INIT_STAGED_PACKAGE: [u8; b"/data/downloads/demo-installed@1.0.0".len()] =
            *b"/data/downloads/demo-installed@1.0.0";
        /// What the boot says when that install worked.
        #[link_section = $section]
        static INIT_INSTALLED: [u8; b"adastra init: installed demo-installed@1.0.0\n".len()] =
            *b"adastra init: installed demo-installed@1.0.0\n";
        #[link_section = $section]
        static INIT_INSTALL_FAILED: [u8; b"adastra init: cannot install ".len()] =
            *b"adastra init: cannot install ";
        /// Which files in that directory are declarations.
        #[link_section = $section]
        static INIT_DECLARATION_SUFFIX: [u8; b".toml".len()] = *b".toml";
        /// Buffer one `read_dir` entry and its name are unpacked into.
        const INIT_LISTING_CAPACITY: usize = 512;
        /// Buffer one full path (`/system/rc.d/<name>`) is built in.
        const INIT_PATH_CAPACITY: usize = 160;

        /// The line the boot gate asserts: it is how a boot says this program ran.
        #[link_section = $section]
        static INIT_BANNER: [u8; b"adastra init (ring 3): reading /system/rc.d\n".len()] =
            *b"adastra init (ring 3): reading /system/rc.d\n";
        #[link_section = $section]
        static INIT_NO_DIRECTORY: [u8;
            b"adastra init: no /system/rc.d; leaving the services to the kernel\n".len()] =
            *b"adastra init: no /system/rc.d; leaving the services to the kernel\n";
        #[link_section = $section]
        static INIT_DECLARED: [u8; b"adastra init: declared ".len()] = *b"adastra init: declared ";
        #[link_section = $section]
        static INIT_FILES_SUFFIX: [u8; b" declaration file(s)\n".len()] =
            *b" declaration file(s)\n";
        #[cfg(not(feature = "init_no_start"))]
        #[link_section = $section]
        static INIT_STARTED: [u8; b"adastra init: started ".len()] = *b"adastra init: started ";
        #[cfg(not(feature = "init_no_start"))]
        #[link_section = $section]
        static INIT_SERVICES_SUFFIX: [u8; b" service(s)\n".len()] = *b" service(s)\n";
        /// What a build with `init_no_start` says instead of asking: the line
        /// the fallback's boot asserts, and the honest report of what this
        /// program did — it read the declarations and left the start to the
        /// kernel.
        #[cfg(feature = "init_no_start")]
        #[link_section = $section]
        static INIT_NO_START: [u8; b"adastra init: leaving the start to the kernel\n".len()] =
            *b"adastra init: leaving the start to the kernel\n";
        #[link_section = $section]
        static INIT_DECLARE_FAILED: [u8; b"adastra init: cannot declare ".len()] =
            *b"adastra init: cannot declare ";
        #[link_section = $section]
        static INIT_NEWLINE: [u8; b"\n".len()] = *b"\n";

        /// Read the three header fields of a `read_dir` entry the syscall just wrote.
        #[inline(never)]
        #[link_section = $section]
        unsafe fn init_listing_fields(listing: usize) -> (usize, usize, usize) {
            // SAFETY: the caller has established that the syscall wrote at least
            // `DIRECTORY_ENTRY_RECORD_SIZE` bytes of header at `listing`.
            unsafe {
                (
                    core::ptr::read_unaligned(
                        listing.wrapping_add(DIRECTORY_ENTRY_RECORD_KIND_OFFSET) as *const usize,
                    ),
                    core::ptr::read_unaligned(
                        listing.wrapping_add(DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET)
                            as *const usize,
                    ),
                    core::ptr::read_unaligned(
                        listing.wrapping_add(DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET)
                            as *const usize,
                    ),
                )
            }
        }

        /// Whether a directory entry's name ends in `.toml`.
        ///
        /// Returns false for a name shorter than the suffix, which cannot be one.
        #[inline(never)]
        #[link_section = $section]
        unsafe fn init_name_is_declaration(name: usize, length: usize) -> bool {
            if length < INIT_DECLARATION_SUFFIX.len() {
                return false;
            }
            let start = name.wrapping_add(length.wrapping_sub(INIT_DECLARATION_SUFFIX.len()));
            let mut index = 0;
            while index < INIT_DECLARATION_SUFFIX.len() {
                // SAFETY: `start + index` is inside the name, which the caller bounds
                // by the bytes the syscall wrote, and `index` is below the suffix's
                // length, so the suffix read is inside the literal's own array.
                let (byte, expected) = unsafe {
                    (
                        core::ptr::read(start.wrapping_add(index) as *const u8),
                        core::ptr::read(INIT_DECLARATION_SUFFIX.as_ptr().wrapping_add(index)),
                    )
                };
                if byte != expected {
                    return false;
                }
                index = index.wrapping_add(1);
            }
            true
        }

        /// Build `/system/rc.d/<name>` into `buffer`, returning its length.
        ///
        /// Zero means the path does not fit, which is a refusal rather than a truncated
        /// path: a name cut short would name another file.
        #[inline(never)]
        #[link_section = $section]
        unsafe fn init_join_path(
            buffer: usize,
            capacity: usize,
            name: usize,
            name_len: usize,
        ) -> usize {
            let prefix = INIT_DECLARATION_DIR.len() + 1;
            if name_len > capacity.wrapping_sub(prefix) {
                return 0;
            }
            let mut index = 0;
            while index < INIT_DECLARATION_DIR.len() {
                let byte = unsafe {
                    // SAFETY: `index` is below the literal's own length, so the
                    // read is inside the array.
                    core::ptr::read(INIT_DECLARATION_DIR.as_ptr().wrapping_add(index))
                };
                unsafe {
                    // SAFETY: `buffer + index` is inside `capacity`, checked
                    // above.
                    core::ptr::write(buffer.wrapping_add(index) as *mut u8, byte)
                };
                index = index.wrapping_add(1);
            }
            unsafe {
                // SAFETY: the separator lands where the directory name ended,
                // still inside the capacity the check above bounded.
                core::ptr::write(buffer.wrapping_add(index) as *mut u8, b'/')
            };
            index = index.wrapping_add(1);
            let mut copied = 0;
            while copied < name_len {
                let byte = unsafe {
                    // SAFETY: `copied` is below the name's length, so the read
                    // is inside the name.
                    core::ptr::read(name.wrapping_add(copied) as *const u8)
                };
                unsafe {
                    // SAFETY: `buffer + index` is inside the capacity the check
                    // above bounded.
                    core::ptr::write(buffer.wrapping_add(index) as *mut u8, byte)
                };
                copied = copied.wrapping_add(1);
                index = index.wrapping_add(1);
            }
            index
        }

        /// Write a decimal number, without allocating.
        #[inline(never)]
        #[link_section = $section]
        fn init_write_number(mut value: usize) {
            let mut digits = [0u8; 20];
            let mut count = 0;
            loop {
                // SAFETY: `count` counts the digits written and the array holds 20 of
                // them, which is more than a 64-bit `usize` produces.
                unsafe {
                    core::ptr::write(
                        digits.as_mut_ptr().wrapping_add(count),
                        b'0'.wrapping_add((value % 10) as u8),
                    )
                };
                count = count.wrapping_add(1);
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            let mut index = 0;
            while index < count {
                // SAFETY: the reversed index stays below `count`, which the loop
                // bounded, and `count` is the number of digits written.
                let byte = unsafe {
                    core::ptr::read(
                        digits
                            .as_ptr()
                            .wrapping_add(count.wrapping_sub(1).wrapping_sub(index)),
                    )
                };
                write_section_message(&byte as *const u8 as usize, 1);
                index = index.wrapping_add(1);
            }
        }

        /// Report that one declaration file could not be used, naming it.
        #[inline(never)]
        #[link_section = $section]
        unsafe fn init_report_file(prefix: usize, prefix_len: usize, name: usize, name_len: usize) {
            write_section_message(prefix, prefix_len);
            write_section_message(name, name_len);
            init_message!(INIT_NEWLINE);
        }

        #[inline(never)]
        #[link_section = $section]
        /// The init program.
        ///
        /// Takes nothing: the loader has already left the user stack in the stack
        /// pointer, which is where its buffers live.
        extern "C" fn init_main() -> ! {
            init_message!(INIT_BANNER);

            let mut listing = MaybeUninit::<[u8; INIT_LISTING_CAPACITY]>::uninit();
            let listing_ptr = listing.as_mut_ptr() as usize;
            let mut path = MaybeUninit::<[u8; INIT_PATH_CAPACITY]>::uninit();
            let path_ptr = path.as_mut_ptr() as usize;

            let mut files = 0usize;
            let mut index = 0usize;
            loop {
                let written = read_dir(
                    init_address!(INIT_DECLARATION_DIR),
                    INIT_DECLARATION_DIR.len(),
                    index,
                    listing_ptr,
                    INIT_LISTING_CAPACITY,
                );
                if payload_runtime_status_is_error(written) {
                    // Running off the end of the directory is how the listing ends;
                    // failing on the first entry means the directory is not there.
                    if index == 0 {
                        init_message!(INIT_NO_DIRECTORY);
                    }
                    break;
                }
                if written < DIRECTORY_ENTRY_RECORD_SIZE {
                    break;
                }

                // SAFETY: the syscall just wrote `written` bytes of a directory entry
                // at `listing_ptr`, and `written` is at least one header.
                let (kind, name_offset, name_len) = unsafe { init_listing_fields(listing_ptr) };
                if kind == FILE_KIND_FILE && name_offset < written {
                    let name_end = if name_offset.wrapping_add(name_len) > written {
                        written
                    } else {
                        name_offset.wrapping_add(name_len)
                    };
                    let name = listing_ptr.wrapping_add(name_offset);
                    let name_len = name_end.wrapping_sub(name_offset);

                    // SAFETY: `name` and `name_len` bound one entry's name inside the
                    // bytes the syscall wrote.
                    if unsafe { init_name_is_declaration(name, name_len) } {
                        let path_len = unsafe {
                            // SAFETY: `path_ptr` names INIT_PATH_CAPACITY
                            // writable bytes in this frame, and `name` is
                            // bounded as above.
                            init_join_path(path_ptr, INIT_PATH_CAPACITY, name, name_len)
                        };
                        if path_len != 0 {
                            // The kernel reads the file itself: this names it, and
                            // what gets registered is the image's bytes.
                            let declared = service_declare(path_ptr, path_len);
                            if payload_runtime_status_is_error(declared) {
                                let prefix = init_address!(INIT_DECLARE_FAILED);
                                // SAFETY: `name`/`name_len` bound the entry's name,
                                // as above.
                                unsafe {
                                    init_report_file(
                                        prefix,
                                        INIT_DECLARE_FAILED.len(),
                                        name,
                                        name_len,
                                    );
                                }
                            } else {
                                files = files.wrapping_add(1);
                            }
                        }
                    }
                }

                index = index.wrapping_add(1);
            }

            init_message!(INIT_DECLARED);
            init_write_number(files);
            init_message!(INIT_FILES_SUFFIX);

            // The distribution's own first install: the package the disk
            // staged in the download cache becomes a version under `/apps`.
            // The kernel does the work and reads the package itself; this
            // program only names what to install, which is the same split the
            // declarations above use.
            let installed = install_package(
                init_address!(INIT_STAGED_PACKAGE),
                INIT_STAGED_PACKAGE.len(),
            );
            if payload_runtime_status_is_error(installed) {
                init_message!(INIT_INSTALL_FAILED);
                init_message!(INIT_STAGED_PACKAGE);
                init_message!(INIT_NEWLINE);
            } else {
                init_message!(INIT_INSTALLED);
            }

            // The distribution's other half: asking for the services to be
            // started.  A build with `init_no_start` leaves that out so a boot
            // exercises the *kernel's* fallback — the supervisor starting what
            // is still pending when the hand-off's deadline passes — which is
            // otherwise only ever the code nobody runs.
            #[cfg(not(feature = "init_no_start"))]
            {
                let started = service_start_all();
                init_message!(INIT_STARTED);
                if payload_runtime_status_is_error(started) {
                    init_write_number(0);
                } else {
                    init_write_number(started);
                }
                init_message!(INIT_SERVICES_SUFFIX);
            }
            #[cfg(feature = "init_no_start")]
            init_message!(INIT_NO_START);

            exit_with_code(0);
        }
    };
}

// Re-exported so the payload modules can reach it by path, as the shell's macro
// is.
#[allow(unused_imports)]
pub(crate) use define_init_payload;
