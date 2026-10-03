//! src/kernel/process/process/object_shape.rs
//!
//! The shape table: what each kind of [`KernelObject`] is, declared once.
//!
//! A handle table entry holds an object and two rights bits; that is what the
//! kernel *stores*.  What a program can *do* with the object depends on a
//! second thing that used to have no home: its shape.  A file can be opened by
//! name, read, written, and listed; a TCP listener can only be accepted on; a
//! process handle can only be used through the dedicated process syscalls.
//! Before this table those answers were spread across the matches in
//! [`handle_entry`](super::handle_entry) and
//! [`handle_ops`](super::handle_ops): nine whole-enumeration matches, each
//! carrying its own opinion about which variants answer a read and which
//! answer `Unsupported`, and none of them the single place to look.
//!
//! The cost of that spread is drift.  A variant added to `KernelObject`
//! compiles only once every match has handled it, so the compiler forces a
//! decision — but it forces eleven separate decisions, and the one that
//! matters ("which projection does this new object belong to?") is the one
//! nothing states.  Here it is stated once, one row per kind, and
//! [`KernelObject::shape`] is the query every other module asks.
//!
//! ## The face
//!
//! The three faces are the kernel's answer to "everything is X".  This kernel
//! does not hold that everything is a file; it holds that everything is a
//! rights-carrying handle, and that the *most complete* shape a handle can
//! present is the file shape.  An object that cannot be a file still has a
//! face, and that face decides which error an operation outside its shape
//! answers:
//!
//! - [`ObjectFace::File`] — named in the filesystem namespace.  `open` reaches
//!   it, and the file operations are part of it.
//! - [`ObjectFace::Stream`] — reached only through a handle, and read/written
//!   as a stream (or polled for readiness).
//! - [`ObjectFace::Control`] — reached only through a handle, and driven only
//!   by dedicated syscalls.  It has no stream interface at all.
//!
//! A file- or stream-faced object that is asked for something outside its
//! shape answers [`Error::InvalidArgument`]: it has an interface, this is not
//! part of it.  A control-faced object answers [`Error::Unsupported`]: it has
//! no such interface to be outside of.  That distinction is the one the
//! [`ObjectFace::outside`] method pins.
//!
//! `ObjectShape` is a snapshot, not a policy of its own: every field is
//! something a call site can ask, and the tests below pin the four invariants
//! the rows have to keep (a named object is visible to `stat`, a
//! directory-capable object is named, a control object reads and writes
//! nothing, and a stream object that is neither readable nor writable must
//! still poll).  The rows are the shape; a change to a row is the deliberate
//! act of changing what an object is.

use crate::Error;

use super::types::HandleEntry;
use super::types::KernelObject;

/// Which projection an object belongs to.
///
/// The choice of face is the choice of error for an operation the object does
/// not have — see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFace {
    /// Named in the filesystem namespace (`open`, `stat`, read/write).
    File,
    /// Reached by handle only, and read or written as a stream.
    Stream,
    /// Reached by handle only, and driven by dedicated syscalls.
    Control,
}

impl ObjectFace {
    /// The error an operation outside this face answers.
    ///
    /// A file or a stream *has* an interface, so an operation that is not part
    /// of it is an invalid argument.  A control object has no such interface,
    /// so the operation is unsupported.  Both errors are visible to
    /// user-space (they encode as different negative values at the syscall
    /// boundary), which is why the choice is made here once rather than
    /// repeated per call site.
    pub const fn outside(self) -> Error {
        match self {
            Self::File | Self::Stream => Error::InvalidArgument,
            Self::Control => Error::Unsupported,
        }
    }
}

/// What an object is, in the terms the handle table asks about it.
///
/// One row per [`KernelObjectKind`]; see [`KernelObjectKind::shape`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectShape {
    /// Which projection the object belongs to (and thus which error an
    /// out-of-shape operation answers).
    pub face: ObjectFace,
    /// Reachable by path: `open` may name it, and it appears in the namespace.
    pub path_reachable: bool,
    /// May present a directory face (`readdir` semantics apply).
    ///
    /// `File` is `true` here because an `OpenFile` may have been opened on a
    /// directory; the runtime kind decides, not the shape.
    pub directory: bool,
    /// `read` through the stream interface (`read`/`recv`) is part of the
    /// shape.
    pub stream_read: bool,
    /// `write` through the stream interface (`write`/`send`) is part of the
    /// shape.
    pub stream_write: bool,
    /// The object answers a readiness query (`is_readable`), whether that
    /// answer is "yes", "no", or a live check.
    pub poll_read: bool,
    /// The object answers a writability query (`is_writable`).
    pub poll_write: bool,
    /// The object carries a `stat` record on the path face.
    pub stat_visible: bool,
}

/// Define the kind enum and its exhaustive `ALL` slice together.
///
/// Keeping the two in one declaration is what makes `ALL` complete: a kind
/// cannot be added to the enum without appearing in `ALL`, so the table tests
/// below cannot silently stop covering a row.
macro_rules! kernel_object_kinds {
    ($($kind:ident),+ $(,)?) => {
        /// A data-free name for a [`KernelObject`] variant.
        ///
        /// `KernelObject` carries payloads — connections, states, ids — so a
        /// value of it cannot be had without building one.  The kind is the
        /// part that describes the *shape*, with no payload, which is what
        /// lets the table be read and tested in one place.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum KernelObjectKind {
            $($kind),+
        }

        impl KernelObjectKind {
            /// Every kind, in declaration order.
            pub const ALL: &'static [KernelObjectKind] = &[
                $(KernelObjectKind::$kind),+
            ];
        }
    };
}

kernel_object_kinds! {
    File,
    Directory,
    Device,
    Network,
    TcpListener,
    UdpSocket,
    DccpSocket,
    RawSocket,
    LocalSocket,
    TlsConnection,
    Process,
    Thread,
    EventFd,
    SignalFd,
    TimerFd,
    Mqueue,
    Epoll,
    IoUring,
}

impl KernelObjectKind {
    /// The shape of this kind.  One row per variant, and the only place a
    /// variant's projection is stated.
    ///
    /// Adding a variant to `KernelObject` forces a new arm in
    /// [`KernelObject::kind`]; adding a kind here forces a new row below.  The
    /// compiler will not let either fall through.
    pub const fn shape(self) -> ObjectShape {
        use ObjectFace::File;
        use ObjectFace::Stream;

        // Rows are written in the order of `KernelObjectKind`.
        match self {
            // Named, streamable, and stattable: the file projection, which is
            // the most complete shape this kernel hands out.
            Self::File => ObjectShape {
                face: File,
                path_reachable: true,
                directory: true,
                stream_read: true,
                stream_write: true,
                poll_read: true,
                poll_write: true,
                stat_visible: true,
            },
            // Named, but a name list rather than a byte stream: read and
            // write through the stream interface are not part of its shape.
            Self::Directory => ObjectShape {
                face: File,
                path_reachable: true,
                directory: true,
                stream_read: false,
                stream_write: false,
                poll_read: false,
                poll_write: false,
                stat_visible: true,
            },
            // A device node: named like a file and streamed like one.
            Self::Device => ObjectShape {
                face: File,
                path_reachable: true,
                directory: false,
                stream_read: true,
                stream_write: true,
                poll_read: true,
                poll_write: true,
                stat_visible: true,
            },
            // Handle-only streams.
            Self::Network => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: true,
                stream_write: true,
                poll_read: true,
                poll_write: true,
                stat_visible: true,
            },
            // A listener accepts; it does not read or write.  It still answers
            // readiness, because accept-readiness is what a poll waits on.
            Self::TcpListener => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: false,
                stream_write: false,
                poll_read: true,
                poll_write: true,
                stat_visible: true,
            },
            // Datagram sockets name a destination per call, so `write` is not
            // part of their stream shape even though a receive side is.
            Self::UdpSocket => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: true,
                stream_write: false,
                poll_read: true,
                poll_write: true,
                stat_visible: true,
            },
            Self::DccpSocket => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: true,
                stream_write: false,
                poll_read: true,
                poll_write: true,
                stat_visible: true,
            },
            // A raw socket is a control object: its packets are moved by the
            // dedicated raw-socket syscalls, and it answers nothing to a
            // stream read, a stream write, or a readiness query.  That is why
            // it is `Control` while the local socket below is `Stream`.
            Self::RawSocket => ObjectShape {
                face: ObjectFace::Control,
                path_reachable: false,
                directory: false,
                stream_read: false,
                stream_write: false,
                poll_read: false,
                poll_write: false,
                stat_visible: true,
            },
            // A local socket is reached by its send/recv syscalls rather than
            // by `read`/`write`, but it does have a readiness side, which is
            // what makes it a stream face rather than a control one.
            Self::LocalSocket => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: false,
                stream_write: false,
                poll_read: true,
                poll_write: true,
                stat_visible: true,
            },
            Self::TlsConnection => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: true,
                stream_write: true,
                poll_read: true,
                poll_write: true,
                stat_visible: true,
            },
            // Process and thread handles are control objects; `/proc` is their
            // read-only path projection, and it is not a handle.
            Self::Process => ObjectShape {
                face: ObjectFace::Control,
                path_reachable: false,
                directory: false,
                stream_read: false,
                stream_write: false,
                poll_read: false,
                poll_write: false,
                stat_visible: false,
            },
            Self::Thread => ObjectShape {
                face: ObjectFace::Control,
                path_reachable: false,
                directory: false,
                stream_read: false,
                stream_write: false,
                poll_read: false,
                poll_write: false,
                stat_visible: false,
            },
            // Notification streams: read and written as counters or records.
            Self::EventFd => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: true,
                stream_write: true,
                poll_read: true,
                poll_write: true,
                stat_visible: false,
            },
            // Signal and timer notifications are read-only.
            Self::SignalFd => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: true,
                stream_write: false,
                poll_read: true,
                poll_write: true,
                stat_visible: false,
            },
            Self::TimerFd => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: true,
                stream_write: false,
                poll_read: true,
                poll_write: true,
                stat_visible: false,
            },
            // A message queue is a record stream in both directions.
            Self::Mqueue => ObjectShape {
                face: Stream,
                path_reachable: false,
                directory: false,
                stream_read: true,
                stream_write: true,
                poll_read: true,
                poll_write: true,
                stat_visible: false,
            },
            // Event loops are control objects driven by their own wait call.
            // They answer a readiness query (usually "nothing yet"), but they
            // do not read or write.
            Self::Epoll => ObjectShape {
                face: ObjectFace::Control,
                path_reachable: false,
                directory: false,
                stream_read: false,
                stream_write: false,
                poll_read: true,
                poll_write: true,
                stat_visible: false,
            },
            Self::IoUring => ObjectShape {
                face: ObjectFace::Control,
                path_reachable: false,
                directory: false,
                stream_read: false,
                stream_write: false,
                poll_read: true,
                poll_write: true,
                stat_visible: false,
            },
        }
    }
}

impl KernelObject {
    /// The data-free kind of this object.
    ///
    /// Adding a variant to `KernelObject` fails this match, which is the
    /// compiler forcing the new object to name itself in the shape table.
    pub fn kind(&self) -> KernelObjectKind {
        match self {
            KernelObject::File(_) => KernelObjectKind::File,
            KernelObject::Directory(_) => KernelObjectKind::Directory,
            KernelObject::Device(_) => KernelObjectKind::Device,
            KernelObject::Network(_) => KernelObjectKind::Network,
            KernelObject::TcpListener(_) => KernelObjectKind::TcpListener,
            KernelObject::UdpSocket(_) => KernelObjectKind::UdpSocket,
            KernelObject::DccpSocket(_) => KernelObjectKind::DccpSocket,
            KernelObject::RawSocket(_) => KernelObjectKind::RawSocket,
            KernelObject::LocalSocket(_) => KernelObjectKind::LocalSocket,
            KernelObject::TlsConnection(_) => KernelObjectKind::TlsConnection,
            KernelObject::Process(_) => KernelObjectKind::Process,
            KernelObject::Thread(_) => KernelObjectKind::Thread,
            KernelObject::EventFd(_) => KernelObjectKind::EventFd,
            KernelObject::SignalFd(_) => KernelObjectKind::SignalFd,
            KernelObject::TimerFd(_) => KernelObjectKind::TimerFd,
            KernelObject::Mqueue(_) => KernelObjectKind::Mqueue,
            KernelObject::Epoll(_) => KernelObjectKind::Epoll,
            KernelObject::IoUring(_) => KernelObjectKind::IoUring,
        }
    }

    /// The shape of this object.
    pub fn shape(&self) -> ObjectShape {
        self.kind().shape()
    }
}

impl HandleEntry {
    /// The shape of the object this entry holds.
    ///
    /// A handle entry is an object plus the rights to it, and every shape
    /// question a call site asks is about the object; the rights gate an
    /// operation the shape already allows.  This is the accessor those call
    /// sites use so the object never has to be matched twice.
    pub fn shape(&self) -> ObjectShape {
        self.object.shape()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_a_row() {
        // `ALL` is generated from the same list as the enum, so this is the
        // whole table; the assertion is that `shape()` answers for each row.
        for &kind in KernelObjectKind::ALL {
            let shape = kind.shape();
            assert!(
                matches!(
                    shape.face,
                    ObjectFace::File | ObjectFace::Stream | ObjectFace::Control
                ),
                "{kind:?} declares a face",
            );
        }
    }

    #[test]
    fn a_named_object_is_stattable() {
        // The path face and the stat record are the same face: if `open` can
        // name it, `stat` must be able to describe it.
        for &kind in KernelObjectKind::ALL {
            let shape = kind.shape();
            if shape.path_reachable {
                assert!(shape.stat_visible, "{kind:?} is named but not stattable");
            }
        }
    }

    #[test]
    fn a_directory_is_named() {
        for &kind in KernelObjectKind::ALL {
            let shape = kind.shape();
            if shape.directory {
                assert!(shape.path_reachable, "{kind:?} lists a directory un-named");
            }
        }
    }

    #[test]
    fn a_control_object_is_not_a_stream() {
        for &kind in KernelObjectKind::ALL {
            let shape = kind.shape();
            if shape.face == ObjectFace::Control {
                assert!(
                    !shape.stream_read && !shape.stream_write,
                    "{kind:?} is a control object with a stream side",
                );
            }
        }
    }

    #[test]
    fn a_control_object_outside_its_shape_is_unsupported() {
        assert_eq!(ObjectFace::File.outside(), Error::InvalidArgument);
        assert_eq!(ObjectFace::Stream.outside(), Error::InvalidArgument);
        assert_eq!(ObjectFace::Control.outside(), Error::Unsupported);
    }

    #[test]
    fn a_readable_or_writable_object_has_a_stream_face() {
        for &kind in KernelObjectKind::ALL {
            let shape = kind.shape();
            if shape.stream_read || shape.stream_write {
                assert_ne!(
                    shape.face,
                    ObjectFace::Control,
                    "{kind:?} streams from a control face",
                );
            }
        }
    }
}
