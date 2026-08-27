//! src/kernel/network/tls/mod.rs
//!
//! TLS 1.3 protocol implementation.
//!
//! Provides the TLS 1.3 record layer and handshake state machine for
//! establishing secure channels over TCP connections.

pub mod certificate;
pub mod handshake;
pub mod record;
pub mod root_store;

#[cfg(test)]
pub(crate) mod test_fixtures;

use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::crypto::sha256;
use crate::kernel::crypto::x25519;
use crate::kernel::network::TcpConnection;
use crate::Error;
use crate::Result;

/// TLS protocol version constants.
pub const TLS_VERSION_1_3: u16 = 0x0304;
pub const TLS_LEGACY_VERSION: u16 = 0x0303;

/// Cipher suite identifiers.
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Named groups for key exchange.
pub const X25519: u16 = 0x001D;

/// Signature schemes.
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;

/// Handshake message types (RFC 8446 §4).
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

// ── Transcript hash ───────────────────────────────────────────────────────

/// Accumulates handshake message hashes for the TLS 1.3 key schedule.
pub struct TranscriptHash {
    /// Running SHA-256 hash of all handshake messages seen so far.
    state: Vec<u8>,
}

impl Default for TranscriptHash {
    fn default() -> Self {
        Self::new()
    }
}

impl TranscriptHash {
    pub fn new() -> Self {
        Self { state: Vec::new() }
    }

    /// Feed a complete handshake message into the transcript.
    pub fn update(&mut self, message: &[u8]) {
        self.state.extend_from_slice(message);
    }

    /// Return the SHA-256 hash of all handshake messages seen so far.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.state)
    }
}

// ── TLS connection ────────────────────────────────────────────────────────

/// A TLS 1.3 client connection.
///
/// Manages the handshake state, traffic keys, and record-layer
/// encryption/decryption for a single TLS session.
pub struct TlsConnection {
    /// Current handshake state (None once handshake is complete).
    pub handshake: Option<TlsHandshakeState>,
    /// Client-to-server traffic keys (available after handshake keys derived).
    pub client_keys: Option<record::TrafficKeys>,
    /// Server-to-client traffic keys (available after handshake keys derived).
    pub server_keys: Option<record::TrafficKeys>,
    /// Application-data client keys (available after handshake complete).
    pub client_app_keys: Option<record::TrafficKeys>,
    /// Application-data server keys (available after handshake complete).
    pub server_app_keys: Option<record::TrafficKeys>,
    /// Accumulated transcript hash.
    pub transcript: TranscriptHash,
    /// Server hostname (for SNI).
    pub server_name: String,
    /// Ephemeral X25519 private key (generated during ClientHello, used for
    /// ECDH shared secret computation after ServerHello).
    ephemeral_private: Option<[u8; 32]>,
    /// Peer certificate chain parsed during the handshake (leaf first).
    pub peer_certificates: Vec<certificate::X509Certificate>,
}

/// Client-side TLS 1.3 handshake state machine.
pub enum TlsHandshakeState {
    /// Waiting to send ClientHello.
    ClientHello,
    /// ClientHello sent, waiting for ServerHello.
    WaitServerHello,
    /// Processing server's handshake messages.
    WaitEncryptedExtensions,
    /// Processing server Certificate.
    WaitCertificate,
    /// Processing server CertificateVerify.
    WaitCertificateVerify,
    /// Processing server Finished.
    WaitFinished,
    /// Handshake complete.
    Done,
}

impl TlsConnection {
    /// Create a new TLS client connection.
    pub fn new(server_name: &str) -> Self {
        Self {
            handshake: Some(TlsHandshakeState::ClientHello),
            client_keys: None,
            server_keys: None,
            client_app_keys: None,
            server_app_keys: None,
            transcript: TranscriptHash::new(),
            server_name: String::from(server_name),
            ephemeral_private: None,
            peer_certificates: Vec::new(),
        }
    }

    /// Build the ClientHello message.
    ///
    /// Returns the raw handshake message (to be wrapped in a TLS record).
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>> {
        let mut hello = Vec::new();

        // Handshake type: ClientHello = 1.
        hello.push(0x01);
        // 3-byte length placeholder (filled in later).
        let len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Protocol version: TLS 1.2 in ClientHello for compatibility
        // (TLS 1.3 uses the supported_versions extension).
        hello.extend_from_slice(&0x0303u16.to_be_bytes());

        // Random: 32 bytes.
        let mut random = [0u8; 32];
        crate::kernel::random::fill_random(&mut random);
        // Set the legacy "session ID" bytes for TLS 1.3 downgrade protection
        // (last 8 bytes).
        random[24..].copy_from_slice(b"DOWNGRD\x01");
        hello.extend_from_slice(&random);

        // Legacy session ID: empty (TLS 1.3).
        hello.push(0x00);

        // Cipher suites: [TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256].
        let cipher_suites: [u8; 4] = [0x13, 0x01, 0x13, 0x03];
        hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        hello.extend_from_slice(&cipher_suites);

        // Legacy compression methods: null.
        hello.push(0x01);
        hello.push(0x00);

        // Extensions.
        let ext_start = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]); // placeholder for extensions length

        // supported_versions extension (TLS 1.3).
        // Extension type = 43 (0x002B).
        hello.extend_from_slice(&0x002Bu16.to_be_bytes());
        hello.extend_from_slice(&0x0003u16.to_be_bytes()); // length
        hello.push(0x02); // versions length
        hello.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3

        // Signature algorithms extension (type 13).
        hello.extend_from_slice(&0x000Du16.to_be_bytes());
        hello.extend_from_slice(&0x0006u16.to_be_bytes()); // length
        hello.push(0x04); // sig algs length
        hello.extend_from_slice(&ECDSA_SECP256R1_SHA256.to_be_bytes());
        hello.extend_from_slice(&RSA_PSS_RSAE_SHA256.to_be_bytes());

        // Supported groups extension (type 10).
        hello.extend_from_slice(&0x000Au16.to_be_bytes());
        hello.extend_from_slice(&0x0004u16.to_be_bytes()); // length
        hello.push(0x02); // groups length
        hello.extend_from_slice(&X25519.to_be_bytes());

        // Key share extension (type 51 = 0x0033).
        let key_share_ext = self.build_key_share_extension();
        hello.extend_from_slice(&0x0033u16.to_be_bytes());
        hello.extend_from_slice(&(key_share_ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&key_share_ext);

        // Server name (SNI) extension (type 0).
        let sni_ext = build_sni_extension(&self.server_name);
        hello.extend_from_slice(&0x0000u16.to_be_bytes());
        hello.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&sni_ext);

        // Fix up extensions length.
        let ext_len = hello.len() - ext_start - 2;
        hello[ext_start] = (ext_len >> 8) as u8;
        hello[ext_start + 1] = ext_len as u8;

        // Fix up handshake message length.
        let msg_len = hello.len() - len_pos - 3;
        hello[len_pos] = (msg_len >> 16) as u8;
        hello[len_pos + 1] = (msg_len >> 8) as u8;
        hello[len_pos + 2] = msg_len as u8;

        self.transcript.update(&hello);
        self.handshake = Some(TlsHandshakeState::WaitServerHello);

        Ok(hello)
    }

    /// Perform a complete TLS 1.3 client handshake over a TCP connection.
    ///
    /// On success, `self.client_app_keys` and `self.server_app_keys` are
    /// populated with the application-data traffic keys, and the handshake
    /// state is set to `Done`.  The caller can then use
    /// [`record::build_tls_record`] and [`record::parse_tls_record`] with
    /// these keys to exchange application data.
    pub fn do_handshake(&mut self, connection: &TcpConnection) -> Result<()> {
        // 1. Send ClientHello.
        let hello = self.build_client_hello()?;
        let hello_record = handshake::build_plaintext_handshake_record(&hello);
        connection.write_all(&hello_record)?;

        // 2. Read ServerHello (plaintext handshake record).
        let parsed_sh = self.read_server_hello(connection)?;

        // 3. Compute ECDH shared secret and derive handshake keys.
        let shared_secret = self.compute_shared_secret(&parsed_sh.server_public_key)?;
        let transcript_sh = self.transcript.digest();
        let hs_secrets = handshake::HandshakeSecrets::compute(&shared_secret, &transcript_sh);
        let (client_hs_keys, server_hs_keys) =
            hs_secrets.derive_handshake_keys(parsed_sh.cipher_suite);
        self.client_keys = Some(client_hs_keys);
        self.server_keys = Some(server_hs_keys);
        self.handshake = Some(TlsHandshakeState::WaitEncryptedExtensions);

        // 4. Read encrypted handshake messages until server Finished.
        let server_finished = self.read_encrypted_handshake(connection, &hs_secrets)?;

        // 5. Build and send client Finished.
        self.send_client_finished(connection, &hs_secrets, &server_finished)?;

        // 6. Derive application traffic keys.
        let transcript_sf = self.transcript.digest();
        let app_secrets =
            handshake::ApplicationSecrets::compute(&hs_secrets.handshake_secret, &transcript_sf);
        let (client_app_keys, server_app_keys) =
            app_secrets.derive_application_keys(parsed_sh.cipher_suite);
        self.client_app_keys = Some(client_app_keys);
        self.server_app_keys = Some(server_app_keys);

        self.handshake = Some(TlsHandshakeState::Done);
        Ok(())
    }

    /// Read and parse the server's ServerHello from a plaintext record.
    fn read_server_hello(
        &mut self,
        connection: &TcpConnection,
    ) -> Result<handshake::ParsedServerHello> {
        let mut buf = Vec::new();
        // Read the plaintext ServerHello record.
        let (ct, payload) = handshake::read_tls_record(connection, &mut buf)?;
        if ct != record::CONTENT_TYPE_HANDSHAKE {
            // Could be an alert — handle gracefully.
            return Err(Error::DeviceError);
        }

        let parsed = handshake::parse_server_hello(&payload)?;
        // Feed ServerHello to transcript.
        self.transcript.update(&parsed.raw_message);
        self.handshake = Some(TlsHandshakeState::WaitEncryptedExtensions);

        Ok(parsed)
    }

    /// Compute the ECDH shared secret from our ephemeral private key and
    /// the server's public key.
    fn compute_shared_secret(&self, server_public_key: &[u8; 32]) -> Result<[u8; 32]> {
        let private = self
            .ephemeral_private
            .as_ref()
            .ok_or(Error::InvalidArgument)?;
        Ok(x25519(private, server_public_key))
    }

    /// Read encrypted handshake messages until the server Finished is
    /// received and verified.
    ///
    /// Skips legacy ChangeCipherSpec.  Decrypts Application Data (type 23)
    /// records with the server handshake keys, strips the inner content type,
    /// and parses handshake messages from the stream.
    ///
    /// The transcript hash for Finished verification is computed correctly:
    /// `parse_handshake_messages_from_stream` does NOT feed Finished messages
    /// to the transcript.  When we encounter Finished, we compute the
    /// pre-Finished transcript hash, verify, and then manually feed the
    /// Finished message to the transcript.
    fn read_encrypted_handshake(
        &mut self,
        connection: &TcpConnection,
        hs_secrets: &handshake::HandshakeSecrets,
    ) -> Result<handshake::ParsedServerFinished> {
        let mut buf = Vec::new();
        let mut stream = Vec::new();
        let mut server_finished: Option<handshake::ParsedServerFinished> = None;

        // Read up to 16 records to collect all server handshake messages.
        for _ in 0..16 {
            buf.clear();
            let (ct, payload) = handshake::read_tls_record(connection, &mut buf)?;

            match ct {
                record::CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                    // Legacy CCS — skip the single byte.
                    continue;
                }
                record::CONTENT_TYPE_ALERT => {
                    return Err(Error::DeviceError);
                }
                record::CONTENT_TYPE_APPLICATION_DATA => {
                    // Decrypt with server handshake keys.
                    let server_keys = self.server_keys.as_mut().ok_or(Error::InvalidArgument)?;
                    // Reconstruct the wire record for parse_tls_record.
                    let mut wire = Vec::with_capacity(5 + payload.len());
                    wire.push(record::CONTENT_TYPE_APPLICATION_DATA);
                    wire.extend_from_slice(&0x0303u16.to_be_bytes());
                    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                    wire.extend_from_slice(&payload);

                    let (_inner_ct, plaintext) = record::parse_tls_record(server_keys, &wire)?;

                    // The plaintext includes the inner content type as the
                    // last byte (TLS 1.3). Extract it and the handshake data.
                    if plaintext.is_empty() {
                        continue;
                    }
                    let inner_ct = plaintext[plaintext.len() - 1];
                    let hs_data = &plaintext[..plaintext.len() - 1];

                    if inner_ct == record::CONTENT_TYPE_ALERT {
                        return Err(Error::DeviceError);
                    }
                    if inner_ct != record::CONTENT_TYPE_HANDSHAKE {
                        continue;
                    }

                    stream.extend_from_slice(hs_data);

                    // Parse accumulated handshake messages.
                    // Finished messages are NOT fed to the transcript by this
                    // function — we handle them below.
                    let messages = handshake::parse_handshake_messages_from_stream(
                        &stream,
                        &mut self.transcript,
                    )?;

                    for (msg_type, msg_data) in &messages {
                        match *msg_type {
                            HS_ENCRYPTED_EXTENSIONS => {
                                self.handshake = Some(TlsHandshakeState::WaitCertificate);
                            }
                            HS_CERTIFICATE => {
                                let _certs = handshake::parse_certificate_message(msg_data)?;
                                // Parse and verify the certificate chain.
                                let der_list: Vec<&[u8]> =
                                    _certs.iter().map(|c| c.der.as_slice()).collect();
                                // Feed each DER cert to the cert parser.
                                let mut parsed_chain = Vec::new();
                                for der in &der_list {
                                    if let Some(cert) = certificate::parse_x509_certificate(der) {
                                        parsed_chain.push(cert);
                                    }
                                }
                                let status =
                                    certificate::verify_chain(&parsed_chain, &self.server_name);
                                if status != certificate::ChainVerifyStatus::Trusted {
                                    return Err(Error::InvalidArgument);
                                }
                                self.peer_certificates = parsed_chain;
                                self.handshake = Some(TlsHandshakeState::WaitCertificateVerify);
                            }
                            HS_CERTIFICATE_VERIFY => {
                                // Verify the server's signature over the
                                // transcript hash using the leaf certificate's
                                // public key.
                                if !handshake::verify_certificate_verify_signature(
                                    msg_data,
                                    &self.peer_certificates,
                                    &self.transcript,
                                ) {
                                    return Err(Error::InvalidArgument);
                                }
                                self.handshake = Some(TlsHandshakeState::WaitFinished);
                            }
                            HS_FINISHED => {
                                // The transcript currently covers
                                // ClientHello...CertificateVerify (Finished
                                // was NOT fed by parse_handshake_messages_
                                // from_stream).  Compute the pre-Finished
                                // hash, verify, then feed Finished.
                                let pre_finished_hash = self.transcript.digest();
                                let finished_key = hs_secrets.server_finished_key();
                                server_finished = Some(handshake::verify_server_finished(
                                    msg_data,
                                    &finished_key,
                                    &pre_finished_hash,
                                )?);
                                // Now feed Finished to the transcript for the
                                // key schedule (application secrets use the
                                // transcript hash *including* server Finished).
                                self.transcript.update(msg_data);
                                self.handshake = Some(TlsHandshakeState::WaitFinished);
                            }
                            _ => {
                                // Unknown handshake message — ignore.
                            }
                        }
                    }

                    // Return as soon as we have a verified server Finished.
                    if let Some(sf) = &server_finished {
                        return Ok(handshake::ParsedServerFinished {
                            verify_data: sf.verify_data,
                        });
                    }

                    // Remove fully parsed messages from stream prefix.
                    let consumed: usize = messages.iter().map(|(_, d)| d.len()).sum();
                    if consumed > 0 && consumed <= stream.len() {
                        stream.drain(..consumed);
                    }
                }
                _ => {
                    // Unknown content type — skip.
                }
            }
        }

        Err(Error::DeviceError)
    }

    /// Build and send the client Finished message.
    fn send_client_finished(
        &mut self,
        connection: &TcpConnection,
        hs_secrets: &handshake::HandshakeSecrets,
        _server_finished: &handshake::ParsedServerFinished,
    ) -> Result<()> {
        let transcript_hash = self.transcript.digest();
        let finished_key = hs_secrets.client_finished_key();
        let finished_msg = handshake::build_client_finished(&finished_key, &transcript_hash);

        // Encrypt with client handshake keys.
        let client_keys = self.client_keys.as_mut().ok_or(Error::InvalidArgument)?;
        let record =
            record::build_tls_record(client_keys, record::CONTENT_TYPE_HANDSHAKE, &finished_msg)?;
        connection.write_all(&record)?;

        Ok(())
    }

    /// Build the key_share extension with an X25519 ephemeral key.
    /// Stores the private key in `self.ephemeral_private` for later use
    /// in the ECDH shared-secret computation.
    fn build_key_share_extension(&mut self) -> Vec<u8> {
        let (private, public) = crate::kernel::crypto::x25519_keygen();

        // key_share extension format:
        //   KeyShareClientHello:
        //     client_shares<2..2^16-1>:
        //       KeyShareEntry:
        //         group<2> = 0x001D (X25519)
        //         key_exchange<2> = length
        //         key_exchange<1..2^16-1> = public key (32 bytes)

        let mut ext = Vec::new();
        // client_shares length placeholder.
        let shares_len_pos = ext.len();
        ext.extend_from_slice(&[0x00, 0x00]);

        // KeyShareEntry for X25519.
        ext.extend_from_slice(&X25519.to_be_bytes()); // group = X25519
        ext.extend_from_slice(&0x0020u16.to_be_bytes()); // key_exchange length = 32
        ext.extend_from_slice(&public);

        // Fix up client_shares length.
        let shares_len = ext.len() - shares_len_pos - 2;
        ext[shares_len_pos] = (shares_len >> 8) as u8;
        ext[shares_len_pos + 1] = shares_len as u8;

        // Store the private key for the ECDH shared-secret computation.
        self.ephemeral_private = Some(private);

        ext
    }
}

/// Build the Server Name Indication (SNI) extension.
fn build_sni_extension(hostname: &str) -> Vec<u8> {
    let mut ext = Vec::new();
    // server_name_list length placeholder.
    let list_len_pos = ext.len();
    ext.extend_from_slice(&[0x00, 0x00]);

    // ServerName:
    //   name_type = 0 (host_name)
    //   name length
    //   name
    ext.push(0x00); // name_type = host_name
    ext.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
    ext.extend_from_slice(hostname.as_bytes());

    // Fix up server_name_list length.
    let list_len = ext.len() - list_len_pos - 2;
    ext[list_len_pos] = (list_len >> 8) as u8;
    ext[list_len_pos + 1] = list_len as u8;

    ext
}

// ── TlsWrappedConnection ──────────────────────────────────────────────────

use crate::kernel::sync::Mutex;

/// A TCP connection wrapped with TLS 1.3 encryption.
///
/// After the TLS handshake completes, all application data written to this
/// connection is encrypted with the client traffic keys, and all data read
/// is decrypted with the server traffic keys (which the client derives during
/// the handshake).
pub struct TlsWrappedConnection {
    /// The underlying TCP connection.
    connection: crate::kernel::network::TcpConnection,
    /// Client traffic keys — `write_key` encrypts outgoing data, `read_key`
    /// decrypts incoming data (derived from server's traffic secret).
    keys: Mutex<record::TrafficKeys>,
    /// Decrypted bytes not yet consumed by the application (because a single
    /// TLS record may be larger than the caller's read buffer).
    read_buf: Mutex<Vec<u8>>,
}

impl core::fmt::Debug for TlsWrappedConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsWrappedConnection")
            .field("endpoint", &self.connection.endpoint())
            .finish_non_exhaustive()
    }
}

// Interior mutability via `Mutex`; the `Arc` in `KernelObject::TlsConnection`
// provides shared ownership for clone semantics.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for TlsWrappedConnection {}
unsafe impl Sync for TlsWrappedConnection {}

impl TlsWrappedConnection {
    /// Wrap an established TCP connection with TLS traffic keys.
    ///
    /// `keys` must be the **client** application traffic keys (containing both
    /// the client write key for encryption and the server read key for
    /// decryption).
    pub fn new(
        connection: crate::kernel::network::TcpConnection,
        keys: record::TrafficKeys,
    ) -> Self {
        Self {
            connection,
            keys: Mutex::new(keys),
            read_buf: Mutex::new(Vec::new()),
        }
    }

    /// Return the remote endpoint address string (as stored by the TCP
    /// stack).
    pub fn endpoint(&self) -> &str {
        self.connection.endpoint()
    }

    /// Read decrypted application data from the TLS connection.
    pub fn read(&self, buffer: &mut [u8], _timeout_ticks: u64) -> crate::Result<usize> {
        // Serve from the decryption buffer first.
        {
            let mut read_buf = self.read_buf.lock();
            if !read_buf.is_empty() {
                let n = core::cmp::min(buffer.len(), read_buf.len());
                buffer[..n].copy_from_slice(&read_buf[..n]);
                read_buf.drain(..n);
                return Ok(n);
            }
        }
        // Read a TLS record from the wire, decrypt, and return plaintext.
        let wire = self.read_raw_record()?;
        let mut keys = self.keys.lock();
        let (inner_ct, plaintext) =
            record::parse_tls_record(&mut keys, &wire).map_err(|_| crate::Error::DeviceError)?;
        drop(keys);
        match inner_ct {
            record::CONTENT_TYPE_APPLICATION_DATA => {
                let app_data = if plaintext.last() == Some(&record::CONTENT_TYPE_APPLICATION_DATA) {
                    &plaintext[..plaintext.len() - 1]
                } else {
                    &plaintext[..]
                };
                let n = core::cmp::min(buffer.len(), app_data.len());
                buffer[..n].copy_from_slice(&app_data[..n]);
                if n < app_data.len() {
                    self.read_buf.lock().extend_from_slice(&app_data[n..]);
                }
                Ok(n)
            }
            _ => Err(crate::Error::DeviceError),
        }
    }

    /// Encrypt and write application data to the TLS connection.
    pub fn write(&self, buffer: &[u8]) -> crate::Result<usize> {
        let mut keys = self.keys.lock();
        let record =
            record::build_tls_record(&mut keys, record::CONTENT_TYPE_APPLICATION_DATA, buffer)
                .map_err(|_| crate::Error::DeviceError)?;
        drop(keys);
        self.connection.write_all(&record)?;
        Ok(buffer.len())
    }

    /// Check whether data is available for reading.
    pub fn is_readable(&self) -> crate::Result<bool> {
        if !self.read_buf.lock().is_empty() {
            return Ok(true);
        }
        self.connection.is_readable()
    }

    /// Check whether the connection can accept outgoing data.
    pub fn is_writable(&self) -> crate::Result<bool> {
        self.connection.is_writable()
    }

    /// Read one complete TLS wire record (5-byte header + encrypted payload)
    /// from the underlying TCP connection.
    fn read_raw_record(&self) -> crate::Result<Vec<u8>> {
        let mut header = [0u8; 5];
        let mut offset = 0usize;
        while offset < 5 {
            let n = self.connection.read(&mut header[offset..], 3000)?;
            if n == 0 {
                return Err(crate::Error::DeviceError);
            }
            offset += n;
        }
        let content_type = header[0];
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if length == 0 || length > 65535 {
            return Err(crate::Error::InvalidArgument);
        }
        let mut payload = alloc::vec![0u8; length];
        let mut offset = 0usize;
        while offset < length {
            let n = self.connection.read(&mut payload[offset..], 3000)?;
            if n == 0 {
                return Err(crate::Error::DeviceError);
            }
            offset += n;
        }
        let mut wire = Vec::with_capacity(5 + length);
        wire.push(content_type);
        wire.extend_from_slice(&0x0303u16.to_be_bytes());
        wire.extend_from_slice(&(length as u16).to_be_bytes());
        wire.extend_from_slice(&payload);
        Ok(wire)
    }
}

/// Connect to a TCP server and perform a TLS 1.3 handshake.
///
/// Returns a [`TlsWrappedConnection`] ready for encrypted application I/O.
pub fn tls_connect(host: &str, port: u16) -> crate::Result<TlsWrappedConnection> {
    let connection = crate::kernel::network::connect_tcp(host, port)?;
    let mut tls = TlsConnection::new(host);
    tls.do_handshake(&connection)?;
    let client_app_keys = tls.client_app_keys.ok_or(crate::Error::InvalidArgument)?;
    Ok(TlsWrappedConnection::new(connection, client_app_keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_hash_empty() {
        let t = TranscriptHash::new();
        let d = t.digest();
        let expected = sha256(b"");
        assert_eq!(d, expected);
    }

    #[test]
    fn transcript_hash_accumulates() {
        let mut t = TranscriptHash::new();
        t.update(b"hello");
        t.update(b" world");
        let d = t.digest();
        let expected = sha256(b"hello world");
        assert_eq!(d, expected);
    }

    #[test]
    fn build_client_hello() {
        let mut conn = TlsConnection::new("example.com");
        let hello = conn.build_client_hello().expect("build hello");
        // ClientHello should be a valid handshake message.
        assert_eq!(hello[0], 0x01, "handshake type = ClientHello");
        assert!(hello.len() > 50, "ClientHello should be substantial");
    }

    #[test]
    fn sni_extension_contains_hostname() {
        let ext = build_sni_extension("test.example.com");
        // Should contain "test.example.com" as bytes.
        let name_bytes = b"test.example.com";
        assert!(ext.windows(name_bytes.len()).any(|w| w == name_bytes));
    }
}
