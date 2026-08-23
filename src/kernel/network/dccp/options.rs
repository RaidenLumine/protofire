//! src/kernel/network/dccp/options.rs
//! DCCP options and minimal feature negotiation (RFC 4340 §6, §11).
//!
//! Options are byte-aligned: `[type(1)][length(1)][length-2 bytes of data]`.
//! The Mandatory option (type 0) is not a standalone option — it is encoded
//! by setting bit 7 of the *preceding* option's type byte.  The receiver
//! must be able to process any option marked mandatory or reset the
//! connection; since this kernel recognises the standard option set, only
//! reserved option types trigger an error.

use alloc::vec::Vec;

use crate::{Error, Result};

pub const OPT_MANDATORY: u8 = 0;
pub const OPT_INIT_COOKIE: u8 = 1;
pub const OPT_CHANGE_L: u8 = 2;
pub const OPT_CONFIRM_L: u8 = 3;
pub const OPT_CHANGE_R: u8 = 4;
pub const OPT_CONFIRM_R: u8 = 5;
pub const OPT_TIMESTAMP: u8 = 6;
pub const OPT_TIMESTAMP_ECHO: u8 = 7;
pub const OPT_ELAPSED_TIME: u8 = 8;
pub const OPT_DATA_CHECKSUM: u8 = 9;
pub const OPT_SEQ_WINDOW: u8 = 11;
pub const OPT_ACK_VECTOR: u8 = 12;
pub const OPT_PENDING_DATA: u8 = 13;
pub const OPT_MIN_CSUM_COVERAGE: u8 = 15;

/// One parsed DCCP option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccpOption {
    /// Whether the Mandatory bit was set on this option.
    pub mandatory: bool,
    /// Option type (0-15, without the Mandatory bit).
    pub kind: u8,
    /// Option data (`len - 2` bytes).
    pub data: Vec<u8>,
}

/// Locally negotiated features that matter for data-plane behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureState {
    /// Congestion Control ID (default 2 = CCID 2).
    pub ccid: u8,
    /// Sequence window in packets (default 100).
    pub seq_window: u16,
    /// Minimum checksum coverage nibble (default 0 = full coverage).
    pub min_csum_coverage: u8,
}

impl Default for FeatureState {
    fn default() -> Self {
        Self {
            ccid: 2,
            seq_window: 100,
            min_csum_coverage: 0,
        }
    }
}

/// Parse the option area of a DCCP packet.
pub fn parse_options(data: &[u8]) -> Result<Vec<DccpOption>> {
    let mut options = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let mandatory = data[pos] & 0x80 != 0;
        let kind = data[pos] & 0x7F;
        pos += 1;
        let len = if kind == OPT_MANDATORY {
            1
        } else {
            if pos >= data.len() {
                return Err(Error::InvalidArgument);
            }
            let len = data[pos] as usize;
            pos += 1;
            if len < 2 || pos + len - 2 > data.len() {
                return Err(Error::InvalidArgument);
            }
            len
        };
        let payload_len = len.saturating_sub(2);
        if payload_len > 0 && pos + payload_len > data.len() {
            return Err(Error::InvalidArgument);
        }
        if kind == OPT_MANDATORY {
            // Standalone Mandatory has no length field and no data.
            continue;
        }
        // Reserved option types (10, 14) must not be ignored when marked
        // mandatory (RFC 4340 §11.4).
        if kind == 10 || kind == 14 {
            if mandatory {
                return Err(Error::Unsupported);
            }
            pos += payload_len;
            continue;
        }
        let payload = data[pos..pos + payload_len].to_vec();
        pos += payload_len;
        options.push(DccpOption {
            mandatory,
            kind,
            data: payload,
        });
    }
    Ok(options)
}

/// Apply Change/Confirm options to the local feature state.  Change L
/// (local, sent by peer to change our behaviour) updates our feature state;
/// Confirm L (our change acknowledged) is accepted as confirmation.
pub fn apply_features(state: &mut FeatureState, options: &[DccpOption]) {
    for option in options {
        match option.kind {
            OPT_CHANGE_L | OPT_CONFIRM_L => {
                // Feature number is the first data byte; the preference
                // number is the second; the NN value follows (RFC 4340 §6).
                let Some(&feature) = option.data.first() else {
                    continue;
                };
                let value = option.data.get(2..).unwrap_or(&[]);
                match feature {
                    2 => {
                        // CCID (NN, 1 byte).
                        if let Some(&ccid) = value.first() {
                            state.ccid = ccid;
                        }
                    }
                    3 => {
                        // Sequence Window (NN, 2 bytes).
                        if value.len() >= 2 {
                            state.seq_window = u16::from_be_bytes([value[0], value[1]]);
                        }
                    }
                    7 => {
                        // Minimum Checksum Coverage (NN, 1 byte).
                        if let Some(&coverage) = value.first() {
                            state.min_csum_coverage = coverage;
                        }
                    }
                    _ => {}
                }
            }
            OPT_CHANGE_R | OPT_CONFIRM_R => {
                // Remote feature changes are acknowledged but do not alter
                // our local data-plane behaviour.
            }
            _ => {}
        }
    }
}

/// Build a "Change L" option requesting `ccid` as the local CCID
/// (`[type 2][len 5][feature 2][preference 1][ccid 1-byte NN value]`).
pub fn build_change_l_ccid(ccid: u8) -> Vec<u8> {
    let value = [2u8, 1, ccid];
    let mut option = Vec::with_capacity(2 + value.len());
    option.push(OPT_CHANGE_L);
    option.push(2 + value.len() as u8);
    option.extend_from_slice(&value);
    option
}

/// Build a "Confirm L" option confirming that `ccid` was accepted
/// (`[type 3][len 5][feature 2][preference 1][ccid 1-byte value]`).
pub fn build_confirm_l_ccid(ccid: u8) -> Vec<u8> {
    let value = [2u8, 1, ccid];
    let mut option = Vec::with_capacity(2 + value.len());
    option.push(OPT_CONFIRM_L);
    option.push(2 + value.len() as u8);
    option.extend_from_slice(&value);
    option
}

/// Build an Init Cookie option (`[type 1][len][cookie bytes]`).
pub fn build_init_cookie(cookie: &[u8]) -> Vec<u8> {
    let mut option = Vec::with_capacity(2 + cookie.len());
    option.push(OPT_INIT_COOKIE);
    option.push(2 + cookie.len() as u8);
    option.extend_from_slice(cookie);
    option
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parse_empty_option_area() {
        let options = parse_options(&[]).expect("empty options");
        assert!(options.is_empty());
    }

    #[test]
    fn parse_change_l_ccid_option() {
        // Change L CCID = 2.
        let option = build_change_l_ccid(2);
        let options = parse_options(&option).expect("parse");
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].kind, OPT_CHANGE_L);
        assert!(!options[0].mandatory);
        assert_eq!(options[0].data, vec![2, 1, 2]);

        let mut state = FeatureState::default();
        apply_features(&mut state, &options);
        assert_eq!(state.ccid, 2);
    }

    #[test]
    fn change_l_seq_window_updates_state() {
        let value = [3u8, 1, 0x01, 0x2C]; // feature 3 (seq window), value 300
        let mut option = Vec::new();
        option.push(OPT_CHANGE_L);
        option.push(2 + value.len() as u8);
        option.extend_from_slice(&value);
        let options = parse_options(&option).expect("parse");
        let mut state = FeatureState::default();
        apply_features(&mut state, &options);
        assert_eq!(state.seq_window, 300);
    }

    #[test]
    fn mandatory_bit_is_enforced_on_reserved_options() {
        // Reserved type 10 with mandatory bit set must be rejected.
        let data = [0x80 | 10, 3, 0, 0];
        assert_eq!(parse_options(&data), Err(Error::Unsupported));
        // Without mandatory it is skipped.
        let data = [10, 3, 0, 0];
        let options = parse_options(&data).expect("skip reserved");
        assert!(options.is_empty());
    }

    #[test]
    fn malformed_length_rejected() {
        let data = [6, 10, 0x12]; // claims len 10 but only 3 bytes present
        assert_eq!(parse_options(&data), Err(Error::InvalidArgument));
    }

    #[test]
    fn init_cookie_round_trip() {
        let cookie = b"0123456789abcdef";
        let option = build_init_cookie(cookie);
        let options = parse_options(&option).expect("parse");
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].kind, OPT_INIT_COOKIE);
        assert_eq!(options[0].data, cookie);
    }
}
