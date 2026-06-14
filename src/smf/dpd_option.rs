/// SMF_DPD Hop-by-Hop option types (RFC 6621 §6.4).
///
/// The option type byte encodes the action (skip if unknown) and changeable flag.
/// For SMF_DPD: 0b000_01000 = 0x08 (skip if unknown, not changeable).
/// This constant is the option type value for the SMF_DPD Hop-by-Hop option.
pub const SMF_DPD_OPTION_TYPE: u8 = 0x08;

/// SMF_DPD option data length field sizes.
const TID_TYPE_NULL: u8 = 0;
#[allow(dead_code)]
const TID_TYPE_DEFAULT: u8 = 1;

/// A parsed SMF_DPD Hop-by-Hop option (RFC 6621 §6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmfDpdOption {
    /// Hash indicator: true if H-DPD mode, false if I-DPD mode.
    pub h_bit: bool,
    /// TaggerId type (0 = NULL, 1 = DEFAULT).
    pub tid_type: u8,
    /// TaggerId length in bytes.
    pub tid_len: u8,
    /// TaggerId bytes (absent if tid_type == NULL).
    pub tagger_id: Option<Vec<u8>>,
    /// Identifier (I-DPD) or Hash Assist Value (H-DPD).
    pub identifier: Vec<u8>,
}

impl SmfDpdOption {
    /// Encode this SMF_DPD option into wire format bytes.
    ///
    /// Wire format:
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Option Type  |  Opt Data Len |H| TidTy| TidLen|
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                 TaggerId (variable)           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |             Identifier / HAV (variable)       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let id_len = self.identifier.len();

        // Option data length = 1 (H|TidTy|TidLen) + tid_len + id_len
        let opt_data_len = 1 + self.tid_len as usize + id_len;

        let mut buf = Vec::with_capacity(2 + opt_data_len);

        // Option type
        buf.push(SMF_DPD_OPTION_TYPE);
        // Opt Data Len
        buf.push(opt_data_len as u8);

        // H | TidTy | TidLen
        let mut flags = (self.tid_type << 5) | (self.tid_len & 0x1F);
        if self.h_bit {
            flags |= 0x80;
        }
        buf.push(flags);

        // TaggerId (if present)
        if let Some(ref tid) = self.tagger_id {
            buf.extend_from_slice(tid);
        }

        // Identifier / HAV
        buf.extend_from_slice(&self.identifier);

        buf
    }

    /// Decode an SMF_DPD option from wire format bytes.
    ///
    /// Returns `None` if the bytes cannot be parsed.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        let flags = data[0];
        let h_bit = (flags & 0x80) != 0;
        let tid_type = (flags >> 5) & 0x03;
        let tid_len = (flags & 0x1F) as usize;
        let flags_len = 1;

        if data.len() < flags_len + tid_len {
            return None;
        }

        let tagger_id = if tid_len > 0 {
            Some(data[flags_len..flags_len + tid_len].to_vec())
        } else {
            None
        };

        let id_start = flags_len + tid_len;
        let identifier = data[id_start..].to_vec();

        if identifier.is_empty() {
            return None; // Must have at least an identifier/HAV
        }

        Some(Self {
            h_bit,
            tid_type,
            tid_len: tid_len as u8,
            tagger_id,
            identifier,
        })
    }

    /// Create a new I-DPD option with the given identifier.
    pub fn new_i_dpd(identifier: Vec<u8>) -> Self {
        Self {
            h_bit: false,
            tid_type: TID_TYPE_NULL,
            tid_len: 0,
            tagger_id: None,
            identifier,
        }
    }

    /// Create a new H-DPD option with the given Hash Assist Value.
    pub fn new_h_dpd(hav: Vec<u8>) -> Self {
        Self {
            h_bit: true,
            tid_type: TID_TYPE_NULL,
            tid_len: 0,
            tagger_id: None,
            identifier: hav,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i_dpd_round_trip() {
        let opt = SmfDpdOption::new_i_dpd(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let encoded = opt.encode();
        let decoded = SmfDpdOption::decode(&encoded[2..]).unwrap();
        assert_eq!(decoded, opt);
    }

    #[test]
    fn h_dpd_round_trip() {
        let opt = SmfDpdOption::new_h_dpd(vec![0x11, 0x22, 0x33, 0x44]);
        let encoded = opt.encode();
        let decoded = SmfDpdOption::decode(&encoded[2..]).unwrap();
        assert_eq!(decoded, opt);
    }

    #[test]
    fn i_dpd_has_h_bit_clear() {
        let opt = SmfDpdOption::new_i_dpd(vec![1, 2, 3]);
        assert!(!opt.h_bit);
    }

    #[test]
    fn h_dpd_has_h_bit_set() {
        let opt = SmfDpdOption::new_h_dpd(vec![1, 2, 3]);
        assert!(opt.h_bit);
    }

    #[test]
    fn decode_invalid_too_short() {
        assert!(SmfDpdOption::decode(&[0x00]).is_none());
    }

    #[test]
    fn decode_invalid_empty_identifier() {
        // Only a flags byte with no identifier bytes
        assert!(SmfDpdOption::decode(&[0x00]).is_none());
    }

    #[test]
    fn option_with_tagger_id_round_trip() {
        let opt = SmfDpdOption {
            h_bit: false,
            tid_type: TID_TYPE_DEFAULT,
            tid_len: 4,
            tagger_id: Some(vec![0x01, 0x02, 0x03, 0x04]),
            identifier: vec![0xAA, 0xBB],
        };
        let encoded = opt.encode();
        let decoded = SmfDpdOption::decode(&encoded[2..]).unwrap();
        assert_eq!(decoded, opt);
    }

    #[test]
    fn encode_produces_correct_header() {
        let opt = SmfDpdOption::new_i_dpd(vec![1, 2, 3, 4]);
        let encoded = opt.encode();
        assert_eq!(encoded[0], SMF_DPD_OPTION_TYPE); // option type
        assert_eq!(encoded[1], 5); // data len = 1 (flags) + 0 (tid) + 4 (id)
        assert_eq!(encoded[2], 0x00); // H=0, TidTy=0, TidLen=0
        assert_eq!(&encoded[3..], &[1, 2, 3, 4]);
    }
}
