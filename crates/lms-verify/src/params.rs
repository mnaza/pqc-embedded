//! RFC 8554 parameter sets.
//!
//! Only the SHA-256/n=32 family is implemented. That is the family NIST SP 800-208
//! approves and the only one that matters for firmware signing today.

use crate::Error;

/// Hash output length in bytes. `n` for LM-OTS, `m` for LMS — equal for SHA-256.
pub const N: usize = 32;

/// Length of the LMS key identifier `I`.
pub const I_LEN: usize = 16;

/// Largest `p` across the supported parameter sets (w=4 → p=67).
///
/// Nothing in the verifier allocates `p` elements — see the module docs on why
/// the chains are folded into the hash incrementally — but the constant is
/// useful for sizing callers' signature buffers.
pub const MAX_P: usize = 67;

/// LM-OTS parameter set (RFC 8554 §4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LmotsParams {
    /// RFC 8554 typecode, as it appears on the wire.
    pub typecode: u32,
    /// Winternitz width in bits: 1, 2, 4 or 8.
    pub w: u32,
    /// Number of hash chains.
    pub p: usize,
    /// Left-shift applied to the checksum.
    pub ls: u32,
}

impl LmotsParams {
    /// Byte length of an LM-OTS signature: `u32str(type) || C || y[0..p]`.
    pub const fn sig_len(&self) -> usize {
        4 + N * (self.p + 1)
    }

    /// Number of hash applications in one full chain.
    pub const fn chain_len(&self) -> u32 {
        (1u32 << self.w) - 1
    }

    /// Look up a parameter set by its RFC 8554 typecode.
    pub fn from_typecode(t: u32) -> Result<Self, Error> {
        match t {
            1 => Ok(LMOTS_SHA256_N32_W1),
            2 => Ok(LMOTS_SHA256_N32_W2),
            3 => Ok(LMOTS_SHA256_N32_W4),
            4 => Ok(LMOTS_SHA256_N32_W8),
            _ => Err(Error::UnknownLmotsType),
        }
    }
}

/// `w=1`: smallest signature-generation cost, largest signature (p=265).
pub const LMOTS_SHA256_N32_W1: LmotsParams = LmotsParams {
    typecode: 1,
    w: 1,
    p: 265,
    ls: 7,
};
/// `w=2`: p=133.
pub const LMOTS_SHA256_N32_W2: LmotsParams = LmotsParams {
    typecode: 2,
    w: 2,
    p: 133,
    ls: 6,
};
/// `w=4`: p=67. A middle trade — 15 hashes per chain, 67 chains.
pub const LMOTS_SHA256_N32_W4: LmotsParams = LmotsParams {
    typecode: 3,
    w: 4,
    p: 67,
    ls: 4,
};
/// `w=8`: p=34. Smallest signature, most hashing per verification (255 per chain).
///
/// The usual choice for boot, where flash is scarcer than boot time.
pub const LMOTS_SHA256_N32_W8: LmotsParams = LmotsParams {
    typecode: 4,
    w: 8,
    p: 34,
    ls: 0,
};

/// LMS parameter set (RFC 8554 §5.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LmsParams {
    /// RFC 8554 typecode, as it appears on the wire.
    pub typecode: u32,
    /// Merkle tree height. The key can sign `2^h` messages, once each.
    pub h: u32,
}

impl LmsParams {
    /// Number of one-time signatures this parameter set allows.
    pub const fn capacity(&self) -> u64 {
        1u64 << self.h
    }

    /// Look up a parameter set by its RFC 8554 typecode.
    pub fn from_typecode(t: u32) -> Result<Self, Error> {
        match t {
            5 => Ok(LMS_SHA256_M32_H5),
            6 => Ok(LMS_SHA256_M32_H10),
            7 => Ok(LMS_SHA256_M32_H15),
            8 => Ok(LMS_SHA256_M32_H20),
            9 => Ok(LMS_SHA256_M32_H25),
            _ => Err(Error::UnknownLmsType),
        }
    }
}

/// `h=5`: 32 signatures. Small enough to generate in a test.
pub const LMS_SHA256_M32_H5: LmsParams = LmsParams { typecode: 5, h: 5 };
/// `h=10`: 1024 signatures. A plausible firmware-release budget for one key.
pub const LMS_SHA256_M32_H10: LmsParams = LmsParams { typecode: 6, h: 10 };
/// `h=15`: 32768 signatures.
pub const LMS_SHA256_M32_H15: LmsParams = LmsParams { typecode: 7, h: 15 };
/// `h=20`: about a million signatures. Key generation is already expensive here.
pub const LMS_SHA256_M32_H20: LmsParams = LmsParams { typecode: 8, h: 20 };
/// `h=25`: about 33 million. Practical only with a hierarchical (HSS) scheme.
pub const LMS_SHA256_M32_H25: LmsParams = LmsParams { typecode: 9, h: 25 };

/// Domain separators (RFC 8554 §3.1.3).
pub(crate) const D_PBLC: u16 = 0x8080;
pub(crate) const D_MESG: u16 = 0x8181;
pub(crate) const D_LEAF: u16 = 0x8282;
pub(crate) const D_INTR: u16 = 0x8383;
