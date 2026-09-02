//! The arithmetic that decides whether a signature scheme fits on a part.

/// Where a number came from.
///
/// This exists because the credibility of a budget table is entirely a question of
/// which rows are facts. Sizes fixed by a standard are facts. Code and RAM figures
/// are not, until somebody builds for the target and reads the map file — and a
/// table that mixes the two without saying so is worse than no table, because it
/// invites a design decision to be made on a guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Provenance {
    /// Fixed by the specification. Not going to change.
    Specified,
    /// Read off a real build or a real board.
    Measured,
    /// An order-of-magnitude placeholder. **Replace before deciding anything.**
    Estimated,
}

impl Provenance {
    /// Short marker for table output.
    pub const fn mark(&self) -> &'static str {
        match self {
            Provenance::Specified => "spec",
            Provenance::Measured => "meas",
            Provenance::Estimated => "EST?",
        }
    }
}

/// A signature scheme, sized.
#[derive(Clone, Copy, Debug)]
pub struct Scheme {
    /// Human-readable name.
    pub name: &'static str,
    /// Public key encoding, bytes.
    pub public_key: usize,
    /// Signature, bytes.
    pub signature: usize,
    /// Approximate verifier code size, bytes.
    pub code: usize,
    /// `code` minus a baseline built from the hash **that scheme uses**.
    ///
    /// The column that is actually comparable. Totals are not: different schemes
    /// pull different hash crates and different versions of them, and those
    /// differences are larger than the differences between the schemes. On
    /// `thumbv7em` the SHA-256 in `sha2` 0.10 is 3880 bytes, the one in 0.11 is
    /// 8840, SHA-512 is 28856, and SHAKE-256 is 2520.
    ///
    /// Approximate: shared machinery and inlining mean the baseline is not a
    /// clean partition.
    pub code_less_hash: Option<usize>,
    /// Peak RAM during verification, bytes.
    pub ram: usize,
    /// Where `code` and `code_less_hash` came from.
    pub code_provenance: Provenance,
    /// Where `ram` came from.
    ///
    /// Separate from [`Self::code_provenance`] because they are established by
    /// completely different means — a linker for one, painting the stack on real
    /// hardware for the other — and a single field let a row claim measured RAM on
    /// the strength of a measured code size. It did, for about an hour.
    pub ram_provenance: Provenance,
    /// Target the figures were measured on. `None` when they are estimates.
    pub measured_on: Option<&'static str>,
    /// Typical SHA-256 compressions to verify, over a 32 KiB image.
    ///
    /// The fourth budget, and the one usually waved at rather than counted: boot
    /// has a time limit as surely as it has a flash limit. Reported in
    /// compressions rather than milliseconds because compressions are exact and
    /// architecture-independent — multiply by what one costs on the part in hand.
    ///
    /// `None` for every scheme whose cost has not been derived. For LMS this comes
    /// from [`lms_verify::cost::bounds`] and a test keeps it from drifting.
    pub verify_hashes: Option<usize>,
    /// True if security rests on a hash function alone.
    pub hash_based: bool,
    /// True if the signing key is stateful and a reused index is fatal.
    pub stateful: bool,
    /// True if a cryptographically relevant quantum computer breaks it.
    pub quantum_broken: bool,
}

/// The part the verifier has to run on.
#[derive(Clone, Copy, Debug)]
pub struct Part {
    /// Board or MCU name.
    pub name: &'static str,
    /// One-time-programmable storage available for the root of trust, bytes.
    ///
    /// Typically tens of bytes: enough for a digest, not for a key.
    pub otp: usize,
    /// Flash available to the boot ROM or first-stage loader, bytes.
    pub flash: usize,
    /// RAM available before the next stage is up, bytes.
    pub ram: usize,
}

/// Which constraint binds, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fit {
    /// Everything fits.
    Fits,
    /// The root digest does not fit in OTP.
    OtpExceeded,
    /// Verifier code plus the stored public key does not fit in flash.
    FlashExceeded,
    /// Peak verification RAM does not fit.
    RamExceeded,
}

/// Bytes of OTP the root of trust consumes.
///
/// **Not the public key.** The near-universal pattern is to burn a 32-byte digest
/// of the root public key into fuses and keep the key itself in ordinary flash;
/// the boot ROM hashes the key it reads and compares against the fuses. That is
/// what makes a 1312-byte ML-DSA key usable on a part with 32 bytes of OTP, and
/// it is the detail that decides whether "we cannot fit a post-quantum key in
/// fuses" is a real objection or a misunderstanding. It is usually the latter.
pub const ROOT_DIGEST_OTP: usize = 32;

impl Scheme {
    /// Check this scheme against a part.
    pub fn fits(&self, part: &Part) -> Fit {
        if ROOT_DIGEST_OTP > part.otp {
            return Fit::OtpExceeded;
        }
        if self.code + self.public_key > part.flash {
            return Fit::FlashExceeded;
        }
        if self.ram > part.ram {
            return Fit::RamExceeded;
        }
        Fit::Fits
    }

    /// Bytes added to every signed image: the signature travels with it.
    pub const fn per_image_overhead(&self) -> usize {
        self.signature
    }
}

/// Key and signature sizes are from the standards.
///
/// The **LMS rows are measured**, on `thumbv7em-none-eabihf`, by
/// `size-probe/measure.sh` — see [`crate::measurements`] for the other three
/// targets and for how the numbers were produced.
///
/// **Every scheme's `code` is now measured** on `thumbv7em`, and
/// [`Scheme::code_less_hash`] is the column to compare — totals are dominated by
/// which hash crate and version the scheme happens to pull.
///
/// **The order that produces is not the expected one:** LMS 1656, SLH-DSA-128s
/// 6576, FN-DSA-512 9376, ML-DSA 11049, Ed25519 12808, **ECDSA P-256 16632**.
/// The classical scheme
/// carries the most code, not the least.
///
/// That order survived a compiler bump: 1.97.1 → 1.98.0 moved every figure by tens
/// of bytes and changed nothing about which scheme sits where.
///
/// These are particular implementations. A size-optimised assembly ECDSA — what
/// a real boot ROM actually ships — would be a fraction of what the `p256` crate
/// measures here, and the comparison should not be read as one between algorithms.
///
/// **RAM is measured for LMS and ML-DSA-44**, on an ESP32-S3.
///
/// **And its estimate had been wrong by a factor of three.** The guess was 12000
/// bytes of RAM; verification actually uses **34044**, because ML-DSA materialises
/// the expanded matrix and several polynomial vectors on the stack. That moved the
/// scheme from fitting a 32 KB part to not fitting one — a design decision the
/// estimate would have got backwards.
///
/// **The FN-DSA-512 RAM figure is derived from the crate's declared arrays, not
/// measured**: 1024 bytes for the key's `h`, plus 1024 and 2048 for the two
/// scratch buffers `verify` puts on the stack, plus the hash state. That method
/// is the one that under-reported LMS badly enough to send me to hardware, so
/// treat 4400 as a floor rather than a figure. It is still the interesting
/// number, because it is roughly four times what LMS needs.
///
/// **RAM is measured only for LMS and ML-DSA-44.** Everything else is a guess,
/// and [`Scheme::ram_provenance`] says so per row rather than one flag covering
/// both columns — an earlier version had a single field, and rows started claiming
/// measured RAM because their code size had been measured.
///
/// **The ML-DSA-65 and -87 RAM estimates are known to be wrong**, not merely
/// unverified. Both have larger matrices than -44, whose measured usage is 34044
/// bytes, so neither can need the 16000 and 20000 the table still carries. They are
/// left visible rather than silently patched, because a number nobody measured
/// should not be quietly replaced by a number nobody measured either.
pub const SCHEMES: &[Scheme] = &[
    Scheme {
        name: "ECDSA P-256",
        public_key: 33,
        signature: 64,
        code: 25_408,
        code_less_hash: Some(16_632),
        ram: 1_500,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Estimated,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: None,
        hash_based: false,
        stateful: false,
        quantum_broken: true,
    },
    Scheme {
        name: "Ed25519",
        public_key: 32,
        signature: 64,
        code: 41_592,
        code_less_hash: Some(12_808),
        ram: 1_200,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Estimated,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: None,
        hash_based: false,
        stateful: false,
        quantum_broken: true,
    },
    Scheme {
        name: "LMS w8/h5",
        public_key: 56,
        signature: 1_292,
        code: 5_464,
        code_less_hash: Some(1_656),
        ram: 1_152,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Measured,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: Some(4_877),
        hash_based: true,
        stateful: true,
        quantum_broken: false,
    },
    Scheme {
        name: "LMS w8/h10",
        public_key: 56,
        signature: 1_452,
        code: 5_464,
        code_less_hash: Some(1_656),
        ram: 1_152,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Measured,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: Some(4_887),
        hash_based: true,
        stateful: true,
        quantum_broken: false,
    },
    Scheme {
        name: "LMS w4/h10",
        public_key: 56,
        signature: 2_508,
        code: 5_464,
        code_less_hash: Some(1_656),
        ram: 1_152,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Measured,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: Some(1_070),
        hash_based: true,
        stateful: true,
        quantum_broken: false,
    },
    Scheme {
        name: "ML-DSA-44",
        public_key: 1_312,
        signature: 2_420,
        code: 13_497,
        code_less_hash: Some(11_049),
        ram: 34_044,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Measured,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: None,
        hash_based: false,
        stateful: false,
        quantum_broken: false,
    },
    Scheme {
        name: "ML-DSA-65",
        public_key: 1_952,
        signature: 3_309,
        code: 13_705,
        code_less_hash: Some(11_257),
        ram: 16_000,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Estimated,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: None,
        hash_based: false,
        stateful: false,
        quantum_broken: false,
    },
    Scheme {
        name: "ML-DSA-87",
        public_key: 2_592,
        signature: 4_627,
        code: 13_657,
        code_less_hash: Some(11_209),
        ram: 20_000,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Estimated,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: None,
        hash_based: false,
        stateful: false,
        quantum_broken: false,
    },
    Scheme {
        name: "FN-DSA-512",
        public_key: 897,
        signature: 666,
        code: 11_824,
        code_less_hash: Some(9_376),
        ram: 4_400,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Estimated,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: None,
        hash_based: false,
        stateful: false,
        quantum_broken: false,
    },
    Scheme {
        name: "SLH-DSA-128s",
        public_key: 32,
        signature: 7_856,
        code: 15_352,
        code_less_hash: Some(6_576),
        ram: 2_000,
        code_provenance: Provenance::Measured,
        ram_provenance: Provenance::Estimated,
        measured_on: Some(crate::measurements::REPRESENTATIVE),
        verify_hashes: None,
        hash_based: true,
        stateful: false,
        quantum_broken: false,
    },
    Scheme {
        name: "SLH-DSA-128f",
        public_key: 32,
        signature: 17_088,
        code: 8_000,
        code_less_hash: None,
        ram: 2_000,
        code_provenance: Provenance::Estimated,
        ram_provenance: Provenance::Estimated,
        measured_on: None,
        verify_hashes: None,
        hash_based: true,
        stateful: false,
        quantum_broken: false,
    },
];

/// Representative parts, from tight to comfortable.
pub const PARTS: &[Part] = &[
    Part {
        name: "tight boot ROM",
        otp: 32,
        flash: 16 * 1024,
        ram: 8 * 1024,
    },
    Part {
        name: "Cortex-M4 class",
        otp: 64,
        flash: 64 * 1024,
        ram: 32 * 1024,
    },
    Part {
        name: "application core",
        otp: 256,
        flash: 512 * 1024,
        ram: 256 * 1024,
    },
];

/// Look a scheme up by name.
pub fn scheme(name: &str) -> Option<&'static Scheme> {
    SCHEMES.iter().find(|s| s.name == name)
}
