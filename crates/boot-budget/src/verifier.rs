//! The interface a bootloader actually needs from a signature scheme.

use lms_verify::{LmotsParams, LmsParams};

/// What a boot stage needs in order to authenticate the next one.
///
/// Deliberately verification-only and deliberately small. A boot ROM does not
/// generate keys, does not sign, does not parse certificates and does not need an
/// allocator. Every capability beyond this list is code that has to fit in flash
/// and be trusted forever, because — see the crate docs — it cannot be replaced.
pub trait BootVerifier {
    /// Why verification failed.
    type Error: core::fmt::Debug;

    /// Bytes of public key this scheme's encoding takes.
    fn public_key_len(&self) -> usize;

    /// Bytes of signature that ship alongside the image.
    fn signature_len(&self) -> usize;

    /// Authenticate `image` against `public_key`.
    fn verify(&self, public_key: &[u8], image: &[u8], signature: &[u8]) -> Result<(), Self::Error>;
}

/// LMS as a boot verifier.
///
/// Carrying the parameter sets at runtime rather than as const generics is a
/// deliberate simplification: it costs two words of RAM and buys the ability to
/// hold several parameter sets in one table, which is what a device supporting
/// more than one signing key ends up needing. A const-generic version is the
/// obvious refinement if those two words ever matter.
#[derive(Clone, Copy, Debug)]
pub struct LmsBootVerifier {
    /// LM-OTS parameter set.
    pub ots: LmotsParams,
    /// LMS parameter set.
    pub lms: LmsParams,
}

impl LmsBootVerifier {
    /// Build a verifier for the given parameter sets.
    pub const fn new(ots: LmotsParams, lms: LmsParams) -> Self {
        Self { ots, lms }
    }
}

impl BootVerifier for LmsBootVerifier {
    type Error = lms_verify::Error;

    fn public_key_len(&self) -> usize {
        lms_verify::PUBLIC_KEY_LEN
    }

    fn signature_len(&self) -> usize {
        lms_verify::signature_len(&self.ots, &self.lms)
    }

    fn verify(&self, pk: &[u8], image: &[u8], sig: &[u8]) -> Result<(), Self::Error> {
        lms_verify::verify(pk, image, sig)
    }
}
