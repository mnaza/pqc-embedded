//! The SHA-256 interface the verifier is written against.
//!
//! # Why this is a trait and not a `use sha2::Sha256`
//!
//! LMS verification is, to a first approximation, nothing but SHA-256 calls: over
//! 99% of the work at every parameter set. So the hash implementation is not a
//! detail of this crate — it *is* this crate's performance, and on real silicon it
//! is usually not software.
//!
//! Most parts that do secure boot ship a hash accelerator, because image integrity
//! needed one before signatures did. Being unable to use it would be an odd thing
//! for a library aimed at those parts. Hence a trait: the caller supplies whatever
//! the hardware offers, and the verifier does not care.
//!
//! This is also the shape a platform-independent library has to have. There is no
//! version of "runs on ARM, RISC-V and whatever the customer has" that hardcodes
//! one software implementation.
//!
//! # Why the caller owns the hasher
//!
//! The obvious signature — `trait Hasher { fn new() -> Self; }` — cannot express a
//! hardware peripheral, which is a borrowed singleton rather than something you
//! construct at will. So the caller passes `&mut` to a backend it already owns, and
//! the verifier borrows it for the duration. That costs an argument and buys the
//! ability to run on the peripheral at all.
//!
//! # Why there is a checkpoint
//!
//! LMS verification needs **two digests in flight at once**: the `Kc` hash
//! accumulates each chain output as it is produced, and producing one takes
//! hundreds of hashes of its own. Software can hold two contexts. A hash
//! *peripheral* has one.
//!
//! An earlier design resolved that by buffering every chain output and hashing the
//! lot at the end, which cost the caller `p * 32` bytes — 1088 at `w = 8`. But the
//! ESP32 SHA peripheral can checkpoint its own state, and `sha2::Sha256` is
//! `Clone`, so both kinds of backend can do the thing the buffer was standing in
//! for. [`Sha256Backend::save`] and [`Sha256Backend::restore`] make it explicit, the
//! buffer is gone, and there is still only one code path through the verifier.
//!
//! The saved state is a couple of hundred bytes against the buffer's kilobyte, and
//! it is saved and restored `p` times per verification — 34 at `w = 8` — against
//! the four thousand digests the verification performs anyway.
//!
//! # Contract
//!
//! [`Sha256Backend::init`] must reset any partial state, so one backend can be
//! reused across the thousands of hashes a single verification performs.
//! Implementations that cannot be reset should reset in `init` rather than
//! surprising the caller.
//!
//! A backend may be `init`ed, used and finished any number of times between a
//! [`save`](Sha256Backend::save) and the matching
//! [`restore`](Sha256Backend::restore). That is the whole point: the chain hashes
//! happen in between.

/// A SHA-256 implementation the verifier can drive.
pub trait Sha256Backend {
    /// Opaque saved state of a digest in progress.
    ///
    /// `Default` so the verifier can create one without knowing what it is.
    type Checkpoint: Default;

    /// Begin a new digest, discarding any state from a previous one.
    fn init(&mut self);

    /// Absorb more input. Called many times per digest.
    fn update(&mut self, data: &[u8]);

    /// Produce the digest and leave the backend ready for [`Self::init`].
    fn finish(&mut self, out: &mut [u8; 32]);

    /// Capture the digest in progress so the backend can be used for something
    /// else and the digest resumed later.
    fn save(&mut self, into: &mut Self::Checkpoint);

    /// Resume a digest captured by [`Self::save`], discarding whatever the backend
    /// was doing.
    ///
    /// Takes `&mut` rather than `&` because a hardware backend restores by handing
    /// the saved words back to the peripheral, which the driver expresses as a
    /// mutable borrow.
    fn restore(&mut self, from: &mut Self::Checkpoint);
}

/// SHA-256 in software, from the `sha2` crate.
///
/// The default, and the right choice on a part with no hash engine. Available
/// unless the `sha2` feature is switched off, which a firmware using a hardware
/// backend should do — otherwise the software implementation is linked in
/// alongside and pays for itself in flash while never running.
#[cfg(feature = "sha2")]
#[derive(Default, Clone)]
pub struct SoftSha256(sha2::Sha256);

#[cfg(feature = "sha2")]
impl SoftSha256 {
    /// A fresh backend.
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "sha2")]
impl Sha256Backend for SoftSha256 {
    /// A whole `sha2::Sha256`. Cloning it is the entire implementation, which is
    /// why software never needed the buffer the hardware constraint imposed.
    type Checkpoint = sha2::Sha256;

    fn init(&mut self) {
        sha2::Digest::reset(&mut self.0);
    }

    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.0.update(data);
    }

    fn finish(&mut self, out: &mut [u8; 32]) {
        use sha2::Digest;
        out.copy_from_slice(&self.0.finalize_reset());
    }

    fn save(&mut self, into: &mut Self::Checkpoint) {
        into.clone_from(&self.0);
    }

    fn restore(&mut self, from: &mut Self::Checkpoint) {
        self.0.clone_from(from);
    }
}
