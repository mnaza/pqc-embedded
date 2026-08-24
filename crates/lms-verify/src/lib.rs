//! LMS signature **verification** — RFC 8554, `no_std`, no allocator.
//!
//! # Scope, and why it is this narrow
//!
//! This crate verifies. It does not sign and it does not generate keys.
//!
//! That is not a limitation, it is the point. A device performing secure boot only
//! ever verifies: the signing key lives in a build system or an HSM, and the part
//! that ships in ROM is the verifier. Verification-only is a fraction of the code,
//! carries no secret state, and — see below — has no meaningful timing surface.
//!
//! # Why LMS rather than ML-DSA for boot
//!
//! LMS is hash-based. Its security rests on the hash function alone: no lattices,
//! no rejection sampling, no NTT, no large constant tables. On a part with tens of
//! kilobytes of flash that difference decides whether a scheme fits at all. NIST
//! SP 800-208 approves LMS and XMSS for exactly this use, and the stateful-key
//! restriction that makes them awkward for general signing is a non-issue for
//! firmware, where a build system signs a countable number of images.
//!
//! # Constant time
//!
//! **Verification handles no secrets.** The message, the signature, the public key
//! and every intermediate are public values. There is therefore nothing here for a
//! timing attack to recover, and the byte comparison at the end is an ordinary
//! comparison on purpose — see [`verify`].
//!
//! This is worth stating explicitly rather than reaching for a constant-time
//! primitive reflexively. "Constant time" means *secret-independent* control flow
//! and memory access. Where there is no secret, the property is vacuous, and code
//! that pretends otherwise obscures where the real requirement lives. The signer,
//! which does hold secrets, is a different problem and is not in this crate.
//!
//! Verification time **does** vary with its inputs, by a wide margin, and
//! `examples/timing_evidence.rs` puts a leakage detector on it and measures
//! `|t| > 400` to prove the point rather than assert it. That is a fact about
//! scheduling, not a finding about security: the inputs whose timing it reveals
//! are the attacker's own. The variation belongs in a boot-time budget — see
//! [`cost`] — and padding it away would roughly double average boot time to defend
//! against nothing.
//!
//! # Allocation
//!
//! None, and no caller-supplied scratch either. The `p` chain outputs and the `h`
//! path nodes are never materialised: each is folded into the running hash as it
//! is produced, with the `Kc` digest parked across each chain via
//! [`Sha256Backend::save`]. Peak working set is one SHA-256 state, one saved state,
//! and a handful of 32-byte buffers — independent of `p`, `h` and message length.
//!
//! # Status
//!
//! **Checked against the RFC 8554 Appendix F vectors.** Both published test
//! cases are taken apart into their constituent bare-LMS signatures and verified,
//! covering H5/W8 and H10/W4, alongside negative vectors for tampering,
//! truncation, index and typecode errors. See `tests/kat.rs`.
//!
//! **Not audited.** Conformance to published vectors is a much weaker property
//! than review: it says the happy path and the tested failure paths behave, not
//! that there is no input that misbehaves. Do not put this in a product.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cost;
pub mod hasher;
pub mod hss;
pub mod params;
pub use hasher::Sha256Backend;
#[cfg(feature = "sha2")]
pub use hasher::SoftSha256;
pub use params::*;

#[cfg(test)]
mod test_signer;

/// Why a verification was rejected.
///
/// The distinction between a malformed signature and a well-formed one that does
/// not verify is deliberate: a bootloader wants to log them differently. A parse
/// failure means a corrupt or truncated image; [`Error::Invalid`] means the image
/// is intact and was not signed by the expected key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A buffer did not have the length the parameter set requires.
    BadLength,
    /// The LM-OTS typecode is not one this crate implements.
    UnknownLmotsType,
    /// The LMS typecode is not one this crate implements.
    UnknownLmsType,
    /// Typecodes in the public key and the signature disagree.
    TypeMismatch,
    /// The leaf index `q` is outside the tree.
    BadIndex,
    /// Everything parsed, and the computed root did not match the public key.
    Invalid,
    /// An HSS level count is zero, above [`hss::MAX_LEVELS`], or disagrees
    /// between the public key and the signature.
    BadLevels,
}

/// Byte length of an LMS public key: `u32str(type) || u32str(otstype) || I || T[1]`.
pub const PUBLIC_KEY_LEN: usize = 4 + 4 + I_LEN + N;

// Counts SHA-256 compressions during verification, in test builds only.
// Thread-local so that tests running in parallel cannot corrupt each other's
// counts. Compiles to nothing outside `cfg(test)`.
#[cfg(test)]
thread_local! {
    static COMPRESSIONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Record that a hash over `len` bytes is about to happen.
///
/// Placed at the real hash sites inside [`verify`], so what it measures is the
/// **actual control flow** — how many chain steps, how many path nodes — rather
/// than a second copy of the arithmetic. The per-hash block count still comes from
/// [`cost::compressions`], which is unit-tested against the SHA-256 padding rule
/// on its own, so the two are not circular.
#[inline(always)]
fn note_hash(_len: usize) {
    #[cfg(test)]
    COMPRESSIONS.with(|c| c.set(c.get() + cost::compressions(_len)));
}

/// Verify, and report how many SHA-256 compressions it took. Tests only.
#[cfg(test)]
pub(crate) fn count_compressions(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<usize, Error> {
    COMPRESSIONS.with(|c| c.set(0));
    verify(pk, msg, sig)?;
    Ok(COMPRESSIONS.with(|c| c.get()))
}

fn u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// `coef(S, i, w)` — the `i`-th `w`-bit field of `S`, RFC 8554 §3.1.3.
///
/// `#[inline(always)]` here is a measured decision, not a decoration.
///
/// Once [`cost`] gained a second call site, LLVM at `opt-level = "z"` stopped
/// inlining this and emitted a real function — reasonably, since outlining a
/// shared helper is usually the size-optimal choice. Forcing it back inline moves
/// the four targets in different directions:
///
/// | target | outlined | inlined |
/// |---|---|---|
/// | Cortex-M0+ | 2032 | **1624** |
/// | Cortex-M4F | **1592** | 1640 |
/// | RISC-V rv32imc | **2244** | 2292 |
///
/// A 20% saving on the tightest part against 3% lost on the roomier ones, so
/// inlining wins: 408 bytes matters on a part with 16 KB of boot ROM and 48 bytes
/// does not matter on one with 64 KB. The Thumb-1 result is the interesting one —
/// no barrel shifter as a free operand makes the call overhead relatively dearer
/// than the duplicated body.
///
/// Reproduce with `size-probe/measure.sh`.
#[inline(always)]
fn coef(s: &[u8], i: usize, w: u32) -> u32 {
    let w = w as usize;
    let per_byte = 8 / w;
    let byte = s[i * w / 8] as u32;
    let shift = 8 - (w * (i % per_byte) + w);
    (byte >> shift) & ((1u32 << w) - 1)
}

/// `Cksm(S)` — RFC 8554 §4.4.
fn checksum(s: &[u8], p: &LmotsParams) -> u16 {
    let mut sum: u32 = 0;
    let fields = (N * 8) / p.w as usize;
    let max = (1u32 << p.w) - 1;
    for i in 0..fields {
        sum += max - coef(s, i, p.w);
    }
    (sum << p.ls) as u16
}

/// Algorithm 4b — recover the LM-OTS public key candidate `Kc` from a signature.
///
/// The `z[i]` are folded into the `Kc` hash as they are computed, so no array of
/// `p` chain outputs ever exists.
fn lmots_public_key_candidate<H: Sha256Backend>(
    h: &mut H,
    id: &[u8; I_LEN],
    q: u32,
    p: &LmotsParams,
    ots_sig: &[u8],
    msg: &[u8],
) -> Result<[u8; N], Error> {
    if ots_sig.len() != p.sig_len() {
        return Err(Error::BadLength);
    }
    if u32_be(&ots_sig[0..4]) != p.typecode {
        return Err(Error::TypeMismatch);
    }
    let c = &ots_sig[4..4 + N];
    let q_be = q.to_be_bytes();

    // Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
    note_hash(I_LEN + 4 + 2 + N + msg.len());
    h.init();
    h.update(id);
    h.update(&q_be);
    h.update(&D_MESG.to_be_bytes());
    h.update(c);
    h.update(msg);
    let mut qh = [0u8; N];
    h.finish(&mut qh);

    // Q || Cksm(Q)
    let mut qc = [0u8; N + 2];
    qc[..N].copy_from_slice(&qh);
    qc[N..].copy_from_slice(&checksum(&qh, p).to_be_bytes());

    // Accumulate the chain outputs into `Kc` as they are produced, parking the
    // `Kc` digest across each chain.
    //
    // Two digests are live at once here, and a hash peripheral has one context. An
    // earlier design handled that by buffering every `z[i]` into a caller-supplied
    // array — `p * 32` bytes, 1088 at `w = 8`. The checkpoint replaces it with a
    // couple of hundred bytes, saved and restored `p` times rather than once per
    // hash, and lets the caller stop thinking about scratch entirely.
    note_hash(I_LEN + 4 + 2 + N * p.p);
    h.init();
    h.update(id);
    h.update(&q_be);
    h.update(&D_PBLC.to_be_bytes());

    let mut kc_state = H::Checkpoint::default();
    h.save(&mut kc_state);

    let last = p.chain_len();
    let mut tmp = [0u8; N];
    for i in 0..p.p {
        let a = coef(&qc, i, p.w);
        tmp.copy_from_slice(&ots_sig[4 + N * (i + 1)..4 + N * (i + 2)]);
        let mut j = a;
        while j < last {
            note_hash(I_LEN + 4 + 2 + 1 + N);
            h.init();
            h.update(id);
            h.update(&q_be);
            h.update(&(i as u16).to_be_bytes());
            h.update(&[j as u8]);
            h.update(&tmp);
            h.finish(&mut tmp);
            j += 1;
        }
        h.restore(&mut kc_state);
        h.update(&tmp);
        h.save(&mut kc_state);
    }

    h.restore(&mut kc_state);
    let mut kc = [0u8; N];
    h.finish(&mut kc);
    Ok(kc)
}

/// Verify an LMS signature with a caller-supplied SHA-256 backend.
///
/// `public_key` is the [`PUBLIC_KEY_LEN`]-byte encoding from RFC 8554 §5.3.
///
/// # Timing
///
/// The final comparison is `==`, not a constant-time compare, and that is
/// deliberate. Both operands are public: the root recomputed from the signature,
/// and the root published in the key. There is no secret whose recovery an early
/// exit could accelerate. Using a constant-time compare here would suggest a
/// secret exists and invite a reader to stop looking for where one actually does.
pub fn verify_with<H: Sha256Backend>(
    h: &mut H,
    public_key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(Error::BadLength);
    }
    let lms_type = u32_be(&public_key[0..4]);
    let ots_type = u32_be(&public_key[4..8]);
    let lms = LmsParams::from_typecode(lms_type)?;
    let ots = LmotsParams::from_typecode(ots_type)?;

    let mut id = [0u8; I_LEN];
    id.copy_from_slice(&public_key[8..8 + I_LEN]);
    let root = &public_key[8 + I_LEN..];

    let ots_len = ots.sig_len();
    if sig.len() != 4 + ots_len + 4 + N * lms.h as usize {
        return Err(Error::BadLength);
    }

    let q = u32_be(&sig[0..4]);
    if u64::from(q) >= lms.capacity() {
        return Err(Error::BadIndex);
    }
    let ots_sig = &sig[4..4 + ots_len];
    if u32_be(&sig[4 + ots_len..8 + ots_len]) != lms_type {
        return Err(Error::TypeMismatch);
    }
    let path = &sig[8 + ots_len..];

    let kc = lmots_public_key_candidate(h, &id, q, &ots, ots_sig, msg)?;

    // Algorithm 6a — climb from the leaf to the root, one 32-byte buffer.
    let mut node = (1u32 << lms.h) + q;
    let mut tmp = [0u8; N];
    note_hash(I_LEN + 4 + 2 + N);
    h.init();
    h.update(&id);
    h.update(&node.to_be_bytes());
    h.update(&D_LEAF.to_be_bytes());
    h.update(&kc);
    h.finish(&mut tmp);

    let mut i = 0usize;
    while node > 1 {
        let sibling = &path[i * N..(i + 1) * N];
        note_hash(I_LEN + 4 + 2 + 2 * N);
        h.init();
        h.update(&id);
        h.update(&(node / 2).to_be_bytes());
        h.update(&D_INTR.to_be_bytes());
        if node % 2 == 1 {
            h.update(sibling);
            h.update(&tmp);
        } else {
            h.update(&tmp);
            h.update(sibling);
        }
        h.finish(&mut tmp);
        node /= 2;
        i += 1;
    }

    if tmp[..] == *root {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

/// Verify using software SHA-256.
///
/// Convenience over [`verify_with`] for the common case. Unavailable when the
/// `sha2` feature is off, which is how a firmware with a hash accelerator keeps
/// the software implementation out of its binary entirely.
#[cfg(feature = "sha2")]
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    verify_with(&mut SoftSha256::new(), public_key, msg, sig)
}

/// Read an LMS signature's own length out of its leading bytes.
///
/// Needed to walk a buffer holding several signatures back to back, which is what
/// an HSS signature is. The length is not stored anywhere: it has to be derived
/// from the two typecodes the signature carries, one of which sits *after* the
/// LM-OTS part whose length the first typecode determines.
///
/// Returns [`Error::BadLength`] if the buffer is too short to hold what its own
/// header says it does — the check that keeps a malformed outer signature from
/// walking a caller off the end of the buffer.
pub fn declared_signature_len(sig: &[u8]) -> Result<usize, Error> {
    if sig.len() < 8 {
        return Err(Error::BadLength);
    }
    let ots = LmotsParams::from_typecode(u32_be(&sig[4..8]))?;
    let ots_len = ots.sig_len();
    if sig.len() < 4 + ots_len + 4 {
        return Err(Error::BadLength);
    }
    let lms = LmsParams::from_typecode(u32_be(&sig[4 + ots_len..8 + ots_len]))?;
    let total = 4 + ots_len + 4 + N * lms.h as usize;
    if sig.len() < total {
        return Err(Error::BadLength);
    }
    Ok(total)
}

/// Byte length of an LMS signature under the given parameter sets.
///
/// Useful for the budget arithmetic a bootloader author actually has to do:
/// this is what has to fit in flash next to the image.
pub const fn signature_len(ots: &LmotsParams, lms: &LmsParams) -> usize {
    4 + ots.sig_len() + 4 + N * lms.h as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_signer::TestKey;

    fn roundtrip(ots: LmotsParams, lms: LmsParams) {
        let key = TestKey::generate(ots, lms, [7u8; I_LEN]);
        let pk = key.public_key();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);

        for q in [0u32, 1, (lms.capacity() - 1) as u32] {
            let msg = b"firmware image v1.2.3";
            let sig = key.sign(q, msg);
            assert_eq!(sig.len(), signature_len(&ots, &lms));
            assert_eq!(verify(&pk, msg, &sig), Ok(()), "q={q}");

            // Wrong message must fail.
            assert_eq!(
                verify(&pk, b"firmware image v1.2.4", &sig),
                Err(Error::Invalid)
            );
        }
    }

    #[test]
    fn roundtrip_w8_h5() {
        roundtrip(LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H5);
    }

    #[test]
    fn roundtrip_w4_h5() {
        roundtrip(LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H5);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let key = TestKey::generate(LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H5, [1u8; I_LEN]);
        let pk = key.public_key();
        let msg = b"boot";
        let mut sig = key.sign(3, msg);
        let n = sig.len();
        sig[n - 1] ^= 0x01; // last byte of the auth path
        assert_eq!(verify(&pk, msg, &sig), Err(Error::Invalid));
    }

    #[test]
    fn malformed_inputs_do_not_panic() {
        let key = TestKey::generate(LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H5, [2u8; I_LEN]);
        let pk = key.public_key();
        let sig = key.sign(0, b"x");

        assert_eq!(verify(&pk[..10], b"x", &sig), Err(Error::BadLength));
        assert_eq!(
            verify(&pk, b"x", &sig[..sig.len() - 1]),
            Err(Error::BadLength)
        );
        assert_eq!(verify(&pk, b"x", &[]), Err(Error::BadLength));

        // Index past the end of the tree.
        let mut bad = sig.clone();
        bad[0..4].copy_from_slice(&999u32.to_be_bytes());
        assert_eq!(verify(&pk, b"x", &bad), Err(Error::BadIndex));

        // Unknown typecode in the public key.
        let mut badpk = pk.clone();
        badpk[0..4].copy_from_slice(&77u32.to_be_bytes());
        assert_eq!(verify(&badpk, b"x", &sig), Err(Error::UnknownLmsType));
    }

    #[test]
    fn a_parked_digest_survives_other_work() {
        // The property the whole design rests on: a digest saved, interrupted by
        // unrelated hashing, and restored must equal the same digest computed
        // without interruption. If this ever fails, `Kc` is being corrupted by the
        // chain hashes and every verification is wrong.
        let mut h = SoftSha256::new();

        let mut uninterrupted = [0u8; N];
        h.init();
        h.update(b"first part");
        h.update(b"second part");
        h.finish(&mut uninterrupted);

        let mut parked = [0u8; N];
        h.init();
        h.update(b"first part");
        let mut saved = <SoftSha256 as Sha256Backend>::Checkpoint::default();
        h.save(&mut saved);

        // Do exactly the kind of work a chain walk does, on the same backend.
        for i in 0..50u8 {
            let mut scratch = [0u8; N];
            h.init();
            h.update(&[i]);
            h.update(b"unrelated");
            h.finish(&mut scratch);
        }

        h.restore(&mut saved);
        h.update(b"second part");
        h.finish(&mut parked);

        assert_eq!(uninterrupted, parked);
    }

    #[test]
    fn a_checkpoint_can_be_restored_more_than_once() {
        // The verifier restores the same `Kc` state `p` times, so restoring must
        // not consume it.
        let mut h = SoftSha256::new();
        h.init();
        h.update(b"prefix");
        let mut saved = <SoftSha256 as Sha256Backend>::Checkpoint::default();
        h.save(&mut saved);

        let mut first = [0u8; N];
        h.restore(&mut saved);
        h.update(b"tail");
        h.finish(&mut first);

        let mut second = [0u8; N];
        h.restore(&mut saved);
        h.update(b"tail");
        h.finish(&mut second);

        assert_eq!(first, second);
    }

    #[test]
    fn coef_matches_rfc_example() {
        // RFC 8554 §3.1.3: for S = 0x1234, coef(S, 0, 4) = 1 and coef(S, 1, 4) = 2.
        let s = [0x12u8, 0x34];
        assert_eq!(coef(&s, 0, 4), 1);
        assert_eq!(coef(&s, 1, 4), 2);
        assert_eq!(coef(&s, 2, 4), 3);
        assert_eq!(coef(&s, 3, 4), 4);
        // And with w=8 a coefficient is just the byte.
        assert_eq!(coef(&s, 0, 8), 0x12);
        assert_eq!(coef(&s, 1, 8), 0x34);
    }

    #[test]
    fn signature_len_is_what_the_budget_table_claims() {
        // w=8, h=5: 4 + (4 + 32*35) + 4 + 32*5 = 4 + 1124 + 4 + 160 = 1292
        assert_eq!(
            signature_len(&LMOTS_SHA256_N32_W8, &LMS_SHA256_M32_H5),
            1292
        );
        // w=8, h=10: 4 + 1124 + 4 + 320 = 1452
        assert_eq!(
            signature_len(&LMOTS_SHA256_N32_W8, &LMS_SHA256_M32_H10),
            1452
        );
        // w=4, h=10: 4 + (4 + 32*68) + 4 + 32*10 = 2508
        assert_eq!(
            signature_len(&LMOTS_SHA256_N32_W4, &LMS_SHA256_M32_H10),
            2508
        );
    }
}
