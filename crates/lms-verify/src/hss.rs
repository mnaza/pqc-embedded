//! HSS — the hierarchical scheme built on LMS. Verification only, `no_std`, no
//! allocator. RFC 8554 §6.
//!
//! # Why a hierarchy exists at all
//!
//! A single LMS tree with `h = 25` can sign 33 million messages, and generating
//! its public key costs 33 million leaf computations — every one of which walks
//! `p` hash chains. That is hours of work before the key can be used, and it has
//! to be redone from scratch if the key is lost.
//!
//! HSS chains trees instead. A small root tree signs the public key of a second
//! tree, which signs messages. Capacity multiplies (`2^h1 * 2^h2`) while key
//! generation stays proportional to one small tree: the lower trees are generated
//! on demand as the upper ones are consumed.
//!
//! **This is what deployments actually use**, which is why RFC 8554 publishes its
//! test vectors as HSS rather than bare LMS.
//!
//! # What the verifier does
//!
//! Walks the chain. Each level's signature authenticates the *next level's public
//! key*; the last authenticates the message. So verification is `L` ordinary LMS
//! verifications where the message for all but the last is 56 bytes of public key.
//!
//! Two consequences worth stating, because both surprise people:
//!
//! - **Cost is linear in the number of levels.** A two-level HSS verification costs
//!   twice a single LMS one, near enough — the intermediate messages are tiny, so
//!   the chain walks dominate at every level. The boot-time budget in
//!   [`crate::cost`] must be multiplied accordingly.
//! - **The verifier learns the intermediate public keys from the signature itself.**
//!   It only ever trusts the root. Nothing else needs provisioning, which is what
//!   keeps the OTP requirement identical to bare LMS.

use crate::{u32_be, Error, Sha256Backend};

/// Largest number of levels this verifier will walk.
///
/// RFC 8554 permits 1 to 8. The bound is enforced rather than assumed because the
/// level count comes out of the *signature* as well as the public key, and an
/// unbounded loop driven by attacker-supplied data is the classic way a parser
/// becomes a denial of service.
pub const MAX_LEVELS: usize = 8;

/// Minimum bytes of an HSS public key: `u32str(L) || pub[0]`.
pub const PUBLIC_KEY_LEN: usize = 4 + crate::PUBLIC_KEY_LEN;

/// Verify an HSS signature.
///
/// `public_key` is `u32str(L) || pub[0]` — the level count followed by the root
/// tree's ordinary LMS public key.
///
/// A bare LMS public key is **not** accepted here, and an HSS one is not accepted
/// by [`crate::verify`]. The four-byte difference between them is exactly the kind
/// of confusion that turns into an authentication bypass, so each function rejects
/// the other's encoding on length alone.
pub fn verify_with<H: Sha256Backend>(
    h: &mut H,
    public_key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(Error::BadLength);
    }
    let levels = u32_be(&public_key[0..4]) as usize;
    if levels == 0 || levels > MAX_LEVELS {
        return Err(Error::BadLevels);
    }

    if sig.len() < 4 {
        return Err(Error::BadLength);
    }
    let nspk = u32_be(&sig[0..4]) as usize;
    // The level count is stated twice, in the key and in the signature. They must
    // agree: a signature claiming fewer levels than the key would otherwise let an
    // intermediate key be presented as if it were the root.
    if nspk + 1 != levels {
        return Err(Error::BadLevels);
    }

    let mut key_offset = 4usize; // into `public_key`, for the root
    let mut key_is_root = true;
    let mut at = 4usize; // into `sig`, past Nspk

    for _ in 0..nspk {
        let signed_len = crate::declared_signature_len(&sig[at..])?;
        let this_sig = &sig[at..at + signed_len];
        at += signed_len;

        // The message this signature authenticates is the next level's public key,
        // which sits immediately after it in the buffer.
        if sig.len() < at + crate::PUBLIC_KEY_LEN {
            return Err(Error::BadLength);
        }
        let next_key = &sig[at..at + crate::PUBLIC_KEY_LEN];

        let signer = if key_is_root {
            &public_key[key_offset..]
        } else {
            &sig[key_offset..key_offset + crate::PUBLIC_KEY_LEN]
        };
        crate::verify_with(h, signer, next_key, this_sig)?;

        key_offset = at;
        key_is_root = false;
        at += crate::PUBLIC_KEY_LEN;
    }

    let signer = if key_is_root {
        &public_key[key_offset..]
    } else {
        &sig[key_offset..key_offset + crate::PUBLIC_KEY_LEN]
    };
    let final_len = crate::declared_signature_len(&sig[at..])?;
    if at + final_len != sig.len() {
        // Trailing bytes are rejected rather than ignored. A verifier that accepts
        // a signature with junk appended lets the same signature be presented in
        // more than one encoding, which breaks anything that deduplicates or
        // caches on the signature bytes.
        return Err(Error::BadLength);
    }
    crate::verify_with(h, signer, msg, &sig[at..])
}

/// Verify an HSS signature using software SHA-256.
#[cfg(feature = "sha2")]
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    verify_with(&mut crate::SoftSha256::new(), public_key, msg, sig)
}

/// Levels an HSS public key declares, without verifying anything.
pub fn levels(public_key: &[u8]) -> Result<usize, Error> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(Error::BadLength);
    }
    let l = u32_be(&public_key[0..4]) as usize;
    if l == 0 || l > MAX_LEVELS {
        return Err(Error::BadLevels);
    }
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::*;
    use crate::test_signer::TestKey;

    /// Build a two-level HSS key pair out of two LMS trees.
    fn two_level() -> (Vec<u8>, TestKey, TestKey) {
        let root = TestKey::generate(LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H5, [1u8; I_LEN]);
        let leaf = TestKey::generate(LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H5, [2u8; I_LEN]);
        let mut pk = Vec::new();
        pk.extend_from_slice(&2u32.to_be_bytes());
        pk.extend_from_slice(&root.public_key());
        (pk, root, leaf)
    }

    fn two_level_sig(root: &TestKey, leaf: &TestKey, q0: u32, q1: u32, msg: &[u8]) -> Vec<u8> {
        let leaf_pk = leaf.public_key();
        let mut sig = Vec::new();
        sig.extend_from_slice(&1u32.to_be_bytes()); // Nspk
        sig.extend_from_slice(&root.sign(q0, &leaf_pk));
        sig.extend_from_slice(&leaf_pk);
        sig.extend_from_slice(&leaf.sign(q1, msg));
        sig
    }

    #[test]
    fn a_two_level_signature_verifies() {
        let (pk, root, leaf) = two_level();
        let msg = b"firmware image";
        let sig = two_level_sig(&root, &leaf, 0, 0, msg);
        assert_eq!(verify(&pk, msg, &sig), Ok(()));
        assert_eq!(levels(&pk), Ok(2));
    }

    #[test]
    fn tampering_at_either_level_is_caught() {
        let (pk, root, leaf) = two_level();
        let msg = b"firmware image";
        let good = two_level_sig(&root, &leaf, 1, 2, msg);
        assert_eq!(verify(&pk, msg, &good), Ok(()));

        // In the root tree's signature over the intermediate key.
        let mut bad = good.clone();
        bad[20] ^= 0x01;
        assert_eq!(verify(&pk, msg, &bad), Err(Error::Invalid));

        // In the intermediate public key itself: it stops matching what the root
        // signed, so the failure lands at level 0, not at level 1.
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - crate::signature_len(&LMOTS_SHA256_N32_W4, &LMS_SHA256_M32_H5) - 10] ^= 0x01;
        assert_eq!(verify(&pk, msg, &bad), Err(Error::Invalid));

        // In the final signature over the message.
        let mut bad = good;
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert_eq!(verify(&pk, msg, &bad), Err(Error::Invalid));
    }

    #[test]
    fn an_intermediate_key_cannot_be_promoted_to_root() {
        // The attack the Nspk-versus-levels check exists to stop: take the
        // intermediate key, present it as a one-level HSS public key, and reuse the
        // final signature. It must fail, because the verifier was provisioned with
        // the root and only the root.
        let (pk, root, leaf) = two_level();
        let msg = b"firmware image";
        let sig = two_level_sig(&root, &leaf, 0, 0, msg);

        // The genuine key accepts it, so the failure below is about the key and
        // not about a signature that was broken to begin with.
        assert_eq!(verify(&pk, msg, &sig), Ok(()));

        let mut forged_pk = Vec::new();
        forged_pk.extend_from_slice(&1u32.to_be_bytes());
        forged_pk.extend_from_slice(&leaf.public_key());
        assert_eq!(verify(&forged_pk, msg, &sig), Err(Error::BadLevels));

        // And the same forgery with the level count left at 2, so it is the
        // cryptography rather than the level check that has to reject it: the
        // intermediate key never signed the intermediate key.
        let mut forged_pk = Vec::new();
        forged_pk.extend_from_slice(&2u32.to_be_bytes());
        forged_pk.extend_from_slice(&leaf.public_key());
        assert_eq!(verify(&forged_pk, msg, &sig), Err(Error::Invalid));
    }

    #[test]
    fn hss_and_lms_public_keys_are_not_interchangeable() {
        let (pk, root, leaf) = two_level();
        let msg = b"x";
        let sig = two_level_sig(&root, &leaf, 0, 0, msg);

        // An HSS key handed to the LMS verifier: four bytes too long.
        assert_eq!(crate::verify(&pk, msg, &sig), Err(Error::BadLength));
        // A bare LMS key handed to the HSS verifier: four bytes too short.
        assert_eq!(verify(&root.public_key(), msg, &sig), Err(Error::BadLength));
    }

    #[test]
    fn trailing_bytes_are_rejected_not_ignored() {
        let (pk, root, leaf) = two_level();
        let msg = b"x";
        let mut sig = two_level_sig(&root, &leaf, 0, 0, msg);
        sig.push(0);
        assert_eq!(verify(&pk, msg, &sig), Err(Error::BadLength));
    }

    #[test]
    fn a_truncated_signature_does_not_panic() {
        let (pk, root, leaf) = two_level();
        let msg = b"x";
        let good = two_level_sig(&root, &leaf, 0, 0, msg);
        for cut in [0, 1, 4, 5, 100, 1000, good.len() - 1] {
            let r = verify(&pk, msg, &good[..cut.min(good.len())]);
            assert!(r.is_err(), "truncation to {cut} verified");
        }
    }

    #[test]
    fn absurd_level_counts_are_rejected_before_any_work() {
        let (_, root, leaf) = two_level();
        let msg = b"x";
        let sig = two_level_sig(&root, &leaf, 0, 0, msg);

        for l in [0u32, 9, 1000, u32::MAX] {
            let mut pk = Vec::new();
            pk.extend_from_slice(&l.to_be_bytes());
            pk.extend_from_slice(&root.public_key());
            assert_eq!(verify(&pk, msg, &sig), Err(Error::BadLevels), "levels={l}");
        }
    }
}
