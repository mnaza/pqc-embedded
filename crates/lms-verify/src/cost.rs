//! Exactly how much work verifying a given signature costs.
//!
//! # Why this is a module and not a comment
//!
//! Boot has a time budget as surely as it has a flash budget, and it is the one
//! constraint that gets waved at rather than counted. "Verification takes a few
//! milliseconds" is not a budget; the number an architect needs is the **worst
//! case**, because that is what has to fit before a watchdog fires or a user
//! notices.
//!
//! LMS makes this interesting, because the cost is **not constant**. Each of the
//! `p` Winternitz chains is walked from its coefficient `a` up to `2^w - 1`, so a
//! signature whose coefficients happen to be small costs far more to verify than
//! one whose coefficients are large. The coefficients come from
//! `Q = H(I || q || D_MESG || C || message)`, so they change with every message.
//!
//! # This leaks nothing
//!
//! A signature that takes longer to verify is not a signature that revealed a
//! secret. Every input to the timing — the message, the signature, the public key
//! — is public, and the verifier holds no secret at all. The variation is a
//! **scheduling** property, not a side channel. It belongs in a boot-time budget,
//! not in a threat model.
//!
//! That distinction is the whole reason to measure it rather than reach for a
//! constant-time countermeasure: padding verification to its worst case would cost
//! roughly twice the average boot time to defend against nothing.
//!
//! # Units
//!
//! Cost is reported in **SHA-256 compression function calls**, not in seconds or
//! cycles. Compressions are exact and architecture-independent; time is neither.
//! Multiply by whatever one compression costs on the part in hand — for a software
//! SHA-256 on Cortex-M4 that is on the order of a thousand cycles, and for a
//! hardware hash engine it is a small fraction of that.

use crate::params::*;
use crate::{u32_be, Error, Sha256Backend};

/// SHA-256 compressions needed to hash `len` bytes.
///
/// One block for the data, plus the padding: a `0x80` byte and a 64-bit length
/// that must fit in the final block, so a message ending within 8 bytes of a block
/// boundary costs an extra one.
pub const fn compressions(len: usize) -> usize {
    (len + 8) / 64 + 1
}

/// A breakdown of verification cost, in SHA-256 compressions.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Cost {
    /// Hashing the message into `Q`. Grows with message length.
    pub message: usize,
    /// Walking the `p` Winternitz chains. **The variable part, and the dominant one.**
    pub chains: usize,
    /// Folding the chain outputs into the LM-OTS public key candidate `Kc`.
    pub public_key: usize,
    /// The leaf hash plus the climb up the Merkle path.
    pub tree: usize,
}

impl Cost {
    /// Total compressions.
    pub const fn total(&self) -> usize {
        self.message + self.chains + self.public_key + self.tree
    }
}

/// Cost of the fixed parts — everything except the chains.
fn fixed_cost(ots: &LmotsParams, lms: &LmsParams, msg_len: usize) -> Cost {
    Cost {
        // I || u32str(q) || u16str(D_MESG) || C || message
        message: compressions(I_LEN + 4 + 2 + N + msg_len),
        chains: 0,
        // I || u32str(q) || u16str(D_PBLC) || z[0..p]
        public_key: compressions(I_LEN + 4 + 2 + N * ots.p),
        // one leaf hash of I || u32str || u16str || Kc, then h interior nodes
        tree: compressions(I_LEN + 4 + 2 + N)
            + lms.h as usize * compressions(I_LEN + 4 + 2 + 2 * N),
    }
}

/// The exact cost of verifying this particular signature.
///
/// Computes `Q` — one hash — and reads the coefficients from it, so this is cheap
/// relative to the verification it is predicting. Returns the same parse errors
/// [`crate::verify`] would.
pub fn verification_cost_with<H: Sha256Backend>(
    h: &mut H,
    public_key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<Cost, Error> {
    if public_key.len() != crate::PUBLIC_KEY_LEN {
        return Err(Error::BadLength);
    }
    let lms = LmsParams::from_typecode(u32_be(&public_key[0..4]))?;
    let ots = LmotsParams::from_typecode(u32_be(&public_key[4..8]))?;
    let id = &public_key[8..8 + I_LEN];

    let ots_len = ots.sig_len();
    if sig.len() != 4 + ots_len + 4 + N * lms.h as usize {
        return Err(Error::BadLength);
    }
    let q = u32_be(&sig[0..4]);
    if u64::from(q) >= lms.capacity() {
        return Err(Error::BadIndex);
    }
    let c = &sig[8..8 + N];

    h.init();
    h.update(id);
    h.update(&q.to_be_bytes());
    h.update(&D_MESG.to_be_bytes());
    h.update(c);
    h.update(msg);
    let mut qh = [0u8; N];
    h.finish(&mut qh);

    let mut qc = [0u8; N + 2];
    qc[..N].copy_from_slice(&qh);
    qc[N..].copy_from_slice(&crate::checksum(&qh, &ots).to_be_bytes());

    let last = ots.chain_len();
    let mut chains = 0usize;
    for i in 0..ots.p {
        // Each chain step hashes I || u32str(q) || u16str(i) || u8str(j) || tmp,
        // which is 55 bytes and therefore exactly one compression.
        chains += (last - crate::coef(&qc, i, ots.w)) as usize;
    }

    let mut cost = fixed_cost(&ots, &lms, msg.len());
    cost.chains = chains;
    Ok(cost)
}

/// The exact cost of verifying this signature, using software SHA-256.
#[cfg(feature = "sha2")]
pub fn verification_cost(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<Cost, Error> {
    verification_cost_with(&mut crate::SoftSha256::new(), public_key, msg, sig)
}

/// Cost bounds over every signature a parameter set can produce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bounds {
    /// Cheapest possible verification. Requires every coefficient at its maximum.
    pub min: usize,
    /// Cost at the mean coefficient value. What a benchmark will show.
    pub typical: usize,
    /// **The number a boot-time budget has to use.**
    pub max: usize,
}

/// Best, mean and worst case for a parameter set and message length.
///
/// # Where the numbers come from
///
/// Write `a_i` for the `i`-th coefficient of `Q || Cksm(Q)`. Chain work is
/// `sum_i (2^w - 1 - a_i)`.
///
/// For the `n*8/w` coefficients that come from `Q` this sum is, by construction,
/// exactly the checksum `Cksm(Q)` before its left shift — the checksum *is* the
/// message part of the chain work. The remaining coefficients come from the
/// checksum itself, and their contribution shrinks as the message part grows,
/// which is precisely the property that stops an attacker raising coefficients for
/// free.
///
/// The bounds follow: `min` when every `a_i` is `2^w - 1`, `max` when every
/// coefficient of `Q` is zero, and `typical` at the mean of a uniform coefficient,
/// which is what a hash output gives.
///
/// `max` is a genuine worst case, not a percentile, and it is astronomically
/// improbable — it needs `Q` to be all zeros. It is still the right number for a
/// hard real-time bound. For a soft budget, use the measured distribution in
/// `crates/lms-verify/examples/cost_distribution.rs`, which reports percentiles.
pub fn bounds(ots: &LmotsParams, lms: &LmsParams, msg_len: usize) -> Bounds {
    let fixed = fixed_cost(ots, lms, msg_len).total();
    let last = ots.chain_len() as usize;
    let msg_coefs = (N * 8) / ots.w as usize;
    let cks_coefs = ots.p - msg_coefs;

    // Every coefficient maximal: no chain work from the message, and the checksum
    // is then zero, so its own coefficients are maximal too.
    let min = fixed;

    // Every message coefficient zero: full chain work, and the checksum is at its
    // largest, so the checksum coefficients cost the least.
    let max_msg_work = msg_coefs * last;
    let max = fixed + max_msg_work + cks_coefs * last - max_checksum_saving(ots);

    // Uniform coefficients average (2^w - 1) / 2 of work each.
    let typical = fixed + ots.p * last / 2;

    Bounds { min, typical, max }
}

/// Chain work the checksum coefficients save when the checksum is at its maximum.
fn max_checksum_saving(ots: &LmotsParams) -> usize {
    let msg_coefs = (N * 8) / ots.w as usize;
    let last = ots.chain_len() as usize;
    // Largest possible checksum, before the shift, is every message coefficient
    // contributing its maximum.
    let s = (msg_coefs * last) << ots.ls;
    let mut saving = 0usize;
    let cks_coefs = ots.p - msg_coefs;
    let bytes = (s as u16).to_be_bytes();
    for i in 0..cks_coefs {
        saving += crate::coef(&bytes, i, ots.w) as usize;
    }
    saving
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_signer::TestKey;

    #[test]
    fn compressions_matches_the_sha256_padding_rule() {
        assert_eq!(compressions(0), 1);
        assert_eq!(compressions(55), 1); // 55 + 1 + 8 = 64, still one block
        assert_eq!(compressions(56), 2); // length no longer fits
        assert_eq!(compressions(64), 2);
        assert_eq!(compressions(119), 2);
        assert_eq!(compressions(120), 3);
    }

    #[test]
    fn the_model_matches_a_counted_verification_exactly() {
        // The test that makes the module worth having: predict the cost, then
        // count what verification actually does, and require they agree. An
        // arithmetic model of a hot loop is worthless if nobody checks it against
        // the loop.
        for (ots, lms) in [
            (LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H5),
            (LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H5),
        ] {
            let key = TestKey::generate(ots, lms, [9u8; I_LEN]);
            let pk = key.public_key();
            for (q, msg) in [(0u32, &b"a"[..]), (1, &b""[..]), (2, &[7u8; 300][..])] {
                let sig = key.sign(q, msg);
                let predicted = verification_cost(&pk, msg, &sig).unwrap();
                let counted = crate::count_compressions(&pk, msg, &sig).unwrap();
                assert_eq!(
                    predicted.total(),
                    counted,
                    "w={} h={} q={q} msg_len={}",
                    ots.w,
                    lms.h,
                    msg.len()
                );
            }
        }
    }

    #[test]
    fn real_signatures_land_inside_the_bounds() {
        let (ots, lms) = (LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H5);
        let key = TestKey::generate(ots, lms, [3u8; I_LEN]);
        let pk = key.public_key();
        let msg = b"firmware";
        let b = bounds(&ots, &lms, msg.len());
        assert!(b.min < b.typical && b.typical < b.max);

        for q in 0..8u32 {
            let cost = verification_cost(&pk, msg, &key.sign(q, msg))
                .unwrap()
                .total();
            assert!(cost >= b.min && cost <= b.max, "{cost} outside {b:?}");
        }
    }

    #[test]
    fn the_chains_dominate_and_the_message_does_not() {
        let (ots, lms) = (LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H5);
        let key = TestKey::generate(ots, lms, [4u8; I_LEN]);
        let pk = key.public_key();

        let short = key.sign(0, b"x");
        let cost = verification_cost(&pk, b"x", &short).unwrap();
        assert!(
            cost.chains > 10 * (cost.public_key + cost.tree),
            "chains {} should dominate: {cost:?}",
            cost.chains
        );

        // A 64 KB image costs about 1024 more compressions than a 1-byte one, and
        // that is the only part of verification that scales with image size. Worth
        // asserting because it is the intuition people get wrong: the signature
        // scheme is not what makes verifying a large image slow.
        let big = vec![0u8; 65536];
        let c_big = fixed_cost(&ots, &lms, big.len());
        let c_small = fixed_cost(&ots, &lms, 1);
        assert_eq!(c_big.message - c_small.message, 1024);
    }

    #[test]
    fn w4_costs_more_compressions_than_w8_for_the_same_tree() {
        // w=4 is 67 chains of 15; w=8 is 34 chains of 255. The trade is signature
        // size against verification work, and it goes the way the RFC says.
        let b4 = bounds(&LMOTS_SHA256_N32_W4, &LMS_SHA256_M32_H5, 32);
        let b8 = bounds(&LMOTS_SHA256_N32_W8, &LMS_SHA256_M32_H5, 32);
        assert!(
            b8.typical > b4.typical * 4,
            "w8 {} w4 {}",
            b8.typical,
            b4.typical
        );
    }
}
