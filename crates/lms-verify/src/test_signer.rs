//! A signer, for tests only.
//!
//! # Read this before trusting anything it produces
//!
//! This exists so the verifier can be exercised end-to-end without external test
//! vectors. It is **not** a signer you may use: it keeps the whole private key in
//! RAM, it has no state management, and nothing stops it signing the same leaf
//! index twice — which for a one-time signature scheme is the single fatal
//! mistake. LMS security collapses if a leaf is reused.
//!
//! It also cannot tell you the verifier is correct. A round-trip test passes if
//! signer and verifier are wrong in the same way, and since both were written
//! from the same reading of RFC 8554 that is a real possibility. Only the
//! published test vectors settle it — see `tests/kat.rs`.

use crate::params::*;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// An in-memory LMS key pair for tests.
pub struct TestKey {
    ots: LmotsParams,
    lms: LmsParams,
    id: [u8; I_LEN],
    /// `x[leaf][chain]` — the LM-OTS private values.
    x: Vec<Vec<[u8; N]>>,
    /// Merkle nodes, 1-indexed: `nodes[r]` for `r` in `1..2^(h+1)`.
    nodes: Vec<[u8; N]>,
}

impl TestKey {
    /// Generate a key. Cost is `2^h * p * (2^w - 1)` hashes — keep `h` small.
    pub fn generate(ots: LmotsParams, lms: LmsParams, id: [u8; I_LEN]) -> Self {
        let mut rng = rand::thread_rng();
        let leaves = 1usize << lms.h;
        let last = ots.chain_len();

        let mut x = Vec::with_capacity(leaves);
        let mut leaf_pubkeys = Vec::with_capacity(leaves);

        for q in 0..leaves {
            let mut xs = Vec::with_capacity(ots.p);
            let mut k = Sha256::new();
            k.update(id);
            k.update((q as u32).to_be_bytes());
            k.update(D_PBLC.to_be_bytes());

            for i in 0..ots.p {
                let mut secret = [0u8; N];
                rng.fill_bytes(&mut secret);
                xs.push(secret);
                let y = chain(&id, q as u32, i, &secret, 0, last);
                k.update(y);
            }
            x.push(xs);
            let pk: [u8; N] = k.finalize().into();
            leaf_pubkeys.push(pk);
        }

        // nodes[0] is unused so that node numbering matches the RFC.
        let mut nodes = vec![[0u8; N]; 2 * leaves];
        for (q, pk) in leaf_pubkeys.iter().enumerate() {
            let r = leaves + q;
            let mut h = Sha256::new();
            h.update(id);
            h.update((r as u32).to_be_bytes());
            h.update(D_LEAF.to_be_bytes());
            h.update(pk);
            nodes[r] = h.finalize().into();
        }
        for r in (1..leaves).rev() {
            let mut h = Sha256::new();
            h.update(id);
            h.update((r as u32).to_be_bytes());
            h.update(D_INTR.to_be_bytes());
            h.update(nodes[2 * r]);
            h.update(nodes[2 * r + 1]);
            nodes[r] = h.finalize().into();
        }

        Self {
            ots,
            lms,
            id,
            x,
            nodes,
        }
    }

    /// The RFC 8554 §5.3 public key encoding.
    pub fn public_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(crate::PUBLIC_KEY_LEN);
        out.extend_from_slice(&self.lms.typecode.to_be_bytes());
        out.extend_from_slice(&self.ots.typecode.to_be_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.nodes[1]);
        out
    }

    /// Sign `msg` with leaf `q`.
    ///
    /// Calling this twice with the same `q` breaks the scheme. Nothing here
    /// prevents it, which is precisely why this type is test-only.
    pub fn sign(&self, q: u32, msg: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut c = [0u8; N];
        rng.fill_bytes(&mut c);

        let mut h = Sha256::new();
        h.update(self.id);
        h.update(q.to_be_bytes());
        h.update(D_MESG.to_be_bytes());
        h.update(c);
        h.update(msg);
        let qh = h.finalize();

        let mut qc = [0u8; N + 2];
        qc[..N].copy_from_slice(&qh);
        qc[N..].copy_from_slice(&crate::checksum(&qh, &self.ots).to_be_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(&q.to_be_bytes());
        out.extend_from_slice(&self.ots.typecode.to_be_bytes());
        out.extend_from_slice(&c);
        for i in 0..self.ots.p {
            let a = crate::coef(&qc, i, self.ots.w);
            let y = chain(&self.id, q, i, &self.x[q as usize][i], 0, a);
            out.extend_from_slice(&y);
        }

        out.extend_from_slice(&self.lms.typecode.to_be_bytes());
        let leaves = 1u32 << self.lms.h;
        let mut node = leaves + q;
        while node > 1 {
            out.extend_from_slice(&self.nodes[(node ^ 1) as usize]);
            node /= 2;
        }
        out
    }
}

/// Apply the LM-OTS chain hash for `j` in `from..to`.
fn chain(id: &[u8; I_LEN], q: u32, i: usize, start: &[u8; N], from: u32, to: u32) -> [u8; N] {
    let mut tmp = *start;
    for j in from..to {
        let mut h = Sha256::new();
        h.update(id);
        h.update(q.to_be_bytes());
        h.update((i as u16).to_be_bytes());
        h.update([j as u8]);
        h.update(tmp);
        tmp.copy_from_slice(&h.finalize());
    }
    tmp
}
