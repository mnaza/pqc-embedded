//! First-order Boolean masking gadgets.
//!
//! # Read this first: the compiler is the adversary here
//!
//! Masking splits a secret `x` into shares `x0 ⊕ x1 = x` so that no single value
//! in the computation is correlated with the secret. The theory is sound and the
//! gadgets below are the standard ones.
//!
//! The theory assumes shares stay separate. **Nothing in Rust or LLVM promises
//! that.** The compiler is free to notice that `x0 ^ x1` is computed later and
//! rematerialise `x` in a register early; to spill both shares to adjacent stack
//! slots; to combine them in a wider vector register; or to constant-fold a whole
//! gadget when it can see the inputs. Every one of those breaks the security
//! argument while leaving the source code looking correct, and none of them shows
//! up in a functional test.
//!
//! This is a known and unsolved problem, and the usual answer in industry is to
//! stop relying on the compiler: write the masked routine in assembly, or at
//! minimum verify the disassembly of the shipped binary. A masked implementation
//! rests on what the machine code does, not on what the source says.
//!
//! What this crate does is put [`core::hint::black_box`] between the steps of each
//! gadget. That is a barrier to *optimisation*, not a security primitive: it makes
//! recombination much less likely, it is not documented to prevent it, and it
//! costs performance. It is the best available mitigation in stable safe Rust, and
//! it is not sufficient on its own.
//!
//! # Status
//!
//! **No leakage measurement has been performed on any of this.** First-order
//! probing security is claimed on the strength of the published gadget designs
//! (ISW for AND, Goubin for B→A), not on evidence from this implementation. A
//! masking implementation that has not been measured on the target hardware has
//! not been shown to do anything. Until then the correct description is "the
//! gadgets are the right gadgets", not "the implementation is masked".
//!
//! Order of work if this is taken further: measure with `ct-probe` on the target,
//! then a proper first-order leakage assessment (TVLA) on real traces, then
//! inspect the disassembly for recombination, then consider assembly.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::hint::black_box;
use rand::Rng;

/// A word that can carry a Boolean or arithmetic mask.
pub trait Word:
    Copy
    + PartialEq
    + core::ops::BitXor<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::Not<Output = Self>
{
    /// The all-zero word.
    const ZERO: Self;
    /// A uniformly random word.
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self;
    /// Wrapping subtraction, for the arithmetic side.
    fn wrapping_sub(self, other: Self) -> Self;
    /// Wrapping addition, for the arithmetic side.
    fn wrapping_add(self, other: Self) -> Self;
}

macro_rules! impl_word {
    ($($t:ty),*) => {$(
        impl Word for $t {
            const ZERO: Self = 0;
            fn random<R: Rng + ?Sized>(rng: &mut R) -> Self { rng.gen() }
            fn wrapping_sub(self, other: Self) -> Self { <$t>::wrapping_sub(self, other) }
            fn wrapping_add(self, other: Self) -> Self { <$t>::wrapping_add(self, other) }
        }
    )*};
}
impl_word!(u8, u16, u32, u64);

/// A secret split into two Boolean shares, `a ⊕ b`.
///
/// The shares are deliberately not public fields: every path that recombines them
/// should go through [`Masked::unmask`], so that a search for that name finds
/// every place the secret exists in the clear.
#[derive(Clone, Copy, Debug)]
pub struct Masked<T: Word> {
    a: T,
    b: T,
}

impl<T: Word> Masked<T> {
    /// Split `value` into fresh shares.
    pub fn new<R: Rng + ?Sized>(value: T, rng: &mut R) -> Self {
        let a = T::random(rng);
        Self {
            a,
            b: black_box(a ^ value),
        }
    }

    /// Build from shares that already exist.
    pub fn from_shares(a: T, b: T) -> Self {
        Self { a, b }
    }

    /// The two shares.
    pub fn shares(&self) -> (T, T) {
        (self.a, self.b)
    }

    /// Recombine. **This is where the secret becomes a single value** — every call
    /// site is a place the masking stops protecting anything.
    pub fn unmask(&self) -> T {
        black_box(self.a) ^ black_box(self.b)
    }

    /// Re-randomise the split without changing the value.
    ///
    /// Needed between gadgets: shares that have been through several operations
    /// accumulate correlations, and refreshing breaks them.
    pub fn refresh<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        let r = T::random(rng);
        self.a = black_box(self.a ^ r);
        self.b = black_box(self.b ^ r);
    }

    /// XOR of two masked values. Linear, so it is share-wise and needs no
    /// randomness — which is why Boolean masking is cheap for XOR-heavy designs
    /// and expensive for arithmetic ones.
    pub fn xor(&self, other: &Self) -> Self {
        Self {
            a: black_box(self.a ^ other.a),
            b: black_box(self.b ^ other.b),
        }
    }

    /// XOR with a public constant. Applied to one share only.
    pub fn xor_public(&self, k: T) -> Self {
        Self {
            a: black_box(self.a ^ k),
            b: self.b,
        }
    }

    /// Bitwise NOT. Complementing one share complements the value.
    pub fn not(&self) -> Self {
        Self {
            a: black_box(!self.a),
            b: self.b,
        }
    }

    /// AND of two masked values — the ISW gadget (Ishai–Sahai–Wagner, CRYPTO 2003).
    ///
    /// Non-linear, so it needs fresh randomness. The order of operations matters:
    /// the fresh `r` must be folded in before the cross terms are combined, or an
    /// intermediate carries the unmasked product.
    pub fn and<R: Rng + ?Sized>(&self, other: &Self, rng: &mut R) -> Self {
        let r = T::random(rng);
        let z0 = black_box((self.a & other.a) ^ r);
        let t = black_box((self.b & other.b) ^ r);
        let t = black_box(t ^ (self.b & other.a));
        let z1 = black_box(t ^ (self.a & other.b));
        Self { a: z0, b: z1 }
    }

    /// OR, via De Morgan over [`Self::and`].
    pub fn or<R: Rng + ?Sized>(&self, other: &Self, rng: &mut R) -> Self {
        self.not().and(&other.not(), rng).not()
    }
}

/// Boolean-to-arithmetic conversion — Goubin's algorithm (CHES 2001).
///
/// Given shares with `x = x' ⊕ r`, returns `A` such that `x = A + r (mod 2^k)`.
/// Seven operations, independent of word width, and proven first-order secure —
/// which is what makes it the standard choice. The naive alternative (unmask,
/// re-split arithmetically) exposes the secret in between.
///
/// The reason this matters for post-quantum work: lattice schemes mix Boolean
/// operations (hashing, sampling) with arithmetic modulo `q` (the NTT), so a
/// masked implementation converts between the two representations constantly, and
/// the conversions dominate the cost.
pub fn boolean_to_arithmetic<T: Word, R: Rng + ?Sized>(x_prime: T, r: T, rng: &mut R) -> T {
    let gamma = T::random(rng);

    let t = black_box(x_prime ^ gamma);
    let t = black_box(t.wrapping_sub(gamma));
    let t = black_box(t ^ x_prime);

    let gamma = black_box(gamma ^ r);
    let a = black_box(x_prime ^ gamma);
    let a = black_box(a.wrapping_sub(gamma));
    black_box(a ^ t)
}

/// Arithmetic-to-Boolean conversion.
///
/// # Not implemented, deliberately
///
/// A→B is the hard direction. Goubin's method is `O(k)` recursive and the
/// efficient alternatives (Coron–Großschädl–Vadnala, Kogge–Stone based) are
/// intricate enough that an implementation written from memory would be plausible
/// and wrong — and a masking gadget that is subtly wrong is worse than none,
/// because it looks like protection.
///
/// The honest position is that this needs the papers open and a leakage
/// measurement afterwards, and until that happens the function does not exist.
pub fn arithmetic_to_boolean_todo() {
    unimplemented!(
        "A→B needs Coron–Großschädl–Vadnala or Goubin's recursive method, \
         implemented from the paper and then measured — see the module docs"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xC0FFEE)
    }

    #[test]
    fn split_and_recombine_is_the_identity() {
        let mut r = rng();
        for _ in 0..1000 {
            let v: u32 = r.gen();
            assert_eq!(Masked::new(v, &mut r).unmask(), v);
        }
    }

    #[test]
    fn shares_are_not_the_value() {
        let mut r = rng();
        let v: u32 = 0xDEAD_BEEF;
        let m = Masked::new(v, &mut r);
        let (a, b) = m.shares();
        assert_ne!(a, v, "share A leaked the value directly");
        assert_ne!(b, v, "share B leaked the value directly");
    }

    #[test]
    fn refresh_preserves_the_value_and_changes_the_shares() {
        let mut r = rng();
        let v: u32 = 0x1234_5678;
        let mut m = Masked::new(v, &mut r);
        let before = m.shares();
        m.refresh(&mut r);
        assert_eq!(m.unmask(), v);
        assert_ne!(m.shares(), before);
    }

    #[test]
    fn xor_gadget_is_correct() {
        let mut r = rng();
        for _ in 0..1000 {
            let (x, y): (u32, u32) = (r.gen(), r.gen());
            let mx = Masked::new(x, &mut r);
            let my = Masked::new(y, &mut r);
            assert_eq!(mx.xor(&my).unmask(), x ^ y);
            assert_eq!(mx.xor_public(y).unmask(), x ^ y);
        }
    }

    #[test]
    fn not_gadget_is_correct() {
        let mut r = rng();
        for _ in 0..1000 {
            let x: u32 = r.gen();
            assert_eq!(Masked::new(x, &mut r).not().unmask(), !x);
        }
    }

    #[test]
    fn isw_and_gadget_is_correct() {
        let mut r = rng();
        for _ in 0..2000 {
            let (x, y): (u32, u32) = (r.gen(), r.gen());
            let mx = Masked::new(x, &mut r);
            let my = Masked::new(y, &mut r);
            assert_eq!(mx.and(&my, &mut r).unmask(), x & y, "x={x:#x} y={y:#x}");
        }
    }

    #[test]
    fn or_gadget_is_correct() {
        let mut r = rng();
        for _ in 0..1000 {
            let (x, y): (u32, u32) = (r.gen(), r.gen());
            let mx = Masked::new(x, &mut r);
            let my = Masked::new(y, &mut r);
            assert_eq!(mx.or(&my, &mut r).unmask(), x | y);
        }
    }

    #[test]
    fn goubin_b2a_round_trips_for_every_width() {
        let mut r = rng();
        for _ in 0..2000 {
            let x: u32 = r.gen();
            let mask: u32 = r.gen();
            let x_prime = x ^ mask;
            let a = boolean_to_arithmetic(x_prime, mask, &mut r);
            assert_eq!(
                a.wrapping_add(mask),
                x,
                "B2A failed: x={x:#x} mask={mask:#x} A={a:#x}"
            );
        }
        for _ in 0..2000 {
            let x: u8 = r.gen();
            let mask: u8 = r.gen();
            let a = boolean_to_arithmetic(x ^ mask, mask, &mut r);
            assert_eq!(a.wrapping_add(mask), x);
        }
        for _ in 0..2000 {
            let x: u64 = r.gen();
            let mask: u64 = r.gen();
            let a = boolean_to_arithmetic(x ^ mask, mask, &mut r);
            assert_eq!(a.wrapping_add(mask), x);
        }
    }

    #[test]
    fn b2a_edge_values() {
        let mut r = rng();
        for &x in &[0u32, 1, u32::MAX, 0x8000_0000] {
            for &mask in &[0u32, 1, u32::MAX, 0x8000_0000] {
                let a = boolean_to_arithmetic(x ^ mask, mask, &mut r);
                assert_eq!(a.wrapping_add(mask), x, "x={x:#x} mask={mask:#x}");
            }
        }
    }

    #[test]
    fn and_gadget_output_shares_vary_run_to_run() {
        // Same inputs, different randomness → different share encodings.
        // If this ever fails, the gadget stopped consuming fresh randomness.
        let mut r = rng();
        let mx = Masked::new(0xAAAA_AAAAu32, &mut r);
        let my = Masked::new(0x5555_5555u32, &mut r);
        let first = mx.and(&my, &mut r).shares();
        let second = mx.and(&my, &mut r).shares();
        assert_ne!(first, second);
    }
}
