//! Measured figures for the LMS verifier, per target.
//!
//! # How these were produced
//!
//! `size-probe/measure.sh` in this repository, which is the whole point: a budget
//! table nobody can reproduce is a blog post, not an engineering input.
//!
//! - **code**: `.text` of a `no_std`, `no_main` binary that calls
//!   [`lms_verify::verify`], linked with `--gc-sections` at `opt-level = "z"` with
//!   LTO. The inputs are read through volatile pointers, which matters more than it
//!   looks: with constant inputs LLVM evaluates the entire verification at compile
//!   time and leaves a binary containing the answer and no verifier — very small,
//!   and meaningless.
//! - **marginal**: the same figure minus a SHA-256-only baseline binary. This is
//!   the number a firmware architect actually weighs, because **a part doing secure
//!   boot already has SHA-256** — image integrity needs a hash before it needs a
//!   signature. The question is never what LMS costs; it is what LMS costs on top
//!   of what is already there.
//! - **stack**: from `-Z emit-stack-sizes`, summed along the deepest path. That is
//!   an upper bound rather than a guess for one specific reason: LMS verification
//!   has **no recursion**. It is a loop over hash chains and a loop up the Merkle
//!   path, with a flat SHA-256 underneath, so an acyclic call graph makes the sum
//!   sound. See `size-probe/stacksum.py`.
//!
//! # The finding
//!
//! **The verifier is smaller than its hash function.** On Cortex-M4F the whole
//! binary is 5520 bytes, of which SHA-256 and the runtime are 3880 — LMS
//! verification itself is about 1.6 KB. That is the case for hash-based signatures
//! on a constrained part, stated as a measurement rather than an intuition.
//!
//! # What supporting a hardware backend cost, and what got it back
//!
//! Abstracting the hash behind [`lms_verify::Sha256Backend`] is not free, and the
//! reason is structural rather than an implementation detail. The streaming
//! formulation fed each chain output into the `Kc` hash as it was produced, which
//! keeps **two hash contexts live at once**. Software can do that. A hash
//! *peripheral* has one context, so the shared path has to buffer the chain
//! outputs instead.
//!
//! Measured on Cortex-M4F, against the original version that could not use an
//! accelerator at all:
//!
//! | | original | + backend trait, caller scratch | + checkpointing |
//! |---|---|---|---|
//! | code | 1536 | 1712 | **1648** |
//! | stack | 1180 | 1844 | **1092** |
//!
//! The middle column is what a hardware backend cost before the constraint was
//! looked at properly: two hash contexts are live during a verification and a
//! peripheral has one, so the chain outputs were collected into `p * 32` bytes of
//! caller-supplied scratch — 1088 at `w = 8`.
//!
//! But the peripheral can checkpoint its own state, and `sha2::Sha256` is `Clone`,
//! so both kinds of backend can park a digest instead. The scratch is gone, and
//! **the final version uses less stack than the original that had no hardware
//! support**, for 112 bytes of code.
//!
//! Worth keeping because the middle column was published for a day: the first
//! answer to a constraint is not always the constraint.
//!
//! # A second thing the measurement decided
//!
//! When `cost` gained a second call site for the innermost `coef` helper, LLVM at
//! `opt-level = "z"` stopped inlining it. Forcing it back with `#[inline(always)]`
//! **saves 408 bytes on Cortex-M0+ and costs 48 on the other three.** That is a
//! 20% saving on the part where 16 KB of boot ROM makes it matter, against 3% lost
//! where it does not, so the attribute stays.
//!
//! Worth recording because it is the argument for having a probe at all: the
//! optimiser's default was wrong precisely on the tightest target, and no amount of
//! reading the source would have said so.
//!
//! # What these figures do not cover
//!
//! Only LMS. Every other row in [`crate::SCHEMES`] is still
//! [`crate::Provenance::Estimated`], because measuring ML-DSA or SLH-DSA means
//! building an implementation of each for these targets, which has not been done.
//! The tempting move — assume the ratios hold — is exactly the kind of guess this
//! table exists to avoid.

/// One target's measured cost for LMS verification.
#[derive(Clone, Copy, Debug)]
pub struct Measurement {
    /// Rust target triple.
    pub target: &'static str,
    /// Human-readable core name.
    pub core: &'static str,
    /// `.text` of the full probe binary, bytes.
    pub code_total: usize,
    /// `.text` of the SHA-256-only baseline, bytes.
    pub code_sha_only: usize,
    /// Heaviest call path found statically — a **lower** bound, not a budget.
    ///
    /// `-Z emit-stack-sizes` gives frame sizes and no call graph, so the graph is
    /// recovered from the disassembly. Indirect and tail calls leave edges missing
    /// and every missing edge can only shrink the answer: on `thumbv7em` the pass
    /// cannot resolve 55 call sites and reports 720 where the frames along the
    /// verifier's actual chain sum to about 1260.
    ///
    /// Useful for catching a regression between two builds. Use [`ON_TARGET`] for
    /// a figure you can budget against.
    pub stack_lower_bound: usize,
}

impl Measurement {
    /// Flash cost of LMS verification on a part that already has SHA-256.
    pub const fn code_marginal(&self) -> usize {
        self.code_total - self.code_sha_only
    }
}

/// Measured with **rustc 1.98.0** on 2026-08-24. Re-measured whenever the
/// toolchain moves, because it moves these.
///
/// The 1.97.1 → 1.98.0 bump shifted every total by about 64 bytes, almost all of
/// it in the hash baselines, and left the hash-subtracted column between +8 and
/// −160. **No conclusion in this crate changed**, which is worth knowing: the
/// findings are not an artifact of one compiler release.
///
/// The on-target figures in [`ON_TARGET`] were taken with the Xtensa `esp` fork,
/// which is a separate toolchain and did not move with stable.
///
/// The figures are identical across LMS parameter sets: `w` and `h` are runtime
/// values in this implementation, not const generics, so H5/W8 and H10/W4 share
/// the same code. Only the loop counts — and therefore the time — differ.
pub const LMS_MEASUREMENTS: &[Measurement] = &[
    Measurement {
        target: "thumbv6m-none-eabi",
        core: "Cortex-M0+",
        code_total: 5568,
        code_sha_only: 3928,
        stack_lower_bound: 1048,
    },
    Measurement {
        target: "thumbv7em-none-eabihf",
        core: "Cortex-M4F",
        code_total: 5464,
        code_sha_only: 3808,
        stack_lower_bound: 720,
    },
    Measurement {
        target: "riscv32imc-unknown-none-elf",
        core: "RISC-V rv32imc",
        code_total: 6652,
        code_sha_only: 4384,
        stack_lower_bound: 736,
    },
    Measurement {
        target: "riscv32imac-unknown-none-elf",
        core: "RISC-V rv32imac",
        code_total: 6652,
        code_sha_only: 4384,
        stack_lower_bound: 736,
    },
];

/// What a verification actually costs, measured on hardware.
///
/// The static pass above cannot bound stack usage, so this is read off the board:
/// `esp-probe` paints a 32 KB window below the stack pointer, runs a verification,
/// and finds the high-water mark. ESP32-S3 at 240 MHz, RFC 8554 Appendix F test
/// case 1.
#[derive(Clone, Copy, Debug)]
pub struct OnTarget {
    /// Which SHA-256 the verifier was handed.
    pub backend: &'static str,
    /// Core cycles for one verification.
    pub cycles: u32,
    /// Peak stack of the verification's own frames, bytes.
    pub stack_frames: usize,
    /// The backend struct, which the caller owns and the watermark does not see.
    pub backend_bytes: usize,
}

impl OnTarget {
    /// Frames plus backend — the figure to budget against.
    pub const fn total_ram(&self) -> usize {
        self.stack_frames + self.backend_bytes
    }

    /// Microseconds at 240 MHz.
    pub const fn micros_at_240mhz(&self) -> u32 {
        self.cycles / 240
    }
}

/// **The accelerator is faster and costs more RAM, not less.**
///
/// Its 2328 bytes are almost entirely a coalescing buffer, and that buffer is why
/// it is fast: feeding the peripheral in one call per digest instead of five saves
/// far more than the copy costs. Shrinking it to 256 bytes was measured at 2606
/// cycles per compression against 2470 — so the trade is roughly 2 KB of RAM for
/// 5% of verification time, and which way it should go depends on the part.
///
/// The software figure is the one to use for a part with no hash engine, and it is
/// the smaller of the two.
pub const ON_TARGET: &[OnTarget] = &[
    OnTarget {
        backend: "software (sha2)",
        cycles: 33_344_698,
        stack_frames: 1040,
        backend_bytes: 112,
    },
    OnTarget {
        backend: "ESP32-S3 SHA accelerator",
        cycles: 10_159_573,
        stack_frames: 272,
        backend_bytes: 2328,
    },
];

/// The target whose figures the main [`crate::SCHEMES`] table quotes.
///
/// Cortex-M4F, as the most common class of part doing secure boot. It is also the
/// smallest of the four, so quoting it is the least conservative choice — which is
/// why [`LMS_MEASUREMENTS`] is published alongside rather than hidden.
pub const REPRESENTATIVE: &str = "thumbv7em-none-eabihf";

/// Look up a target's measurement.
pub fn measurement(target: &str) -> Option<&'static Measurement> {
    LMS_MEASUREMENTS.iter().find(|m| m.target == target)
}
