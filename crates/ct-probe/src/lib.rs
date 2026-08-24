//! Timing-leakage detection by Welch's t-test — the dudect method.
//!
//! # What this answers, and what it does not
//!
//! The question this exists for: how do you write software that is constant time,
//! when the algorithm itself is not deterministic — as ML-KEM and ML-DSA are not?
//!
//! The tempting answer is to add padding loops until the measured times look equal.
//! It is wrong, and wrong in a way that looks like it worked: an attacker averages
//! away the noise you added, and the compiler is free to move or delete the padding
//! entirely.
//!
//! The right frame is that constant time means **secret-independent control flow
//! and memory access**. You establish it by construction — no branch on a secret,
//! no memory index derived from a secret — and then you *measure* to catch the
//! places where the compiler, the microarchitecture, or your own mistake broke the
//! property anyway.
//!
//! This crate is the measurement half. It cannot give you the property.
//!
//! # The method
//!
//! Run the target repeatedly on inputs drawn from two classes — conventionally one
//! fixed input and one random per trial — with the class chosen at random each
//! time so that drift in machine state cannot correlate with class. Then ask
//! whether the two timing distributions have the same mean, using Welch's t-test,
//! which does not assume equal variances.
//!
//! A large `|t|` is evidence that the execution time depends on the input class,
//! and therefore on the secret. The conventional threshold is `|t| > 4.5`.
//!
//! Because timing distributions are heavy-tailed — a preemption or a cache miss
//! adds an outlier unrelated to the secret — the test is also run on
//! progressively cropped data, discarding the slowest measurements. A signal that
//! only appears after cropping is still a signal.
//!
//! # Limits, stated plainly
//!
//! - **It can show leakage. It can never show its absence.** A negative result
//!   means this harness, on this machine, at this sample size, found no evidence.
//!   Increase the sample count and the answer can change.
//! - **It measures the host.** Results from an x86-64 laptop say nothing about a
//!   Cortex-M4. Cache structure, pipeline behaviour and the absence of an OS
//!   scheduler all differ. For an embedded target this has to run on the target.
//! - **It measures one binary.** A different optimisation level, a different LLVM
//!   version or a different inlining decision is a different experiment.
//! - **Wall-clock resolution is coarse** relative to the effects being hunted.
//!   [`Instant`](std::time::Instant) is used for portability; a serious campaign
//!   wants a cycle counter (`rdtsc` with the appropriate fences on x86, `DWT->CYCCNT`
//!   on Cortex-M) and the frequency scaling turned off.
//! - **The statistic is not a proof.** Formal approaches — type systems, symbolic
//!   execution over a leakage model — prove things this cannot. They are also much
//!   more work. This is the cheap check that catches most real mistakes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rand::Rng;
use std::time::Instant;

/// Which of the two input populations a trial was drawn from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// Conventionally the fixed input.
    A,
    /// Conventionally the freshly randomised input.
    B,
}

impl Class {
    fn index(self) -> usize {
        match self {
            Class::A => 0,
            Class::B => 1,
        }
    }
}

/// How to run the experiment.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Measurements to take, split randomly between the two classes.
    pub samples: usize,
    /// Untimed iterations first, to let caches and branch predictors settle.
    pub warmup: usize,
    /// `|t|` above which the result is reported as leaking.
    pub threshold: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            samples: 100_000,
            warmup: 1_000,
            threshold: 4.5,
        }
    }
}

/// Streaming Welch's t-test over two populations.
///
/// Uses Welford's algorithm so that a long run does not lose precision the way a
/// naive sum-of-squares does.
#[derive(Clone, Copy, Debug, Default)]
pub struct Welch {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl Welch {
    /// A fresh, empty test.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one observation.
    pub fn push(&mut self, class: Class, x: f64) {
        let i = class.index();
        self.n[i] += 1.0;
        let delta = x - self.mean[i];
        self.mean[i] += delta / self.n[i];
        self.m2[i] += delta * (x - self.mean[i]);
    }

    /// Sample variance of one class, or `None` with fewer than two observations.
    pub fn variance(&self, class: Class) -> Option<f64> {
        let i = class.index();
        if self.n[i] < 2.0 {
            return None;
        }
        Some(self.m2[i] / (self.n[i] - 1.0))
    }

    /// Welch's `t`. `None` if either class is too small or has zero variance.
    pub fn t(&self) -> Option<f64> {
        let (va, vb) = (self.variance(Class::A)?, self.variance(Class::B)?);
        let denom = (va / self.n[0] + vb / self.n[1]).sqrt();
        if denom == 0.0 || !denom.is_finite() {
            return None;
        }
        Some((self.mean[0] - self.mean[1]) / denom)
    }

    /// Observations per class.
    pub fn counts(&self) -> (usize, usize) {
        (self.n[0] as usize, self.n[1] as usize)
    }
}

/// One t-test at one crop level.
#[derive(Clone, Copy, Debug)]
pub struct CropResult {
    /// Fraction of the fastest measurements retained. `1.0` means no cropping.
    pub keep: f64,
    /// Welch's t over the retained measurements.
    pub t: Option<f64>,
    /// How many measurements survived the crop.
    pub kept: usize,
}

/// The outcome of a run.
#[derive(Clone, Debug)]
pub struct Report {
    /// One entry per crop level, uncropped first.
    pub crops: Vec<CropResult>,
    /// Threshold the run was configured with.
    pub threshold: f64,
}

impl Report {
    /// Largest `|t|` seen at any crop level.
    pub fn max_abs_t(&self) -> f64 {
        self.crops
            .iter()
            .filter_map(|c| c.t)
            .fold(0.0, |a, b| a.max(b.abs()))
    }

    /// Whether any crop level exceeded the threshold.
    ///
    /// True means leakage was detected. False means **not detected**, which is a
    /// weaker claim than "constant time" and should never be reported as one.
    pub fn leaks(&self) -> bool {
        self.max_abs_t() > self.threshold
    }

    /// A short human-readable verdict.
    pub fn verdict(&self) -> &'static str {
        let t = self.max_abs_t();
        if t > self.threshold * 2.0 {
            "LEAKS — clear timing dependence on the input class"
        } else if t > self.threshold {
            "LEAKS — above threshold"
        } else if t > self.threshold * 0.8 {
            "BORDERLINE — rerun with more samples before believing either way"
        } else {
            "no evidence of leakage at this sample size (NOT a proof of constant time)"
        }
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  crop    kept        t")?;
        for c in &self.crops {
            match c.t {
                Some(t) => writeln!(f, "  {:>4.0}%  {:>7}  {:>+8.2}", c.keep * 100.0, c.kept, t)?,
                None => writeln!(f, "  {:>4.0}%  {:>7}        --", c.keep * 100.0, c.kept)?,
            }
        }
        write!(
            f,
            "  max |t| = {:.2}  →  {}",
            self.max_abs_t(),
            self.verdict()
        )
    }
}

/// Fractions of the fastest measurements kept, in the order they are reported.
const CROPS: [f64; 8] = [1.0, 0.95, 0.9, 0.8, 0.7, 0.6, 0.4, 0.2];

/// Run the experiment.
///
/// `prepare` builds an input for the given class; it is called outside the timed
/// region. `exercise` is the operation under test and is what gets timed.
///
/// The class is drawn at random for every trial. That randomisation is not a
/// detail — running all of class A and then all of class B lets thermal drift,
/// frequency scaling or another process's activity masquerade as a timing signal.
///
/// ```no_run
/// use ct_probe::{run, Config, Class};
/// let secret = [0x42u8; 32];
/// let report = run(
///     &Config::default(),
///     |class| match class {
///         Class::A => [0u8; 32],
///         Class::B => rand::random(),
///     },
///     |input| { std::hint::black_box(input == &secret); },
/// );
/// println!("{report}");
/// ```
pub fn run<T>(
    cfg: &Config,
    mut prepare: impl FnMut(Class) -> T,
    mut exercise: impl FnMut(&T),
) -> Report {
    let mut rng = rand::thread_rng();

    for _ in 0..cfg.warmup {
        let input = prepare(Class::A);
        exercise(std::hint::black_box(&input));
    }

    let mut samples: Vec<(Class, u64)> = Vec::with_capacity(cfg.samples);
    for _ in 0..cfg.samples {
        let class = if rng.gen::<bool>() {
            Class::A
        } else {
            Class::B
        };
        let input = prepare(class);
        let input = std::hint::black_box(input);

        let start = Instant::now();
        exercise(&input);
        let elapsed = start.elapsed().as_nanos() as u64;

        std::hint::black_box(&input);
        samples.push((class, elapsed));
    }

    let mut sorted: Vec<u64> = samples.iter().map(|(_, t)| *t).collect();
    sorted.sort_unstable();

    let crops = CROPS
        .iter()
        .map(|&keep| {
            let cutoff = if keep >= 1.0 {
                u64::MAX
            } else {
                let idx = ((sorted.len() as f64 * keep) as usize).min(sorted.len() - 1);
                sorted[idx]
            };
            let mut w = Welch::new();
            let mut kept = 0usize;
            for &(class, t) in &samples {
                if t <= cutoff {
                    w.push(class, t as f64);
                    kept += 1;
                }
            }
            CropResult {
                keep,
                t: w.t(),
                kept,
            }
        })
        .collect();

    Report {
        crops,
        threshold: cfg.threshold,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welch_matches_a_hand_computed_case() {
        // Two populations with clearly different means and tiny variance.
        let mut w = Welch::new();
        for x in [10.0, 10.0, 11.0, 9.0, 10.0] {
            w.push(Class::A, x);
        }
        for x in [20.0, 20.0, 21.0, 19.0, 20.0] {
            w.push(Class::B, x);
        }
        let t = w.t().expect("both classes populated");
        assert!(t < -10.0, "expected a large negative t, got {t}");
        assert_eq!(w.counts(), (5, 5));
    }

    #[test]
    fn identical_populations_give_a_small_t() {
        let mut w = Welch::new();
        for i in 0..1000 {
            let x = (i % 7) as f64;
            w.push(Class::A, x);
            w.push(Class::B, x);
        }
        assert!(w.t().unwrap().abs() < 0.001);
    }

    #[test]
    fn zero_variance_is_not_an_infinite_t() {
        let mut w = Welch::new();
        for _ in 0..10 {
            w.push(Class::A, 5.0);
            w.push(Class::B, 5.0);
        }
        assert_eq!(w.t(), None, "zero denominator must not produce inf or NaN");
    }

    #[test]
    fn one_sided_data_yields_no_statistic() {
        let mut w = Welch::new();
        w.push(Class::A, 1.0);
        w.push(Class::A, 2.0);
        assert_eq!(w.t(), None);
    }

    #[test]
    fn report_does_not_call_undetected_the_same_as_safe() {
        let r = Report {
            crops: vec![CropResult {
                keep: 1.0,
                t: Some(0.4),
                kept: 100,
            }],
            threshold: 4.5,
        };
        assert!(!r.leaks());
        assert!(r.verdict().contains("NOT a proof"));
    }

    #[test]
    fn harness_runs_end_to_end() {
        let cfg = Config {
            samples: 2_000,
            warmup: 100,
            threshold: 4.5,
        };
        let report = run(
            &cfg,
            |class| match class {
                Class::A => 0u64,
                Class::B => 1u64,
            },
            |x| {
                std::hint::black_box(x.wrapping_mul(3));
            },
        );
        assert_eq!(report.crops.len(), CROPS.len());
        // No assertion on the verdict: a 2k-sample run on a shared CI machine is
        // not a reliable oracle, and a test that flakes teaches people to ignore it.
    }
}
