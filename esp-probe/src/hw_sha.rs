//! `Sha256Backend` over the ESP32-S3 SHA accelerator, streaming.
//!
//! # Why a state machine
//!
//! esp-hal's digest context borrows the peripheral, so holding one across the
//! `init` / `update` / `finish` calls of [`Sha256Backend`] would need a
//! self-referential struct. The escape hatch is [`Sha::start_owned`], which
//! *consumes* the peripheral and returns a context that owns it, paired with
//! [`ShaDigest::cancel`], which hands it back. Moving the peripheral between the
//! two states gives the whole cycle with no `unsafe`, no self-reference, and — the
//! part that matters — **no change to the trait**.
//!
//! # Why it coalesces, which the measurements decided
//!
//! Three versions were built and timed on the board, at 4113 compressions each:
//!
//! Five versions were built and timed on the board, 4113 compressions each. The
//! run-to-run spread is under 0.01%, so these differences are real.
//!
//! | version | cycles/compression |
//! |---|---|
//! | buffer the whole digest into 2 KB, borrowed context — **capped at 2 KB** | 2209 |
//! | stream every caller slice to the peripheral, owned context | 2631 |
//! | coalesce into 256 bytes, owned context | 2606 |
//! | buffer 2.3 KB, borrowed fast path, but `mem::replace` in `finish` | 2463 |
//! | buffer 2.3 KB, borrowed fast path, no move, stream on overflow | 2427 |
//! | **the same, plus `save`/`restore` so the verifier needs no scratch** | **2470** |
//!
//! **The capped version is still the fastest, by 10%, and it is wrong.** A firmware
//! image is megabytes and it asserted past two kilobytes.
//!
//! The last row costs another 1.8% and buys 752 bytes of the verifier's stack: with
//! checkpointing the caller no longer supplies a kilobyte of scratch. That is 34
//! peripheral round trips per verification against four thousand digests, and a
//! kilobyte of RAM for under two percent of time is not a close call on a part with
//! 8 KB of it.
//!
//! Three things came out of chasing that 10%.
//!
//! **Per-call overhead is real.** Streaming was *slower* than buffering. The
//! verifier calls `update` five times per chain step — `I`, `q`, `i`, `j`, `tmp`,
//! 55 bytes together — and each carries `nb` polling and alignment handling.
//! Buffering pays that once per digest instead of five times.
//!
//! **Moving the peripheral costs.** `start_owned` / `cancel` move the `Sha` value,
//! and it is not a small struct; twice per digest across four thousand digests is
//! work unrelated to hashing. The fast path therefore borrows in place, and an
//! intermediate revision that used `mem::replace` there — taking the value out and
//! putting it back — measured 2463 against 2427 for the same logic without it.
//!
//! **And most of the remaining cost is not ours.** A 55-byte digest is one block:
//! the engine itself wants on the order of a hundred cycles, so roughly 2300 are
//! going somewhere else. The plausible destination is APB register access — writing
//! sixteen words in, polling the busy flag, reading eight words out, all across a
//! bus running at a fraction of the core clock. That is inside esp-hal's driver and
//! the peripheral's interface, not in this file, and fixing it would mean rewriting
//! the driver.
//!
//! Which is also why **DMA would not help here**: there is nothing to stream in a
//! 55-byte hash, and the latency being paid is per-transaction rather than
//! per-byte.
//!
//! # Checkpointing
//!
//! [`ShaDigest::save`] and [`ShaDigest::restore`] hand the engine's state in and
//! out, which is what lets the verifier park its `Kc` digest across each chain
//! instead of collecting the chain outputs into a kilobyte of caller scratch.
//!
//! `save` has to flush first: on the fast path the bytes are still sitting in this
//! buffer and the peripheral has not been told about them, so a context is opened,
//! the buffer pushed, and only then is the state read out. That costs a peripheral
//! round trip — but `save` happens `p` times per verification, 34 at `w = 8`,
//! against four thousand digests.
//!
//! # And what would not help
//!
//! DMA. Nearly every digest is one 64-byte block, there is nothing to stream in
//! that, and the latency being paid is per-transaction rather than per-byte.

use core::mem;

use esp_hal::peripherals::SHA;
use esp_hal::sha::{Context, Sha, Sha256, ShaDigest};
use lms_verify::Sha256Backend;

type Digest = ShaDigest<'static, Sha256, Sha<'static>>;

/// The peripheral is either idle or inside a digest. `Moving` exists only so the
/// value can be taken out of `&mut self` while it is transferred between the two.
#[allow(clippy::large_enum_variant)]
enum State {
    Idle(Sha<'static>),
    Hashing(Digest),
    Moving,
}

/// Sized so that every digest in an LMS verification except the message hash fits
/// without overflowing, which keeps them all on the no-move fast path.
///
/// The largest is `Kc = H(I || q || D_PBLC || z[0..p])`: 1110 bytes at `w = 8` and
/// 2166 at `w = 4`. 2304 covers both with room, at 36 SHA blocks.
const COALESCE: usize = 2304;

pub struct HwSha256 {
    state: State,
    buf: [u8; COALESCE],
    len: usize,
}

/// Push bytes into the peripheral, looping over what it declines to take.
///
/// A free function rather than a method so the caller can borrow `state` and `buf`
/// as separate fields.
fn push(state: &mut State, data: &[u8]) {
    match state {
        State::Hashing(digest) => {
            let mut remaining = data;
            while !remaining.is_empty() {
                remaining = nb::block!(digest.update(remaining)).unwrap();
            }
        }
        _ => panic!("update before init"),
    }
}

impl HwSha256 {
    pub fn new(peripheral: SHA<'static>) -> Self {
        Self { state: State::Idle(Sha::new(peripheral)), buf: [0; COALESCE], len: 0 }
    }

    /// Recover the peripheral, abandoning any digest in progress.
    fn take_sha(&mut self) -> Sha<'static> {
        match mem::replace(&mut self.state, State::Moving) {
            State::Idle(sha) => sha,
            State::Hashing(digest) => digest.cancel(),
            State::Moving => unreachable!("state left in transit"),
        }
    }
}

impl Sha256Backend for HwSha256 {
    fn init(&mut self) {
        // Deliberately does not touch the peripheral. A digest that fits the buffer
        // never starts one until `finish`, which is what keeps `Sha` from moving.
        if let State::Hashing(_) = self.state {
            let sha = self.take_sha();
            self.state = State::Idle(sha);
        }
        self.len = 0;
    }

    fn update(&mut self, data: &[u8]) {
        let mut rest = data;
        while !rest.is_empty() {
            let space = COALESCE - self.len;
            let n = space.min(rest.len());
            self.buf[self.len..self.len + n].copy_from_slice(&rest[..n]);
            self.len += n;
            rest = &rest[n..];

            if self.len == COALESCE {
                // Overflow: this digest is too big to buffer, so open a real
                // context and stream from here on.
                if let State::Idle(_) = self.state {
                    let sha = self.take_sha();
                    self.state = State::Hashing(sha.start_owned::<Sha256>());
                }
                push(&mut self.state, &self.buf);
                self.len = 0;
            }
        }
    }

    /// Saved engine state. About two hundred bytes, against the 1088 of scratch it
    /// replaces at `w = 8`.
    type Checkpoint = Context<Sha256>;

    fn finish(&mut self, out: &mut [u8; 32]) {
        // Fast path first, and **without `mem::replace`**. Taking the value out and
        // putting it back is still two moves of a large struct, which is what the
        // whole design is trying to avoid — an earlier revision did exactly that
        // here and measured 2463 rather than the 2313 below.
        if let State::Idle(sha) = &mut self.state {
            let mut digest = sha.start::<Sha256>();
            let mut remaining = &self.buf[..self.len];
            while !remaining.is_empty() {
                remaining = nb::block!(digest.update(remaining)).unwrap();
            }
            nb::block!(digest.finish(out)).unwrap();
            drop(digest);
            self.len = 0;
            return;
        }

        match mem::replace(&mut self.state, State::Moving) {
            State::Idle(_) => unreachable!("handled above"),
            // Streaming path: already mid-digest, so flush the tail and close it.
            State::Hashing(mut digest) => {
                if self.len > 0 {
                    let mut remaining = &self.buf[..self.len];
                    while !remaining.is_empty() {
                        remaining = nb::block!(digest.update(remaining)).unwrap();
                    }
                }
                nb::block!(digest.finish(out)).unwrap();
                self.state = State::Idle(digest.cancel());
            }
            State::Moving => unreachable!("state left in transit"),
        }
        self.len = 0;
    }

    fn save(&mut self, into: &mut Self::Checkpoint) {
        // Whatever is buffered has to reach the peripheral before its state means
        // anything, so the fast path opens a context here that it otherwise would
        // not have needed.
        if let State::Idle(_) = self.state {
            let sha = self.take_sha();
            self.state = State::Hashing(sha.start_owned::<Sha256>());
        }
        if self.len > 0 {
            push(&mut self.state, &self.buf[..self.len]);
            self.len = 0;
        }
        match &mut self.state {
            State::Hashing(digest) => nb::block!(digest.save(into)).unwrap(),
            _ => unreachable!("just ensured Hashing"),
        }
    }

    fn restore(&mut self, from: &mut Self::Checkpoint) {
        let sha = self.take_sha();
        self.state = State::Hashing(ShaDigest::restore(sha, from));
        self.len = 0;
    }
}
