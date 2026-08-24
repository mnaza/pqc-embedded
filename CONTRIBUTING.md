# Contributing

Some notes if you want to change something here.

## What this is

Four crates about post-quantum signature verification on small embedded targets, plus two measurement harnesses.

`README.md` has technical part. `DECISIONS.md` has reasoning, including places where a measurement showed earlier assumption was wrong.

## Numbers

Most of value of this repository is in measured numbers.

One wrong number is worse than no number, because reader who finds it stops trusting rest of table.

So:

Do not say crypto is correct when it is not verified. `lms-verify` passes RFC 8554 Appendix F vectors, so "conformance-checked" is fine. "Audited", "production-ready" and "secure" are not, and passing tests do not change this. New algorithm starts again from "self-consistent" until it has own vectors.

Do not change `Provenance::Estimated` to `Measured` without measuring. `Measured` also needs target name attached to it. Code and RAM have separate provenance because they come from different processes. One shared field already made rows advertise measured RAM which was never measured.

"No evidence of leakage" is not "constant time". `ct-probe` can show leakage. It cannot show absence of it.

If measurement disagrees with something written here, then text changes, not measurement. This happened several times already and corrections stay in `DECISIONS.md`.

## Scope

`lms-verify` does not sign and does not generate keys. Test signer is `#[cfg(test)]` and marked as unusable. Please keep it this way.

`arithmetic_to_boolean` stays `unimplemented!()`. Masking gadget written from memory is worse than missing one.

Missing things should be visible in code, not only in commit message. `tests/kat.rs`, `EST?` column and `stack>=` label exist for reader who never talks to me.

## Code

`#![forbid(unsafe_code)]` in library crates. Probes are exception and they say why.

`lms-verify` and `boot-budget` are `no_std` and allocation-free. No `Vec` and no `alloc` outside `#[cfg(test)]`.

Before saying something works, run these and paste output:

```sh
cargo test
cargo clippy --all-targets
cargo fmt --check
```

Clippy is at zero warnings now.

No flaky tests. Timing statistics belong in `examples/`, not in test suite. A test which sometimes fails teaches people to ignore failures.

Tests should explain themselves. If test asserts magic number, comment should say where number came from.

## After changing lms-verify

Re-run `size-probe/measure.sh` and reflash `esp-probe`. Update `boot-budget::measurements` if numbers moved.

They moved before for reasons which had nothing to do with verifier logic: inlining decision, shared helper getting second call site, compiler update.

Tests compare table against stored numbers, not against live build. So difference between repository and reality is exactly what they cannot catch.

`rust-version` in manifest is tested, not guessed. Check with `cargo +<version> test --workspace` before changing it.
