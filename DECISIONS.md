# Decisions, and the ones that were wrong

Some design notes for this repository.

Second half is probably more useful than first one. Several times measurements showed that something written here was wrong. I keep the corrections instead of cleaning history and pretending first idea was correct.

## Why these four crates

Rust post-quantum ecosystem is already not empty.

RustCrypto has `ml-kem`, `ml-dsa` and `slh-dsa`. Cryspen's `libcrux` has formally verified ML-KEM used by Firefox. `pqcrypto` binds PQClean. `rustls` negotiates X25519MLKEM768.

So writing another ML-DSA implementation did not look very useful. It would mostly produce one more unaudited lattice implementation which nobody should put in product.

The gaps I found more interesting are different:

- hash-based firmware signatures have not much Rust support;
- flash/RAM/time numbers which decide if scheme actually fits are rarely published;
- constant-time verification tooling in cargo is very small;
- masking gadgets in Rust are almost absent.

## Decisions

### Verification only

A device doing secure boot does not need to sign.

Signing key belongs in build system or HSM. Device only needs public key and verifier.

This makes implementation much smaller, there is no private key state on target, and timing is also different problem because verifier only touches public data.

It also makes this project easier to justify as something non-cryptographer can work on without pretending to implement complete signing system safely.

### LMS first

LMS is hash based, so there is no lattice arithmetic to implement wrong.

For verification, security mostly comes down to SHA-256 and correct RFC implementation.

NIST SP 800-208 approves LMS for this kind of use. Stateful signing key is annoying for general-purpose signatures, but much less annoying when one build system signs a finite number of firmware images.

So LMS was the first target.

### Provenance is a type, not comment in table

Budget table is only useful if it is clear which numbers are real measurements and which are estimates.

I did not want this information living in README footnotes which will eventually become outdated.

So provenance is part of the data.

Tests fail if something says it is measured but there is no target attached to measurement.

This became more useful later than I expected.

### tests/kat.rs was empty intentionally

At first `tests/kat.rs` existed but had no KATs.

This was intentional.

Round-trip tests only prove signer and verifier agree with each other. They do not prove either agrees with RFC.

I wanted this missing part to be visible in repository, not something hidden behind "tests pass".

Later RFC vectors were added and file became real test file.

### arithmetic_to_boolean stays unimplemented!()

I did not want to write a masking conversion from memory just because formula looked familiar.

Crypto code which looks plausible is dangerous enough already.

Leaving `unimplemented!()` was better than adding something I was not sure about.

### Caller should not supply scratch memory

One version of LMS hardware backend required caller to provide `p * 32` bytes of scratch.

Reason was simple: during verification there are two live hash states, but hardware SHA peripheral only has one context.

First solution was to save chain outputs in scratch memory.

For `w = 8` this means 1088 bytes.

It worked, but it was ugly and expensive for stack.

Then I noticed both backends can actually checkpoint hash state.

ESP32 peripheral can save its internal state and `sha2::Sha256` is `Clone`.

So now backend can park one digest, do chain work, and restore it later.

Scratch parameter disappeared.

Funny result is final hardware-capable version uses less stack than original version which had no hardware support at all.

This was one of first cases where hardware limitation looked like API limitation, but actually was not.

## Where assumptions were wrong

### Linker script problem which looked like compiler problem

ESP32-S3 firmware did not link.

Error was:

```text
dangerous relocation: l32r: literal placed after use
```

and it pointed inside esp-hal `__pre_init`.

This looked very much like Xtensa compiler/linker problem.

I tried two esp-hal versions, downgraded PAC, changed optimisation levels, LTO on and off, `rust-lld`, `--no-relax`, and some other combinations.

All real builds, all same type of failure.

At that point I concluded installed Xtensa GCC was broken and global toolchain change was needed.

That conclusion was wrong.

The actual problem was missing rustflag:

```text
-C link-arg=-Tlinkall.x
```

Without esp-hal linker script, sections are placed wrong. The result happens to fail with error which looks exactly like compiler bug.

Good lesson here for me: when error points to somebody else's compiler, probably check own linker setup one more time before blaming compiler.

### Streaming was slower than buffering

Hardware backend originally buffered digest input.

Obvious optimisation looked like: stop buffering and send every input slice directly to SHA peripheral.

Less memory, less copying, should be faster.

It was around 8% slower.

Reason is verifier calls `update` five times for one chain step, but total input is only 55 bytes.

Every peripheral transaction has polling, setup and alignment cost.

Buffering pays this cost once. Streaming pays it five times.

I built and timed five backend versions.

Fastest one used buffer capped at 2 KB, but that would assert on a normal firmware image, so it is not acceptable API.

Version in repository is around 10% slower than fastest benchmarked one, but it works for real input sizes.

So in this case extra copy is cheaper than extra peripheral transactions.

### Static stack model could not give upper bound

Original idea was simple.

`-Z emit-stack-sizes` gives stack frame size for each function.

Then parse call graph from disassembly, find heaviest path, and that should give upper bound.

Except it does not.

On one binary there are 55 call sites analyser cannot resolve.

Indirect calls. Tail calls compiled as branches. Linker generated thunks.

Each unresolved edge can only remove something from path, so answer gets smaller.

The script reported 720 bytes.

Real measured RAM figure was 1152 bytes.

A stack estimate which is too low is worse than no estimate because somebody may actually design around it.

So static analyser is still there, but it is explicitly a lower bound and mostly useful for comparing two builds.

Real number comes from hardware by painting stack and reading high-water mark.

There was also an earlier and more embarrassing bug.

`nm` output was demangled but `objdump` output was not.

So symbol names did not match.

Call graph was basically empty and analyser returned only entry frame.

Result looked completely reasonable.

It was also completely wrong.

This is exactly type of bug I worry about in measurement tooling: bad number does not always look obviously bad.

### SHA accelerator argument did not survive measurement

One early argument in these notes was:

- LMS is mostly SHA-256.
- Many embedded chips already have SHA accelerator.
- ML-DSA uses SHAKE, so that accelerator does not help it.
- Therefore hardware root-of-trust parts are especially good fit for LMS.

First three points are true.

Fourth one does not follow.

On ESP32-S3:

```text
LMS w8/h5, SHA accelerator    41.7 ms
ML-DSA-44, software           17.3 ms
```

Hardware SHA makes LMS around 3.3x faster.

Still not enough.

ML-DSA is about 2.4x faster even compared against accelerated LMS.

So speed is not argument I first thought it was.

RAM is where comparison becomes very different:

```text
LMS w8/h5       1152 bytes
ML-DSA-44      34044 bytes
```

A chip with 8 KB RAM can run LMS and cannot run this ML-DSA implementation at all.

And flash is not necessarily problem. ML-DSA code can still fit.

So real trade is more like time vs memory, not "hash-based wins".

Neither one wins on every target.

### One provenance field was describing two different measurements

Originally `Provenance` treated code and RAM as one thing.

If row was measured, both looked measured.

This was bad design.

Code size comes from linker output.

RAM comes from completely different process, in this case measuring stack on actual hardware.

They should not share one truth value.

After splitting provenance for code and RAM, another problem became obvious immediately.

ML-DSA-65 and ML-DSA-87 RAM numbers were still estimates:

```text
ML-DSA-65    16000
ML-DSA-87    20000
```

But measured ML-DSA-44 already uses:

```text
34044
```

Both larger parameter sets have larger matrices.

So 16 KB and 20 KB are not just "not measured". They are basically impossible to believe.

I left those estimates visible and added test which pins contradiction.

Replacing bad estimate with another estimate does not improve much. Better to leave it obviously wrong until real measurement exists.

### Whole binary totals were not comparing schemes

At first I compared total verifier binary sizes directly.

This looked simple but it was mostly comparing hash implementations.

Example:

```text
sha2 0.10 SHA-256    3808 bytes
sha2 0.11 SHA-256    8776 bytes
```

Same hash algorithm, more than twice size.

Ed25519 was even more misleading because around 64% of complete binary was unrolled SHA-512.

So "Ed25519 verifier is huge" was partly really "this SHA-512 implementation is huge".

Now every scheme is compared against baseline using same hash implementation and version.

So calculation is roughly:

```text
scheme-only = full verifier - matching hash baseline
```

It is still approximate because compiler inlining and shared code means subtraction is not perfect.

But at least comparison now says something about signature implementation instead of mostly saying which dependency has bigger hash code.

## Still open

There is still a lot not done.

XMSS is missing.

RAM is measured only for LMS and ML-DSA-44.

I would like hardware SHA backend which can stream without paying transaction cost on every small update, but I do not have good design for this yet.

SLH-DSA-128f still has no code-size figure.

And some table values are still estimates which I do not trust very much.

That is fine for now. Better visible missing measurements than numbers which look exact and are not.
