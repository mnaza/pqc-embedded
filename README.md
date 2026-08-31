# pqc-embedded

Four small Rust crates about post-quantum signatures on small embedded targets.

Main question behind this repository is pretty simple:

**if device already has secure boot, what is needed to make it quantum secure?**

Nothing here is production code. See [Status](#status).

```text
crates/
  lms-verify    LMS and HSS (RFC 8554) verification — no_std, no allocator
  boot-budget   what bootloader needs from a scheme, and if it fits
  ct-probe      dudect-style timing-leakage detection
  masked        first-order Boolean masking gadgets
```

## Why these four

Rust PQ ecosystem is already not empty.

RustCrypto has `ml-kem`, `ml-dsa` and `slh-dsa`. Cryspen's `libcrux` has formally verified ML-KEM and it is used in Firefox. `pqcrypto` provides PQClean bindings. `rustls` already negotiates X25519MLKEM768.

So I did not see much point to implement ML-DSA one more time. It would be interesting as learning project, but result is another unaudited lattice implementation which nobody should use. Not very useful.

The gaps I found more interesting are these:

| Gap                                                                    | Crate         |
| ---------------------------------------------------------------------- | ------------- |
| Hash-based firmware signatures have not much Rust support              | `lms-verify`  |
| Flash/RAM/OTP numbers used for scheme choice are usually not published | `boot-budget` |
| There is very little tooling for timing leakage in verification code   | `ct-probe`    |
| Masking gadgets in Rust are almost absent                              | `masked`      |

## Verification only

`lms-verify` only verifies.

There is no signing and no key generation.

For secure boot this is enough. Device only verifies firmware. Signing key should stay on build server or in HSM, not inside the target.

Verification-only also makes code much smaller and there is no secret signing state to protect.

One important detail: verifier is not constant time, and this is intentional.

Constant time means execution should not depend on secret values. Here message, signature and public key are all public. There is no secret in verifier, so variable execution time is not leaking a secret.

This comes back later in the `ct-probe` example.

## Why LMS for boot

LMS is hash based.

Security depends basically on hash function. No lattice arithmetic, rejection sampling, NTT, big tables etc.

On normal machine this maybe does not sound very important. On boot ROM with 16 KB or 32 KB, it matters a lot.

The annoying part of LMS is stateful signing keys. For general signing this is really a problem because reusing state can destroy security.

For firmware signing I think it is much less bad. Build system signs a known number of images and can keep state in one place. NIST SP 800-208 also approves LMS and XMSS for this type of stateful hash-based signature use.

But "state in one place" is doing a lot of work in that sentence, and it does not hold everywhere. A large vendor with geographically redundant signing appliances cannot keep state in one place by definition. Then the state is distributed, and for a one-time-key scheme a synchronisation failure is not downtime. It is key reuse, which means forgeable signatures. SP 800-208 spends many pages on exactly this and I gave it one line.

So the operational cost of LMS grows with the size of the signing organisation, while the RAM benefit stays the same. This narrows LMS to constrained parts with a single signing authority. Credit for this: jodonoghue on r/rust.

Run:

```sh
cargo run -p boot-budget --example table
cargo run --release -p lms-verify --example cost_distribution
cargo run --release -p lms-verify --example timing_evidence
```

Example comparison:

```text
scheme            pubkey      sig     tight boot ROM
ECDSA P-256           33       64               fits   classical
LMS w8/h5             56     1292               fits   hash-based, stateful
ML-DSA-44           1312     2420              flash
SLH-DSA-128s          32     7856               fits   hash-based
```

ML-DSA has big public key. SLH-DSA has big signature. LMS is somewhere reasonable on both.

Also OTP does not need to contain complete public key. Root of trust can store 32-byte digest of public key.

So argument like "post-quantum key does not fit in fuses" is in many cases not really the problem.

## Measurements

LMS code sizes below are from real builds. `size-probe/measure.sh` reproduces them.

```text
target                        core              total  sha-only  marginal
thumbv6m-none-eabi            Cortex-M0+         5568      3928      1640
thumbv7em-none-eabihf         Cortex-M4F         5464      3808      1656
riscv32imc-unknown-none-elf   RISC-V rv32imc     6652      4384      2268
riscv32imac-unknown-none-elf  RISC-V rv32imac    6652      4384      2268
```

RAM I measure on hardware instead of calculating from source or disassembly. I tried the static way first and it gave numbers which were too low. More about that below.

ESP32-S3 at 240 MHz:

```text
                           cycles       µs   frames   backend   total RAM
software (sha2)          33344698   138936     1040       112        1152
SHA accelerator          10159573    42331      272      2328        2600
```

Something I did not expect first: **verifier is smaller than SHA-256 implementation** on all measured targets.

For secure boot this is useful because normally SHA-256 is already there for firmware image integrity.

So if hash is already linked, more interesting number is `marginal`, not total.

For these builds, adding LMS verification is around **1.6–2.3 KB flash**, and software version uses around **1.1 KB RAM**.

Hardware SHA accelerator is about 3.3x faster, but surprisingly it uses more RAM.

Most of this 2328 bytes is coalescing buffer. The buffer lets software feed peripheral one time per digest instead of many smaller writes. I tried shrinking it to 256 bytes and verification became around 5% slower.

So bigger buffer is not only waste. It buys some speed.

Which one is better depends on target.

### What exactly is measured

`total` is `.text` from a `no_std` binary which calls `verify`.

Build uses `--gc-sections`, `opt-level = "z"` and LTO.

Inputs are read through volatile pointers. This is important.

If inputs are normal constants, LLVM is smart enough to calculate verification during compile and remove basically whole verifier. Then binary is very small, but number means nothing.

I found this the hard way because first result looked almost too good.

## Static stack analysis did not work well

Original plan was to calculate stack statically.

`-Z emit-stack-sizes` gives stack frame size for each function. Then call graph can be recovered from disassembly and you can find biggest path.

`size-probe/stackgraph.py` does this.

Problem is call graph from real optimised binary is not so clean.

On `thumbv7em` build the script cannot resolve **55 call sites**. Some are indirect calls through registers, some tail calls which became normal branches, some linker thunks.

Every missing edge makes result too small, never too big.

The tool reported 720 bytes.

Known verifier call path by itself adds to around 1260 bytes.

For me a stack number which is too low is worse than no number. Someone can copy it into memory budget and then device crashes in boot.

So static pass stays because it can still show regressions between builds, but I call it lower bound.

For real RAM figure I measure on target.

`esp-probe` fills 32 KB below stack pointer with pattern, runs verification, and looks how much of pattern was overwritten. Pretty standard embedded stack watermark method.

Backend object is owned by caller, so it is not inside painted stack region. I report it separately.

This matters especially for hardware SHA backend. Otherwise hardware version looks like it uses very little RAM, which is not true.

## One optimisation surprise

The size probe already found one thing I probably would not notice only reading source.

`cost` got a second call site to `coef`.

At `opt-level = "z"`, LLVM stopped inlining `coef` and made it a separate function.

Normally this makes sense. Two call sites, shared function, less duplicated code.

But forcing `#[inline(always)]` gave this:

```text
                  outlined   inlined
Cortex-M0+            2032      1624     -408  (-20%)
Cortex-M4F            1592      1640      +48   (+3%)
RISC-V rv32imc        2244      2292      +48   (+2%)
```

So on M0+ inlining saves 408 bytes, around 20%.

On M4F and RISC-V it costs 48 bytes.

I keep the attribute.

For 16 KB boot ROM, 408 bytes can matter. On target with 64 KB, losing 48 bytes is not so important.

This is also good example why I prefer measuring compiler output instead of deciding from source what "should" be smaller.

## Code size for other schemes

`size-probe/measure.sh` also builds other verifiers.

Comparing only final binary size is not very fair because each scheme brings different hash crate, sometimes even another version of same crate.

And this difference is actually quite big.

So I subtract a baseline build with the hash implementation that scheme uses.

Cortex-M4F:

```text
                     total   hash-base   scheme-only
LMS w8/h5             5464        3808          1656
SLH-DSA-128s         15352        8776          6576
ML-DSA-44            13497        2448         11049
Ed25519              41592       28784         12808
ECDSA P-256          25408        8776         16632

hash baselines:
  sha2-0.10 SHA-256    3808
  sha2-0.11 SHA-256    8776
  SHA-512             28784
  SHAKE-256            2448
```

One funny result is classical schemes are not smallest here.

ECDSA P-256 has more scheme-only code than ML-DSA-44 in these builds. LMS is much smaller than both.

But more surprising for me was hash sizes.

Baselines are from 2448 to 28784 bytes.

Even `sha2` version makes big difference: SHA-256 from `sha2` 0.10 is 3808 bytes here, and from 0.11 it is 8776.

Same hash algorithm, same target, more than 2x size.

On RISC-V SHA-512 baseline reaches 51552 bytes.

So before spending lots of time choosing signature algorithm to save 2 KB, maybe check what hash crate is doing first.

These figures are not "algorithm sizes". They are sizes of specific Rust implementations built with specific compiler and flags.

For example, a hand-written size-optimised ECDSA implementation in real boot ROM can probably be much smaller than `p256` crate here.

Also subtraction is not perfect. Inlining and shared code means `total - hash-base` is not exact independent contribution.

ML-DSA parameter sets are almost same in code size:

```text
ML-DSA-44   11049
ML-DSA-65   11257
ML-DSA-87   11209
```

So higher parameter sets mostly cost in key size, signature size and RAM, not much in flash code.

## Compiler changes the numbers

All measurements depend on compiler version.

Current size numbers use `rustc 1.98.0`.

ESP32-S3 measurements use Xtensa `esp` Rust fork, so this is another toolchain.

Moving from 1.97.1 to 1.98.0 moved most totals by around 64 bytes. Most difference was actually inside hash baseline.

Scheme-only numbers moved from around +8 to -160 bytes.

Nothing important changed in ordering.

So exact byte numbers are compiler-dependent, but main conclusion survived one compiler update at least.

`Cargo.lock` is committed for same reason. Dependency version changes moved numbers more than Rust compiler version did.

## LMS vs ML-DSA on same chip

This is probably the comparison I care most about.

ESP32-S3, 240 MHz:

|                         | LMS w8/h5 |            ML-DSA-44 |
| ----------------------- | --------: | -------------------: |
| code (`.text`)          |      5464 |                13497 |
| public key              |        56 |                 1312 |
| signature               |      1292 |                 2420 |
| RAM                     |      1152 |            **34044** |
| verify, software        |  138.9 ms |          **17.3 ms** |
| verify, with SHA engine |   41.7 ms | not possible — SHAKE |

ML-DSA is much faster.

Even after using SHA accelerator, LMS is still about 2.4x slower.

But RAM is opposite: ML-DSA-44 uses about 34 KB, while LMS software path uses little over 1 KB.

This changed my initial conclusion.

At first I expected hardware SHA to be one of strongest arguments for LMS: chip already has SHA engine, LMS uses it, ML-DSA uses SHAKE so accelerator does nothing.

All of this is true.

But 3.3x acceleration is still not enough to make LMS faster than ML-DSA.

So it is not really "LMS wins because SHA hardware".

The question is which budget is tight.

If device has 8 KB RAM, LMS fits and this ML-DSA implementation simply cannot run.

Interesting thing is flash is not the problem. 13497 bytes might fit. RAM is what kills it.

If device has 256 KB RAM then situation is different, and maybe ML-DSA speed becomes more important.

Earlier I had estimate of around 12 KB RAM for ML-DSA-44.

That estimate said it would fit on 32 KB part.

Measurement says 34 KB, so no.

This is exactly why I started caring about `Provenance`. An estimate which changes yes/no fit result is not "close enough".

Some other numbers are still estimates, especially RAM for ML-DSA-65, ML-DSA-87 and SLH-DSA. I would not make hardware decision based on those yet.

## Immutable boot ROM is the real problem

For signatures there is no harvest-now-decrypt-later problem like with encryption.

Nobody stores firmware signature today and somehow forges yesterday's boot later.

Problem is different.

> A device shipped with ECC-only trust root in immutable boot ROM cannot upgrade this root later. For this device, post-quantum migration deadline is not when quantum computer arrives. It was tape-out.

This is main reason I think boot is interesting case.

## Two hashes, one peripheral

LMS verification needs two hash states alive.

`Kc` collects chain outputs, but calculating one chain output itself requires many hashes.

Software does not care. Just keep two `Sha256` objects.

Hardware SHA peripheral usually has only one state.

This changed API two times.

First version stored all chain outputs into caller-provided scratch memory.

For `w = 8`, that is `p * 32 = 1088` bytes.

It worked, but stack went up by 664 bytes compared to version without hardware support.

Then I looked at peripheral again.

ESP32 SHA can save and restore state. `sha2::Sha256` can also be cloned.

So both software and hardware backends can checkpoint a digest.

`Sha256Backend::save` / `restore` does this now.

Scratch buffer disappeared and verifier still has one code path.

```text
Cortex-M4F              original   + hw backend, scratch   + checkpointing
code                        1536                    1712              1648
stack                       1180                    1844              1092
```

These three are from Rust 1.97.1 so compiler is same between columns. Current 1.98.0 code size is 1656.

Final version actually uses less stack than original software-only design.

It costs 112 bytes more code.

On S3 there are 34 extra peripheral save/restore round trips per verification. This is around 1.8% of 42 ms operation, and saves about 1 KB RAM.

The scratch-buffer version was in repository for some time before I changed it.

I keep the numbers because they are useful reminder that first solution to hardware limitation is sometimes not a good one.

## HSS

`lms-verify::hss` verifies HSS from RFC 8554 §6.

This is probably more realistic deployment than one huge LMS tree.

For example one tree with `h = 25` gives around 33 million signatures, but it also needs around 33 million leaf calculations to generate complete tree. This can take very long before key is ready.

HSS chains smaller trees.

Root tree signs child public key. Child signs messages. More levels multiply capacity.

Two details are maybe not obvious.

Verification cost is linear with number of HSS levels.

And verifier learns intermediate public keys from signature itself. It does not need them in OTP. Only root key is trusted.

So OTP requirement is same as bare LMS.

HSS also made RFC tests better.

RFC 8554 Appendix F gives HSS vectors. Before HSS support I was taking those vectors apart to test LMS.

Now HSS verifier checks them with original framing too: `L`, `Nspk`, and rule that values agree.

Test data is shared between bare-LMS and HSS tests so there are not two copies which can get different over time.

## Boot time is also a budget

Flash and RAM are obvious, but boot also has deadline.

`lms-verify::cost` counts verification work in SHA-256 compression calls.

I use compressions instead of milliseconds because compressions do not depend on CPU clock or architecture.

There is also a test that calculates expected cost, counts real compression calls during verification, and checks both values are exactly same.

LMS verification cost is not constant.

Each Winternitz chain starts from coefficient derived from hash and walks until `2^w - 1`.

So different messages cause different chain lengths.

Example:

```sh
cargo run --release -p lms-verify --example cost_distribution
```

200k sampled signatures:

```text
LMOTS w=8, LMS h=10, 32 KiB image      compressions
  theoretical min                               552
  measured median                              4887
  measured p99                                 5907
  theoretical max                              8967   <- hard real-time bound
  worst / median                              1.83x
```

The maximum is real hard bound.

For hard real-time system you need to care about it.

But it is also pretty pessimistic for normal budgeting because to reach worst case the hash coefficients need to be extremely unlucky.

Measured distribution is much tighter.

For normal boot-time estimate, p99 can be more useful. For hard deadline, use max.

### `w=4` vs `w=8`

This trade surprised me a little:

```text
              signature     compressions
w=8                1452             4887
w=4                2508             1070
w=4 - w=8         +1056            -3817
```

Smaller signature means slower verification.

`w=8` has 34 chains with up to 255 steps.

`w=4` has 67 chains but only up to 15 steps each.

So `w=4` adds 1056 bytes to firmware signature, but saves around 3800 SHA compression calls every boot.

On 168 MHz with software SHA-256 this is about 22 ms in my numbers.

Maybe flash is more important. Maybe boot time is more important.

Without both numbers you cannot really decide.

## ct-probe

`ct-probe` is basically dudect-style testing: two classes of inputs, Welch t-test, percentile cropping.

Run:

```sh
cargo run --release -p ct-probe --example naive_vs_ct
```

Example result:

```text
naive_eq   max |t| = 318.37  →  LEAKS — clear timing dependence on the input class
ct_eq      max |t| =   1.82  →  no evidence of leakage at this sample size
```

Use `--release`.

Debug build can have enough noise that even bad early-exit comparison looks fine.

This is an important point: test measures binary you execute, not source code you are looking at.

Known problems:

* It can show leakage evidence but cannot prove no leakage.
* Running on x86 does not say much about Cortex-M.
* `Instant` has not great timing resolution for this.
* CPU frequency scaling adds noise.
* Serious measurement should probably use cycle counter.

This crate is mostly a small experiment, not a replacement for proper leakage lab setup.

## masked

`masked` contains first-order masking gadgets.

ISW for AND and Goubin for Boolean-to-arithmetic conversion.

Functional tests pass.

But functional correctness is not the hard part with masking.

Masking assumes shares stay separate.

Rust compiler does not promise this. LLVM also does not care about masking security model. It can recompute secret, put both shares next to each other on stack, merge expressions, spill things, etc. As long as result is same, optimiser is happy.

I put `black_box` barriers between gadget steps to stop some obvious optimisation.

This is not a security guarantee.

`black_box` is not documented as masking primitive and I don't treat it like one.

Real implementation would need assembly, or at minimum serious inspection of generated machine code.

No leakage measurements were done for `masked` yet.

So current claim is only:

**these are the intended masking gadgets and they are functionally correct.**

Not:

**this compiled Rust code is proven masked.**

Because I don't know that.

## Timing leakage result from LMS

`timing_evidence` intentionally gives a ridiculous result:

```sh
cargo run --release -p lms-verify --example timing_evidence
```

`ct-probe` normally reports `|t| > 400`.

This looks terrible if you only look at threshold.

But it is expected.

Verification time changes with message because message hash controls chain lengths.

So of course timing distributions of two message classes can be different.

The important question for a side channel is: what secret does this reveal?

Here there is no secret.

Message is public. Signature is public. Public key is public.

So tool found timing dependence, but not security leak.

I think this distinction gets lost sometimes. "Not constant time" and "timing vulnerability" are not same sentence.

A signer would be different because private key is secret.

There is no signer in this repository on purpose.

## Status

**Not audited. Do not put this in a product.**

`lms-verify` is tested against RFC 8554 Appendix F vectors.

RFC vectors are HSS objects, not plain LMS signatures.

For bare LMS tests I split each HSS object into parts. With `Nspk = 1`, signature contains root LMS signature over serialized level-1 public key, then that public key, then second LMS signature over message.

Both parts verify independently.

This gives four bare-LMS vectors over parameter sets implemented here, including H5/W8 and H10/W4.

There are also negative tests for corrupted signature regions, wrong keys, swapped signatures, wrong leaf indexes, typecode mismatch, truncation and malformed HSS framing.

HSS verifier also checks RFC vectors in their original HSS format now.

This is useful, but it is not audit.

Known-answer tests show tested inputs behave how expected. They do not show all possible malformed inputs are handled correctly, and they say nothing about code review quality.

For `boot-budget`, pay attention to provenance of each number.

Measurements described as measured in this README come from actual builds or target runs. Some other parameter sets still have estimates, especially RAM figures, and I don't think those should be used for hard fit decisions before target measurement.

## Running it

```sh
cargo test
cargo clippy --all-targets

cargo run -p boot-budget --example table
cargo run --release -p lms-verify --example cost_distribution
cargo run --release -p lms-verify --example timing_evidence
cargo run --release -p ct-probe --example naive_vs_ct

./size-probe/measure.sh
```

Current test suite has 75 tests, including 16 RFC 8554 KATs.

`measure.sh` needs four bare-metal targets, `llvm-size`, `nm`, `objcopy`, and nightly Rust for `-Z emit-stack-sizes`.

Stable is enough if you only want code-size numbers.

## License

MIT OR Apache-2.0
