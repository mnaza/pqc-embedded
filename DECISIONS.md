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

### Asked on r/rust: what made you change the trait twice

Short version, because the two changes had different causes.

**First version had `sha2` hardcoded.** There was no trait at all and nothing
wrong with that. Then I wanted to use the ESP32 SHA peripheral, and that is when
the trait appeared. That change was ordinary.

**The second change is the interesting one**, and it came from a constraint I got
wrong.

LMS verification keeps two hash states alive at the same time. `Kc` collects the
chain outputs, and producing a single chain output needs many hashes by itself.
In software this is a non-problem. You keep two `Sha256` objects and forget about
it. The peripheral has one context.

So my first solution was to make the caller pass a scratch buffer. Chain outputs
went there, and `Kc` was hashed at the end over the whole thing. That is `p * 32`
bytes, 1088 for `w = 8`, and it cost 664 bytes of stack.

It worked. Then I looked at the peripheral again and found it can save and
restore its own state. And `sha2::Sha256` is `Clone`. So both backends can park a
digest instead of me collecting outputs by hand.

Save and restore went into the trait, the scratch parameter disappeared, and the
final version uses **less stack than the original that had no hardware support at
all**.

The lesson I took is not about traits. My first solution was working around a
hardware limitation which was not really there. I had read the peripheral as
"one context, therefore one digest" and never checked whether it could put a
context down and pick it up again. It can, and it says so.

On the S3 that costs 34 extra save/restore round trips per verification, about
1.8% of a 42 ms operation, and it saves roughly 1 KB of RAM.

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

FN-DSA was asked for on r/rust. Reasonable ask, and the person making it had the right
reason: FIPS standardised three so that there is a plan B and a plan C.

It fits better than it looks. This is verify-only, and verification is the half of FALCON
which does not touch floating point. That problem belongs to signing. Pornin has fn-dsa
with a separate fn-dsa-vrfy crate for embedded verify-only cases, and it is no_std. So it
drops into the same shape as the other three instead of needing special handling.

The reason to want it is size. Signatures are much smaller than ML-DSA. That is the
constraint which actually bites on a small part, and it is what this repo is about.

Not promised. But it is the next one if there is a next one.

**Done, 2026-09-02.** `fn-dsa-vrfy` 0.4 dropped in with no special handling, exactly as expected.

The result is better than I expected and I want to write down why, because I nearly did not add it.

Measured on the four probe targets, FN-DSA-512 has less scheme-only code than ML-DSA-44 everywhere. 9376 against 11049 on Cortex-M4F. Its key is 897 bytes against 1312 and its signature is 666 against 2420. So it wins on all three of the numbers this repository cares about.

I had assumed FALCON would be the awkward one because of floating point. That is a signing problem. Verification never touches it. My assumption was about the scheme; the constraint was about the operation.

One deliberate choice in the probe. `VerifyingKeyStandard` accepts degree 512 or 1024, so it carries the array for the larger one either way. A boot verifier knows its degree at build time and should pay for one. That is worth about 2 KB of RAM, and hiding it inside a convenience type is the sort of thing this table exists to expose.

RAM is not measured. I read the arrays out of the crate: 1024 in the key, 1024 and 2048 on the stack in `verify`, plus hash state. Around 4400.

That is the same method which under-reported LMS and sent me to hardware. So it is a floor, and it is marked estimated. Until it is measured on a target it should not decide anything.


LMS state management was raised on r/rust and the objection is better than what I wrote.

My argument for LMS in firmware signing was that a build system signs a known number of
images and can keep state in one place. That is true for one signing box. It is not true
for a vendor running geographically redundant signing appliances, which is what a large
one does. Then state is distributed, and for a one-time-key scheme a synchronisation
failure is not downtime, it is key reuse, and key reuse means forgeable signatures.

I gave this one line. SP 800-208 gives it many pages. That was the weak part of the
README and it deserved to be found.

It also agrees with my own numbers, which is what makes it uncomfortable. ML-DSA-44
verifies in 17.3 ms in software against 41.7 ms for LMS with the SHA accelerator, so LMS
is 2.4x slower even when the hardware helps. LMS wins on RAM, about 1 KB against 34 KB,
and that is the only axis where it wins. Adding an operational cost that grows with the
size of the signing organisation narrows LMS further: constrained parts, single signing
authority.

Not changing the code for this. It changes what the README is allowed to claim.

One clarification I also owed, because I described it badly the first time. The SHA
problem here is not several implementations of the algorithm. LMS verification needs two
digests live at the same time, message hash and tree chain, and a hardware SHA peripheral
has one context register. A single audited implementation does not help, because the
constraint is the peripheral and not the code.



## The README led with the wrong thing

Two people on r/rust said the same thing in different words. One said the numbers
that matter are ML-DSA's, because that is what will actually get used. The other
said "overall this doesn't tell me much".

They were both right and I said so at the time. The comparison I care most about
was sitting halfway down a six-hundred-line page, after every section about LMS.
The repository led with LMS because that is where I started. That is a fact about
me, not a reason for a reader.

So the comparison moved to the top, and it now carries the operational argument
as well as the numbers, because the two point the same way. LMS wins on RAM by
roughly 30x and loses on everything else, and distributed signing state turns its
one advantage into a liability for any vendor big enough to need geographic
redundancy. What is left is genuinely constrained parts with a single signing
authority.

The uncomfortable part is that my own measurements said this before the comments
did. I had the ML-DSA numbers. I just had them in the wrong place.

## On calling the sha2 difference a regression

I should not have. I measured a difference between 0.10 and 0.11 and I never
found out why. It could be a deliberate speed against size trade. The README now
says that.

The reason it mattered is that at the time I was comparing whole verifier
binaries, so part of what looked like a bigger signature scheme was a bigger
hash arriving as a dependency. That is what the baseline subtraction is for, and
noticing this is what put it there.


## The FN-DSA RAM estimate was wrong in the direction I was sure about

I estimated 4400 bytes by adding the arrays the crate declares: 1024 for the
key's `h`, 1024 and 2048 for the two scratch buffers in `verify`, plus hash
state. I wrote that it should be read as a floor, because deriving RAM from
source is what under-reported LMS badly enough that I went to hardware.

Measured on an ESP32-S3: **3708 bytes.**

The estimate was high. Those three arrays alone come to 4096, so the compiler is
not keeping them all live at once, and I have not worked out what it does
instead. I could guess, and a guess is what got me here.

What I take from it is narrower than "estimates are unreliable". It is that an
estimate has no direction you can lean on. I had a reason to expect low and the
reason was sound and it was still wrong. This is why the table records where a
number came from and not how confident I was.

## Timing, and a display bug that had been lying

Full numbers on one chip, same 162-byte message:

```text
scheme            verify      stack
LMS software     138.9 ms      1152
LMS + SHA engine  41.7 ms      2600
ML-DSA-44         17.3 ms     34044
FN-DSA-512         3.9 ms      3708
```

FN-DSA-512 is the fastest by a distance, gets nothing from the SHA accelerator,
and its stack sits nearer LMS than ML-DSA. Adding it was somebody else's idea.

While reading that output I found the probe had been printing `vs LMS+hw 0.4x
slower` for ML-DSA. Integer division of the faster time by the slower one, which
rounds to zero and then reads as a claim that ML-DSA is slower than LMS. It is
2.4x faster. The line had been wrong for as long as it had existed, in a
direction that flattered the scheme this repository started out about.
