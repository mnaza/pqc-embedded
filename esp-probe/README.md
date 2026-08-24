# esp-probe — LMS verification on real silicon

Runs an RFC 8554 Appendix F verification on hardware and times it with the CPU
cycle counter, against software SHA-256 and against the chip's SHA accelerator.

Everything else in this repository is cross-compiled and modelled: `.text` from a
linker, stack from `-Z emit-stack-sizes`, cost in SHA-256 compressions. All of it
is checkable and none of it had run until this.

## Results — ESP32-S3, 240 MHz, rev 0.2

```
LMS verification, RFC 8554 Appendix F test case 1
  public key 56 B, message 162 B, signature 1292 B, 4113 compressions

                     result     cycles     µs      cycles/compression
software SHA-256     Ok(())   33344505   138935         8107
hardware SHA-256     Ok(())   10159886    42332         2470
                                                        speedup 3.2x
```

**139 ms of boot time becomes 42 ms**, on the same chip, with the same verifier —
the only difference is which `Sha256Backend` it was handed.

### Why this matters beyond one board

LMS verification is over 99% SHA-256 by work, so a hash engine is close to the
whole cost. **The same silicon does nothing for ML-DSA**, which is NTT and
rejection sampling rather than hashing.

Most parts that do secure boot already ship a hash accelerator, because image
integrity needed one before signatures did. So the asymmetry is not a curiosity:
on exactly the class of part that carries a root of trust, hash-based signatures
get a large discount that lattice signatures do not.

### What these numbers are not

- **8095 cycles per compression in software is slow**, and that is the `sha2`
  crate's portable Rust at `opt-level = "s"` executing from flash. Hand-tuned
  assembly would do far better. The software row is a realistic *default*, not a
  floor.
- **2470 cycles per compression in hardware is still slow** for an accelerator:
  a 55-byte digest is one block and the engine wants on the order of a hundred
  cycles. Five backend versions were built and timed chasing that; the module docs
  in `src/hw_sha.rs` carry the table. The short version is that most of the
  remaining cost looks like APB register latency inside esp-hal's driver — sixteen
  words in, poll the busy flag, eight words out, on a bus slower than the core —
  rather than anything this file controls.
  
  **3.3× is what this integration achieves, not what the peripheral can do**, and
  DMA would not change it: there is nothing to stream in a 55-byte hash and the
  latency is per-transaction, not per-byte.
  
  Two faster versions exist and are not used. Buffering each digest whole was 10%
  quicker at 2209 and asserted on messages past two kilobytes — a firmware image is
  megabytes. Dropping `save`/`restore` was another 1.8% at 2427 and put a kilobyte
  of scratch back on the caller. Both trades went the same way: correctness and RAM
  over single-digit percentages of a 42 ms operation.
- One board, one vector, one clock setting. Nothing here is a benchmark suite.

## Building

**Run cargo from this directory.** The rustflags that add `-Tlinkall.x` live in
`.cargo/config.toml`, which cargo discovers from the working directory — building
with `--manifest-path` from the repository root silently omits them and the link
fails for reasons that look nothing like the cause.

Two architectures, so the toolchain and target are chosen per command rather than
pinned in a `rust-toolchain.toml`.

**ESP32-S3 (Xtensa)** — needs the `esp` Rust fork, and `-Zbuild-std=core` because
that fork ships no prebuilt `core` for Xtensa:

```sh
cargo +esp build --release --target xtensa-esp32s3-none-elf \
      --features esp32s3 -Zbuild-std=core
espflash flash --monitor target/xtensa-esp32s3-none-elf/release/esp-probe
```

**ESP32-C3 / C6 (RISC-V)** — stock stable Rust, stock rustup target, `rust-lld`.
No GCC, no fork, no `build-std`:

```sh
rustup target add riscv32imc-unknown-none-elf
cargo +stable build --release --target riscv32imc-unknown-none-elf --features esp32c3
```

Untested on hardware — no RISC-V board here. It links, which is the part that was
in doubt.

## Four things that each cost an hour, recorded so they cost nobody else one

**`-Tlinkall.x` is not optional.** Without esp-hal's linker script the memory
layout and symbols like `_stack_end_cpu0` are simply absent. On RISC-V that fails
loudly. On Xtensa it fails as `dangerous relocation: l32r: literal placed after
use` in `__pre_init`, which reads exactly like a compiler or toolchain bug and is
not one. **An earlier revision of this file blamed Xtensa GCC 15.2 and said a
global toolchain change was needed. That was wrong.** The rustflags were missing.

**The bootloader descriptor must match esp-hal's linker script.**
`esp-bootloader-esp-idf` 0.3 emits `.rodata_desc.appdesc`; esp-hal 1.1's
`linkall.x` places `.flash.appdesc`, which 0.5 emits. With the wrong pair the
descriptor lands somewhere inside `.rodata`, the bootloader reads the first bytes
of whatever is there, and reports something like *"image requires efuse blk rev
>= v123.38"*. `123.38` is `0x3032`, the ASCII bytes `"02"` — a string field being
read as a version number. Nothing about that message points at the real cause.

**The descriptor also needs a reference.** The macro carries no `#[used]`, so
`--gc-sections` drops it and the image flashes and is then rejected at boot.
`main` touches it through `black_box`.

**Big buffers do not go on the stack.** 2368 bytes of vectors plus 1088 of
verifier scratch overflows `main`'s stack. The failure is silent: the canary check
traps into `__stack_chk_fail`, which loops, and the symptom is output that stops
mid-line with no panic. They live in `.bss`.

## Safety

No eFuse is written by any of this. Secure Boot and flash encryption are disabled
on the board and nothing here needs them. Burning fuses is irreversible.

`__stack_chk_guard` is defined here as a constant because esp-hal expects a C
runtime to supply it. **A constant canary is not a security feature** — a real one
is random per boot. This is a measurement binary and it is stated rather than left
to be assumed.
