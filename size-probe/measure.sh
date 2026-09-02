#!/usr/bin/env bash
# Regenerate the code-size figures in `boot-budget`.
#
# Two columns per scheme:
#
# total        .text of a --gc-sections binary that verifies one signature
# scheme-only  the same, minus a baseline built from the hash that scheme uses
#
# The second exists because the first is not comparable. Different schemes pull
# different hash crates -- and different *versions*: `lms-verify` uses sha2 0.10,
# while p256 and slh-dsa require 0.11, whose SHA-256 compiles to 8840 bytes against
# 3880. Ed25519's SHA-512 is 28856. Those differences are larger than the
# differences between the signature schemes, so a table of totals would mostly be a
# table of hash implementations.
#
# Subtraction is approximate. Shared machinery and inlining mean the baseline is
# not a clean partition, and every figure is one implementation of one scheme -- a
# size-optimised assembly ECDSA, which is what a real boot ROM ships, would be a
# fraction of what the `p256` crate measures here.
#
# Stack is not measured by this script; see esp-probe, which paints the stack on
# real hardware. The static pass in stackgraph.py under-reports and is kept only
# for spotting regressions.
set -euo pipefail
cd "$(dirname "$0")"

TARGETS=(thumbv6m-none-eabi thumbv7em-none-eabihf riscv32imc-unknown-none-elf riscv32imac-unknown-none-elf)

# scheme:binary:baseline-binary
SCHEMES=(
    "LMS w8/h5:size-probe:sha_only"
    "ML-DSA-44:mldsa_only:shake256_only"
    "ML-DSA-65:mldsa65_only:shake256_only"
    "ML-DSA-87:mldsa87_only:shake256_only"
    "SLH-DSA-128s:slhdsa128s_only:sha256_v11_only"
    "FN-DSA-512:fndsa512_only:shake256_only"
    "ECDSA P-256:ecdsa_p256_only:sha256_v11_only"
    "Ed25519:ed25519_only:sha512_v11_only"
)
BASELINES=(sha_only sha256_v11_only sha512_v11_only shake256_only)

text() { llvm-size --format=sysv "target/$1/release/$2" | awk '/^\.text/{print $2}'; }

for T in "${TARGETS[@]}"; do
    cargo build --release --target "$T" -q
    echo "=== $T ==="
    printf "  %-16s %8s %10s %13s\n" scheme total hash-base scheme-only
    for entry in "${SCHEMES[@]}"; do
        NAME="${entry%%:*}"; REST="${entry#*:}"
        BIN="${REST%%:*}"; BASE_BIN="${REST##*:}"
        TOT=$(text "$T" "$BIN"); BASE=$(text "$T" "$BASE_BIN")
        printf "  %-16s %8s %10s %13s\n" "$NAME" "$TOT" "$BASE" "$((TOT - BASE))"
    done
    printf "  %-16s" "hash baselines"
    for B in "${BASELINES[@]}"; do printf " %s=%s" "${B%_only}" "$(text "$T" "$B")"; done
    echo; echo
done
