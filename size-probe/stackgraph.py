"""Peak stack for a bare-metal binary, from frame sizes plus a call graph.

`-Z emit-stack-sizes` gives one frame size per function and says nothing about who
calls whom. The previous version of this script closed that gap by hand, listing
the LMS call chain from the disassembly, which was fine for one binary and useless
for any other — and ML-DSA needed measuring too.

This reads the call graph out of the disassembly instead: every direct call is an
edge, and the answer is the heaviest path from the entry point. That makes the
number an upper bound rather than an estimate, and it works for any binary.

    stackgraph.py <stack_sizes.bin> <nm.txt> <objdump.txt> [root] [-v]

Both inputs must use **mangled** symbol names. Demangling one and not the other
makes every name fail to match, the graph comes out empty, and the answer is the
entry frame alone — which looks plausible and is half the truth. That happened.

# This is a LOWER bound, not an upper one

That was the intention and it is not what came out. On the LMS binary for
`thumbv7em` this finds **55 call sites it cannot resolve** — `blx` through a
register, tail calls compiled to plain branches, anything the linker turned into an
outlined thunk. Every one of them is an edge missing from the graph, and every
missing edge can only make the answer smaller.

Concretely: this reported 720 bytes where the frames along the verifier's actual
call chain — `_start`, the backend impl, the digest wrapper, `compress256`, the
round function — sum to about 1260. It found `_start` and one callee and stopped.

So the number is useful for **spotting a regression** between two builds of the
same code, and it must not be used as a stack budget. The figure that can be is in
`esp-probe`, which paints the stack and reads the high-water mark on the board
after a real verification. Measurement beats modelling here, and the hardware was
already on the desk.

**Recursion.** A cycle makes "heaviest path" meaningless, so it is reported as an
error rather than silently bounded. Neither LMS nor ML-DSA verification recurses.
"""

import re
import struct
import sys

ss_path, nm_path, dump_path = sys.argv[1], sys.argv[2], sys.argv[3]
root = "_start"
if len(sys.argv) > 4 and not sys.argv[4].startswith("-"):
    root = sys.argv[4]

# Symbol addresses, so .stack_sizes entries can be named.
addr_to_name = {}
for line in open(nm_path):
    parts = line.split(None, 3)
    if len(parts) >= 4 and parts[2] in "tTwW":
        addr_to_name[int(parts[0], 16)] = parts[3].strip()

frames = {}
data = open(ss_path, "rb").read()
i = 0
while i + 4 <= len(data):
    addr = struct.unpack_from("<I", data, i)[0]
    i += 4
    val = shift = 0
    while i < len(data):
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    # Thumb symbol addresses carry the interworking bit.
    name = addr_to_name.get(addr) or addr_to_name.get(addr & ~1)
    if name:
        frames[name] = max(frames.get(name, 0), val)

CALL = re.compile(r"\t(bl|blx|jal|jalr|call4|call8|call12|callx4|callx8|callx12)\t")
TARGET = re.compile(r"<([^<>]+)>")
HEADER = re.compile(r"^[0-9a-f]+ <(.+)>:$")

edges = {}
current = None
indirect = 0
for line in open(dump_path, errors="replace"):
    line = line.rstrip("\n")
    m = HEADER.match(line)
    if m:
        current = m.group(1)
        edges.setdefault(current, set())
        continue
    if current is None or not CALL.search(line):
        continue
    targets = TARGET.findall(line)
    if not targets:
        indirect += 1
        continue
    callee = targets[-1].split("+")[0]
    edges[current].add(callee)

WHITE, GREY, BLACK = 0, 1, 2
colour = {}
best = {}


def walk(fn):
    """Heaviest path from `fn` inclusive, or raise on recursion."""
    if colour.get(fn, WHITE) == GREY:
        raise SystemExit(f"recursion through {fn}: no finite bound")
    if colour.get(fn, WHITE) == BLACK:
        return best[fn]
    colour[fn] = GREY
    deepest = max((walk(c) for c in edges.get(fn, ())), default=0)
    best[fn] = frames.get(fn, 0) + deepest
    colour[fn] = BLACK
    return best[fn]


if root not in edges and root not in frames:
    raise SystemExit(f"root {root} not found")

total = walk(root)

if "-v" in sys.argv:
    print(f"# {indirect} indirect call sites unresolved", file=sys.stderr)
    print(f"# {len(frames)} frames, {sum(len(v) for v in edges.values())} edges",
          file=sys.stderr)
    fn = root
    while fn:
        print(f"#   {frames.get(fn, 0):6}  {fn[:78]}", file=sys.stderr)
        callees = [(best.get(c, 0), c) for c in edges.get(fn, ())]
        fn = max(callees)[1] if callees and max(callees)[0] > 0 else None

print(total)
