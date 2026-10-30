"""Conditional branches in the constant-time code, from an objdump listing
of bench/ct/dudect.zig's binary: for every function of p256, field_p256,
x25519 and field25519 (what is inlined into them included), the
conditional branches that go backward (loops over public counts) and
forward. A select the compiler turned into a branch on a secret is a
forward branch, so forward branches must be in bench/ct/allowed.txt:
"function count [mode]" lines, the most forward branches the function may
have (on public values: the table-ready flag, the DRBG's rejection loop,
error checks on public inputs and on results); a line for the build's
optimize mode takes precedence over one without. Prints a summary; exits
1 on a function over its allowance.
Usage: branches.py LISTING ARCH ALLOWED [MODE]
"""
import re
import sys

path, arch, allowed_path = sys.argv[1], sys.argv[2], sys.argv[3]
mode = sys.argv[4] if len(sys.argv) > 4 else None
allowed = {}
for line in open(allowed_path):
    fields = line.split("#")[0].split()
    if len(fields) == 2 or (len(fields) == 3 and fields[2] == mode):
        if len(fields) == 3 or fields[0] not in allowed:
            allowed[fields[0]] = int(fields[1])

watched = re.compile(r"^_?tls\.(p256|field_p256|x25519|field25519)\.")
head = re.compile(r"^([0-9a-f]+) <(.*)>:$")
forward, backward, where = {}, {}, {}
fn = None
for line in open(path):
    m = head.match(line.strip())
    if m:
        name = m.group(2).lstrip("_")
        fn = name if watched.match(name) else None
        if fn:
            forward.setdefault(fn, 0)
            backward.setdefault(fn, 0)
        continue
    if not fn:
        continue
    parts = line.split()
    if len(parts) < 3 or not parts[0].endswith(":"):
        continue
    op = parts[1]
    if arch == "x86_64":
        cond = op.startswith("j") and op not in ("jmp", "jmpq")
    else:
        cond = op.startswith("b.") or op in ("cbz", "cbnz", "tbz", "tbnz")
    if not cond:
        continue
    targets = [p for p in parts[2:] if re.fullmatch(r"0x[0-9a-f]+", p)]
    if not targets:
        continue
    addr = int(parts[0][:-1], 16)
    if int(targets[-1], 16) > addr:
        forward[fn] += 1
        where.setdefault(fn, []).append(parts[0][:-1])
    else:
        backward[fn] += 1

if not forward:
    print(f"{path}: no p256/x25519 functions found")
    sys.exit(1)
bad = False
for f in sorted(forward):
    # Generic instances carry their arguments in the name: match the base.
    base = re.sub(r"__anon_\d+|\(.*", "", f)
    limit = allowed.get(f, allowed.get(base, 0))
    over = forward[f] > limit
    bad |= over
    if forward[f] or over:
        mark = "OVER" if over else "ok"
        print(f"  {mark:4s} {f:44s} forward={forward[f]:3d} (allowed {limit}) backward={backward[f]:3d}" + (f"  at {' '.join(where[f][:6])}" if over else ""))
print(f"  {len(forward)} functions scanned, {sum(backward.values())} backward and {sum(forward.values())} forward conditional branches" + (": FAIL" if bad else ""))
sys.exit(1 if bad else 0)
