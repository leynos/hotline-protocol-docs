# Receive-limit origin and indexed reference boundary

This bounded GAP-011 note records 12 read-only GhidraMCP calls against a saved,
independent analysis of the hashed Hotline Server 1.9 PEF. The
[as-run query record][corpus] keeps exact arguments, output, the script and
checksums. The project had 1,840 functions; it was reopened with
`--no-analyze --discard`. No native server or GUI was queried in this batch.

## Positive native-code comparison

The image's four bytes at global `10094a50` are `00 20 00 00` (2 MiB), but the
[headless startup decompilation][startup] exactly matches the earlier GUI
record: `100007b0` assigns `0x80000` (512 KiB) to `_DAT_10094a50` **before**
calling configuration loader `10008fd0`. The
[complete startup assembly][startup-asm] has 592 instructions and pins this
sequence:

| Address    | Bytes      | PowerPC instruction |
| ---------- | ---------- | ------------------- |
| `10000b84` | `3c000008` | `lis r0,0x8`        |
| `10000b88` | `38624330` | `addi r3,r2,0x4330` |
| `10000b8c` | `90030000` | `stw r0,0x0(r3)`    |
| `10000b9c` | `48008435` | `bl 0x10008fd0`     |

The matching decompilation maps the store to `_DAT_10094a50`. The assembly
itself shows an **`r2`-relative address calculation and store**. Separately,
[bytes at data slot `10088d90`][pointer] are `10 09 4a 50`, a pointer to the
same global. The [direct-reference query][global-xrefs] reports one data
reference from that slot to the global; [outgoing references][outgoing] from
the slot agree. The [slot xref query][slot-xrefs] returns zero indexed users.
The role, if any, of that slot in code access is unproved. Zero indexed slot
xrefs cannot negate the observed startup store or exclude TOC-relative or
indirect accesses elsewhere.

The [receiver decompilation][receiver] at `100590e0` exactly matches the GUI
record, and all 219 [receiver instruction address/byte pairs][receiver-asm]
match. It rejects either total or data size when zero or **greater than** the
current global. The retained [native framing corpus][framing] supplies the
runtime boundary: physical payload 524,288 passes a request-500 case, 524,289
closes, and two accepted fragments can accumulate to 524,290 before dispatch.
Thus the comparison is a per-physical-frame size check in these cases, not a
demonstrated aggregate transaction cap. It says nothing by itself about
concurrent partial assemblies or process memory.

## Configuration and remaining question

The one conditional follow-up slot used the pinned `10008fd0` configuration
loader because no recognized code xref was returned from `10088d90`. Its
[untruncated decompilation][config] does not name `10094a50`. That is a bounded
observation about this function's displayed code, **not** proof that config or
later code cannot change the global by another route. The 12-call batch has no
runtime RAM measurement and does not establish that the 512 KiB value is
immutable or user-configurable.

The programme identity matched before and after, and the private project file
hash map was unchanged. These checks and the exact parity comparisons are in
[the report][report]. The separate original GAP-011 criterion also requires
explicit mxd limits, inclusive boundaries, overflow checks and boundary
fixtures. This static origin trace does not supply those mxd decisions or close
the gap.

## Reproduce the bounded query

From a fresh private workspace with the same recorded directory layout and
**no** existing `receive-limit-01` output, verify the input PEF/JAR SHA-256
values and the stopped 1,840-function project, then run the retained
[as-run script][script] under the oracle lock:

```sh
flock -x /data/leynos/Projects/mothra/state/delegation/oracle.lock \
  /data/leynos/Projects/mothra/tools/ghidramcp/.venv/bin/python \
  /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-account/mothra/evidence/gap-remediation/2026-11-13/receive-limit-origin-01/receive_limit_probe.py.txt
```

The script pins absolute local paths and refuses an existing output. Review
those paths before use on another host; do not run it against an occupied
project. It stops on identity, GUI parity or pagination mismatch, allows only
one adaptive candidate, and caps itself at 12 calls. The committed corpus is
rechecked from mothra with:

```sh
sha256sum --quiet -c evidence/gap-remediation/2026-11-13/receive-limit-origin-01/SHA256SUMS
```

[corpus]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/result-summary.json
[report]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/report.json
[script]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/receive_limit_probe.py.txt
[startup]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/04-startup-decomp.json
[startup-asm]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/05-startup-disasm.json
[global-xrefs]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/06-global-xrefs.json
[slot-xrefs]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/07-toc-xrefs.json
[outgoing]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/08-toc-outgoing.json
[pointer]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/10-toc-pointer.json
[receiver]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/02-receiver-decomp.json
[receiver-asm]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/03-receiver-disasm.json
[framing]: evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json
[config]: evidence/gap-remediation/2026-11-13/receive-limit-origin-01/11-selected-consumer.json
