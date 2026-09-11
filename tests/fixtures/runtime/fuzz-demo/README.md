# RecordView Fuzz Demo

Self-authored Windows x64 teaching fixture, not a third-party application or
formal course acceptance target. The parser reads local bytes only; it has no
network, command execution, or persistence behavior.

## Version Pair

The record format is `AEG1|NN|TEXT`. `NN` is a two-digit decimal payload length,
with a maximum of 63 bytes. Both versions share `record_parser.c`:

- `1.0.0`: intentionally omits the source-length check, causing a CWE-125
  out-of-bounds read when the declared payload is longer than the input.
- `1.0.1`: compiled with `AEGIS_RECORD_FIXED=1`, rejects the truncated payload.

`record_cli.c` provides a normal file-inspector CLI. `record_fuzz.c` provides
`LLVMFuzzerTestOneInput` for LLVM libFuzzer. Both use AddressSanitizer. Only the
`-fuzz.exe` builds are valid prebuilt targets for AegisAudit dynamic fuzz testing.

## Build and Verify

Run from the repository root with the configured LLVM/MSVC toolchain:

```powershell
py -3 scripts/build_fuzz_demo.py
py -3 scripts/check_fuzz_demo.py --demo-dir .data/demos/BUILD_DIRECTORY
```

The build produces four executables, the ASan runtime DLL, valid seed files,
runtime configurations, source, build receipts, CLI boundary checks, and a ZIP
package. Existing output directories are never overwritten.

Product verification requires the local AegisAudit service. It starts from the
valid `hello.txt` and `demo.txt` seeds, requests up to 2000 executions over 15
seconds with random seed 71413, and saves the discovered minimized crash input.
That same input is replayed against all four executables. The buggy builds must
produce an ASan read error; the fixed CLI must reject it and the fixed fuzz
target must return normally. Boundary regression inputs are not fuzz seeds.

Keep `clang_rt.asan_dynamic-x86_64.dll` beside the executables. Windows host
execution is not sandbox isolation. A reproduced fixture crash does not prove
arbitrary code execution, and a bounded clean fuzz run does not prove safety.
