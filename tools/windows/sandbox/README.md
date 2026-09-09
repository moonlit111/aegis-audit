# A01 Windows Sandbox probe

This directory contains the harmless guest probe used by
`scripts/check_sandbox.py`. Each attempt copies only `probe.ps1` into a private
read-only tools directory; the generated `.wsb` configuration also maps one
generated input directory and one empty output directory.

`CONTRACT.md` contains A's minimal field proposal for the C00 runtime contract.
The product-side A02 bridge is `crates/application/src/windows_sandbox.rs`;
`scripts/check_sandbox.py` remains the standalone evidence harness.
`A05-COMPATIBILITY.md` records the current native fuzzing-engine boundary.
`A-STATUS.md` is the current A-line handoff summary.
`install-zig.py` installs the pinned compiler used by native-source attempts.
`install-llvm.py` installs the pinned minimal LLVM/libFuzzer runtime.

The probe:

- records the guest OS, architecture, user, and session ID;
- proves the input mapping rejects writes;
- proves the output mapping accepts the expected marker and observation;
- attempts DNS and TCP connections and records the default-route state;
- writes only `output-marker.txt` and `guest-observation.json`;
- asks the guest to shut down after flushing the observation.

`run-libfuzzer.ps1` runs a prebuilt libFuzzer target in the guest, preserves
the corpus and crash input, and replays the crash input when one is found.

The host checker validates file hashes, output names, sizes, reparse points,
observation fields, process exit, and cross-session immutability. It never
terminates sandbox processes that it did not launch.
