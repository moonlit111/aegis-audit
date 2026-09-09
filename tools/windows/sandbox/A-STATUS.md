# A-line status for handoff

Updated: 2026-09-09, Asia/Hong Kong.

## Verified

- A01 boundary probe: two disposable sessions passed network, mapping, write,
  cleanup, and cross-session checks.
  Evidence: `.data/verification/windows-runtime/a01-final3-20260909/summary.json`.
- A02 product bridge: per-attempt input/tool/output manifests, SHA-256
  verification, fixed WSB policy, bounded receipt export, and session-aware
  process cleanup are implemented in
  `crates/application/src/windows_sandbox.rs`.
- A03 prototype contract: Windows Python, native source, PE32, and PE64
  adapters are modeled and validated without reinterpreting the legacy
  Linux/ELF contract.
- A04 benign execution:
  - pinned Windows Python 3.13.13 ran in Sandbox and returned exit 0;
  - benign PE32 and PE64 fixtures ran in Sandbox and returned exit 42;
  - benign C and C++ sources compiled with pinned Zig 0.15.2 in Sandbox,
    executed, and returned exit 0;
  - all sessions closed without leftover `WindowsSandbox*` processes.
- A06 lifecycle:
  - user cancellation closed the owned remote session;
  - timeout closed the owned remote session;
  - neither path reported success.
- A05 source-engine experiment:
  - LLVM 23.1.1 libFuzzer and libFuzzer+ASan probes compile and run;
  - a prebuilt libFuzzer probe ran in Windows Sandbox with inline-8-bit-counter
    coverage;
  - a benign crash fixture preserved `crash-input.bin`, archived `corpus.zip`,
    and replay reproduced the same nonzero exit;
  - this is an engine experiment, not yet product integration.
- A05 closed-source PE-engine experiment:
  - TinyInst `litecov` runs against a benign PE64 fixture;
  - TinyInst ran in Windows Sandbox and produced coverage offsets;
  - TinyInst is pinned and installable through `tools/windows/versions.json`;
  - this is also an engine experiment, not yet product integration.

## Not ready

- Zig 0.15.2 is now pinned in `tools/windows/versions.json` and prepared for
  standalone bundling, but the final package still needs its own A08 acceptance
  run after C integrates the product runtime path.
- LLVM 23.1.1 and TinyInst are also pinned and prepared for bundling. A08 still
  needs a package-local acceptance run after product integration.
- A05 source compilation currently occurs on the host for the compatibility
  probe; compiling inside Sandbox and integrating the engine into the product
  runtime remain pending.
- A05 crash-input preservation, deduplication, minimization, and repeated
  execution evidence remain pending.
- Executor crash, service disconnect, and full product integration are not yet
  tested because those paths require the shared runtime contract and executor
  dispatch changes.

## Handoff request

C should freeze the C00 contract from `CONTRACT.md` and the implemented
`SandboxSession`, `SandboxOutput`, `SandboxExecution`, and
`WindowsRuntimeConfig` shapes. B should review observation fields and own the
`executor/jobs.rs` dispatch integration. A should not edit those shared files
while C/B are integrating.
