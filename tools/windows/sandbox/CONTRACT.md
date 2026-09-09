# Minimal Windows runtime contract proposal

This is A's input for C00 contract freezing. It describes the fields required
by the Windows Sandbox runner; it is not a claim that the product contract has
already been migrated.

## Runtime configuration

- `schema_version` and `config_version`
- platform: `windows-x64`
- adapter: Windows Python call, Windows instrumented source build, original
  PE32, or original PE64
- immutable target path and target hash
- declarative entry or function invocation; no host command
- input mode, fixtures, baseline input, and probe input
- repeat count, per-run timeout, and fuzz budget
- environment requirements and pinned tool versions
- observer and coverage-feedback mode
- fuzz options when `mode=FUZZ`: engine, run count, timeout, random seed,
  maximum input size, crash-input artifact, corpus archive, and replay result

Required invariant: a missing configuration must remain recoverable. Old
Linux/ELF/AFL++ configurations are historical data and must not be silently
reinterpreted as Windows configurations.

## Sandbox session

- `run_id`, `attempt_id`, and unique sandbox session ID
- owning executor and machine identity
- hashes of target, configuration, tool manifest, and input manifest
- guest OS and architecture
- network, mapping, memory, and device-redirection policy
- start and end timestamps
- cleanup state and cleanup proof

Required invariant: a result belongs to one attempt. After a disconnect,
timeout, cancellation, or executor crash, the old session must be confirmed
closed before the same attempt can be retried.

## Runtime result

- target, configuration, and session identifiers
- environment and tool summary
- observation artifact IDs
- per-trial input hash, input JSON, exit code, stdout/stderr artifact,
  exception, and repeat number
- coverage mode and coverage artifact when applicable
- explicit cleanup result
- capability state: unsupported, not accepted, waiting for configuration,
  partial, cancelled, timed out, cleanup failed, or completed

Required invariant: absent evidence cannot upgrade a result to success. A
component observation, a reproduced crash, and complete target impact remain
separate conclusion levels.
