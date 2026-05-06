# v0.1.1 — peer-review-driven detection-logic fixes

This release addresses four **P0 detection-logic bugs** discovered by a
post-publish 5-reviewer audit on 2026-05-06 (3 paid cloud models +
2 local Ollama models, plus the maintainer's own pass). All fixes were
re-validated by a 3-paid-source diff consult before merge.

## What changed

### 🐛 P0-1 — `powershell_outbound_to_uncommon_tld_or_raw_ip.yml`

The raw-IPv4 detection branch matched on `DestinationHostname`, but
**Sysmon Event 3 (`network_connection`) does not populate
`DestinationHostname` by default** — only `DestinationIp` is reliably
present. The branch never fired on real telemetry.

Fix: switched to `DestinationIp|re: '^(\d{1,3}\.){3}\d{1,3}$'`. The
`selection_raw_ipv4_in_hostname` selector was renamed to
`selection_raw_ipv4_dest` and the condition updated.

### 🐛 P0-2 — `muddywater_scheduled_task_vbscript_persistence.yml`

`filter_signed_admin_paths` excluded `\Windows\System32\` from the
command line. Because both `schtasks.exe` and `wscript.exe` live in
System32, this filter cancelled the legitimate true-positive
constellation (a scheduled task in System32 invoking a script host in
System32 against a user-writable script).

Fix: removed `\Windows\System32\` from the filter. The user-writable
path assertion in `selection_writable_path` already provides the
correct positive gate. Comment added to the rule explaining why.

### 🐛 P0-4 — `obfuscated_powershell_defender_disable.yml`

Two issues in `selection_defender_tamper`:

1. The selector mixed `CommandLine|contains|all` (for the verb) and
   `CommandLine|contains` (for the parameter) under the same mapping —
   a Sigma anti-pattern that confused multiple reviewers and risked
   backend-specific evaluation differences.
2. The verb list covered only `Set-MpPreference`. A real attacker
   pattern is `Add-MpPreference -ExclusionPath C:\Users\Public\` to
   carve a directory out of Defender — that case was missed.

Fix: split into two explicit selectors, `selection_defender_verb`
(matches `Set-MpPreference` OR `Add-MpPreference`) and
`selection_defender_param` (matches a real-time-disable verb OR an
`ExclusionPath` / `ExclusionExtension` / `ExclusionProcess`
parameter), AND'd in the condition.

### 🏷️ P0-5 — ATT&CK tag corrections

- `muddywater_scheduled_task_vbscript_persistence.yml`: added
  `attack.t1059.007` (JavaScript) since the rule already covers `.js`.
- `suspicious_7zip_password_with_delete_source.yml`: added
  `attack.t1070.004` (File Deletion) since the rule fires on the
  `-sdel` flag (delete source after archiving).

## What did **not** change

A few reviewer suggestions were intentionally **not** adopted:

- Removing `attack.t1027` from the 7-Zip rule — `T1027 (Obfuscated
  Files or Information)` per ATT&CK includes encrypted archives, so
  the tag is correct.
- Replacing the explicit 16-prefix RFC1918 listing for `172.16.0.0/12`
  in the network rule — Sigma's `startswith` modifier does not support
  CIDR; the explicit listing is the canonical workaround.
- Several stylistic changes (status/level alignment, etc.) — deferred
  to a future release once positive-detection telemetry from a lab
  exercise is in.

## Validation

- `pySigma` parse + metadata: 4/4 PASS.
- `pySigma` Lucene backend conversion: 4/4 PASS (local).
- 3-paid-source diff consult (Gemini Pro 2.5 + GPT-5 + Perplexity
  Sonar Pro): 4/4 SHIP after one MODIFY round on the
  Defender-tampering selector split.

## Reviewers

5-reviewer post-publish audit:

- Gemini Pro 2.5 (cloud)
- GPT-5 medium reasoning (cloud)
- Perplexity Sonar Pro web-grounded (cloud)
- Ollama qwen2.5-coder:14b (local)
- Ollama deepseek-r1:14b (local — note: hallucinated several ATT&CK
  technique IDs; suggestions were filtered before merge)

Cumulative independent review on this repo since publish: 9 model-runs
across 5 unique models + 1 maintainer pass.

## How to upgrade

If you pinned to `v0.1.0`:

```bash
git fetch --tags
git checkout v0.1.1
```

Backend-converted detections from v0.1.0 should be re-converted from
v0.1.1 — the `network_connection` and `process_creation` rules
above produce different field selectors after this release.
