# Research notes + dedupe check — `defensive-detection-rules`

> **Purpose:** Document the prior-art search, sources consulted, and the dedupe check
> performed against upstream Sigma rules before publishing the four rules in this
> repository. Required for traceability and to demonstrate that contributions are
> additive, not redundant copies.
>
> **Date of audit:** 2026-05-06 (matches `v0.1.0` release).

---

## 1. Web research — sources cited

The repo structure, license, and quality signals were grounded in a 4-source
cloud consult (Gemini Pro 2.5, GPT-5 medium, Perplexity Sonar Pro web-grounded,
Hermes qwen2.5-coder:7b local) plus 3 web searches via Perplexity Sonar Pro.

### Structural norms confirmed

- `rules/<product>/<logsource>/` directory layout — used in this repo.
- `LICENSE` file at repo root (MIT for permissive sharing of detection logic).
- `README.md` with badges (CI status, license, Sigma version) — present.
- `tests/` directory with at least a placeholder README — present.
- `.github/workflows/` for CI parsing + metadata — present.
- `SECURITY.md` + `CONTRIBUTING.md` for community signaling — present.
- `.vscode/` settings + extension recommendations for editor onboarding — present.

### Anti-patterns avoided

| Anti-pattern | Mitigation in this repo |
| --- | --- |
| Verbatim copy from `SigmaHQ/sigma` | All 4 rules originally authored; ATT&CK technique IDs reused, but field selectors + filters + falsepositives are independently reasoned. |
| Vague titles | Titles include the threat-actor / activity-class + technique cluster. |
| Missing `falsepositives` | Every rule has at least 2 concrete tuning hints. |
| Missing tests / CI | `sigma-validate.yml` runs pySigma parse + metadata on every push. |
| Inflated technique tags | Round-2 review trimmed `T1486` from rule 4 (overstatement vs `T1560.001`). |

### Quality signals adopted

- Anonymization: no real IOCs, hashes, IPs, hostnames, or campaign IDs.
- Defensive header on every rule: `# DEFENSIVE — owned-lab only`.
- ATT&CK v15 tag format with lowercase technique IDs.
- UUIDv4 rule IDs.
- pySigma parse + metadata 4/4 PASS (twice — pre-fix + post-fix).
- Elasticsearch Lucene backend conversion 4/4 PASS (local one-shot validation).

---

## 2. Dedupe check vs upstream Sigma

Each rule was checked against the public `SigmaHQ/sigma` repository to confirm
the contribution is additive, not duplicated.

### Methodology

- Cloned a snapshot of `SigmaHQ/sigma` to a local read-only mirror.
- For each rule, grep'd for the technique IDs (`T1053.005`, `T1059.001`,
  `T1059.005`, `T1027`, `T1071.001`, `T1105`, `T1486`, `T1560.001`, `T1562.001`)
  to enumerate existing coverage.
- Compared the field selectors + filter compositions of each upstream match
  against the rule in this repo.
- A rule is considered a duplicate only if both the technique IDs **and** the
  field-selector logic are equivalent within tuning noise.

### Per-rule findings

| File | Upstream coverage | Verdict |
| --- | --- | --- |
| `muddywater_scheduled_task_vbscript_persistence.yml` | Upstream rules cover scheduled-task creation generally and PowerShell-via-WSCRIPT individually, but no single rule joins T1053.005 with the VBScript / `cscript` / `.vbe` / `.js` execution constellation observed in MuddyWater 2024-2025 reports. | Additive |
| `obfuscated_powershell_defender_disable.yml` | Upstream has `proc_creation_win_powershell_set_mppreference.yml` (Defender disable) and several encoded-PowerShell rules separately, but does not combine the `[char]` / `-bxor` / `-join` obfuscation indicators with the Defender-disable selectors in one constellation. | Additive |
| `suspicious_7zip_password_with_delete_source.yml` | Upstream has rules for `7z.exe` invocations and password-protected archive creation. This rule additionally requires a non-empty `-p<value>` selector via regex and the `-sdel` "delete after archive" flag — a combination that signals exfiltration prep rather than benign packaging. | Additive |
| `powershell_outbound_to_uncommon_tld_or_raw_ip.yml` | Upstream has rules for raw-IP outbound from PowerShell, but they typically miss the uncommon-TLD branch and don't apply the RFC1918 + `169.254.0.0/16` filter to reduce internal-tooling FPs. | Additive |

### How to reproduce the dedupe check

Anyone can re-verify locally:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/upstream-sigma
# For each technique ID:
grep -rl 'T1053\.005' /tmp/upstream-sigma/rules/
grep -rl 'T1027' /tmp/upstream-sigma/rules/
# Compare the field selector + filter composition of each match against the
# corresponding rule in this repo.
```

If a future upstream PR introduces an equivalent constellation, this repo will
either reference it as inspiration or open a follow-up PR upstream.

---

## 3. Ranking of rule contributions

Internal ranking by detection value, from a defensive-utility perspective:

1. `obfuscated_powershell_defender_disable.yml` — covers a high-frequency
   precursor across multiple actor families.
2. `muddywater_scheduled_task_vbscript_persistence.yml` — actor-specific
   constellation backed by 2024-2025 reporting.
3. `suspicious_7zip_password_with_delete_source.yml` — exfiltration prep
   indicator with a tight FP profile.
4. `powershell_outbound_to_uncommon_tld_or_raw_ip.yml` — useful as a
   complement to network telemetry, but more sensitive to environment tuning.

---

## 4. Conclusion

- All four rules are **additive** to the public Sigma corpus as of 2026-05-06.
- Quality signals (CI, ATT&CK v15, UUIDs, FP notes, anonymization) match
  contemporary norms for solo-researcher detection repositories.
- Upstream dedupe check was non-trivial but reproducible — see methodology
  above.
- Future contributions should re-run the dedupe check before opening a PR.

---

## 5. References

- `SigmaHQ/sigma` — upstream rule corpus.
- MITRE ATT&CK v15 — technique IDs cited per rule.
- pySigma — parser + backend used in CI.
- 4-source cloud consult artifacts (in the project this repo originated from):
  `github_repo_consult.json`, `github_repo_review.json`, `next_steps_consult.json`
  (not included in this public repo — they contain internal infrastructure paths).
