# defensive-detection-rules

Sigma detection rules authored by a solo defensive security researcher, focused on
Windows endpoint telemetry. All rules are validated against MITRE ATT&CK v15.

> **Scope:** 100% defensive. Every rule is intended for blue-team detection,
> purple-team validation, and incident-response prep inside an isolated, owned
> lab. Nothing in this repository is a payload, a stager, an offensive tool, or
> instructions for one.

## Repository layout

```
defensive-detection-rules/
├── LICENSE                          MIT
├── README.md                        this file
├── rules/
│   └── windows/
│       ├── process_creation/
│       │   ├── muddywater_scheduled_task_vbscript_persistence.yml
│       │   ├── obfuscated_powershell_defender_disable.yml
│       │   └── suspicious_7zip_password_with_delete_source.yml
│       └── network_connection/
│           └── powershell_outbound_to_uncommon_tld_or_raw_ip.yml
├── tests/
│   └── README.md                    how to validate locally
└── .github/
    └── workflows/
        └── sigma-validate.yml       CI: pySigma lint on every push / PR
```

## Rule index

| File | Logsource | Techniques | Level |
| --- | --- | --- | --- |
| `muddywater_scheduled_task_vbscript_persistence.yml` | process_creation | T1053.005, T1059.005 | high |
| `obfuscated_powershell_defender_disable.yml` | process_creation | T1059.001, T1027, T1562.001 | high |
| `suspicious_7zip_password_with_delete_source.yml` | process_creation | T1560.001, T1027 | high |
| `powershell_outbound_to_uncommon_tld_or_raw_ip.yml` | network_connection | T1059.001, T1071.001, T1105 | high |

## Validation

Every rule is validated locally with `pySigma` before commit. To reproduce:

```bash
pip install --user pysigma pysigma-backend-elasticsearch
python -c "from sigma.collection import SigmaCollection; SigmaCollection.load_ruleset(['rules/'])"
```

CI runs the same check via `.github/workflows/sigma-validate.yml` on every push
and pull request.

## Authoring conventions

- **Anonymized.** No specific filenames, hashes, IPs, hostnames, ASNs, or
  campaign-internal artifacts from any real intrusion. Rules describe a
  technique pattern, not a single sample.
- **Defensive header.** Every rule starts with a `# DEFENSIVE — owned-lab only`
  comment block stating the purpose and the anonymization guarantee.
- **ATT&CK tagging.** Every rule cites at least one technique under ATT&CK
  v15. Tactics and sub-techniques are tagged when applicable.
- **False-positive notes.** Every rule has a `falsepositives:` section with at
  least two concrete tuning hints. Detections without FP notes are not merged.
- **Tunable filters.** Where a benign baseline is known (signed admin paths,
  RFC1918 destinations, common admin ports), it is expressed as a `filter_*`
  selection joined with `not` in the `condition` so site-specific tuning is a
  one-line change.

## Use, attribution, and contact

MIT licensed (see `LICENSE`). If you adapt a rule, a reference to this
repository is appreciated but not required.

This repository is maintained by a solo researcher; issues and pull requests
are welcome but reviewed asynchronously.
