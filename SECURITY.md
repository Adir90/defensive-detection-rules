# Security policy

## Scope of this repository

This repository contains **defensive detection rules** authored by a solo
researcher. There is no service, no binary release, no executable code being
distributed. The rules themselves describe attacker patterns so that a blue
team can detect them.

## What is in scope

- A factual error in a rule (wrong technique ID, wrong field name, wrong
  logsource mapping) that would cause a defender to miss real activity.
- A false-positive trap that is severe enough to make a rule unusable in a
  production SIEM and is not already mitigated by the `falsepositives:`
  section.
- An anonymization regression: any indicator that maps to a real, identifiable
  campaign sample (filename, hash, IP, hostname, ASN, internal artifact).

If you find any of the above, please open an issue or, if the issue is
sensitive, open a private security advisory via GitHub's "Security" tab.

## What is out of scope

- Requests to weaponize a rule, to add evasion tips, or to assist with anything
  that is not a defender perspective. The repository will not accept such
  contributions and will not respond to such requests.
- Reports about the absence of a particular technique. Coverage gaps are
  expected; the index in `README.md` is the canonical list.

## Disclosure expectations

This is a personal project. Responses are best-effort and asynchronous.

## Acknowledgements

If you reported a real defect that materially improves a rule, you will be
credited in the commit message and the rule's `references:` section unless you
prefer to remain anonymous.
