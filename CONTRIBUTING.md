# Contributing

Thanks for considering a contribution. This is a personal repository, so the
bar is mostly "does the rule meet the conventions in `README.md` and pass
CI?".

## Before you open a PR

1. Run the local validation:
   ```bash
   pip install --user pysigma
   python -c "from sigma.collection import SigmaCollection; SigmaCollection.load_ruleset(['rules/'])"
   ```
2. Confirm the rule has every required field listed in `README.md` →
   "Authoring conventions".
3. Confirm the rule is anonymized: no real filenames, hashes, IPs, hostnames,
   ASNs, or campaign-internal artifacts.
4. Add at least two concrete false-positive tuning hints. "Investigate
   manually" is not a tuning hint.

## What I will accept

- New rules that follow the layout under `rules/<product>/<logsource>/`.
- Fixes to existing rules that close a real false-positive trap or correct an
  ATT&CK technique mapping.
- Documentation improvements to `README.md` or `tests/README.md`.

## What I will not accept

- Offensive content of any kind: payloads, evasion notes, red-team scripts,
  adversary emulation profiles that aren't already public.
- Rules that copy verbatim from another repository without attribution and a
  derivative-work note in `references:`.
- Rules that lack a `falsepositives:` section.

## Style

- YAML, two-space indent, no tabs.
- ATT&CK tags use the lowercase `attack.tNNNN[.NNN]` form.
- The rule `id:` is a UUIDv4. New IDs only — never reuse.
- Keep the `# DEFENSIVE — owned-lab only` header on every new rule.

## License

By submitting a contribution you agree it is licensed under the MIT License
that covers this repository.
