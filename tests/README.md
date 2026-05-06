# tests/

Local validation harness for the Sigma rules in this repository.

## Quick check (every rule parses)

```bash
pip install --user pysigma
python -c "from sigma.collection import SigmaCollection; SigmaCollection.load_ruleset(['rules/'])"
```

If a rule has invalid YAML or an unknown field, `pySigma` raises immediately
with the offending file path.

## Full pipeline check (parse + backend convert)

```bash
pip install --user pysigma pysigma-backend-elasticsearch pysigma-backend-splunk
python -m sigma convert -t es-qs -p windows-audit rules/
python -m sigma convert -t splunk -p sysmon rules/
```

Both backends should produce a non-empty query for every `.yml` file. A rule
that fails one backend but passes another is acceptable as long as the failure
mode is a known backend limitation (documented in the rule's PR description).

## CI parity

`.github/workflows/sigma-validate.yml` runs the same `SigmaCollection.load_ruleset`
call on every push and pull request. If the local check above passes, CI
should pass.

## What the CI does NOT do

CI only validates *syntax* and *schema*. It does not run the rules against
recorded telemetry. Behavioral validation (true-positive / false-positive
counts on a known dataset) is performed manually inside the author's owned
lab and is out of scope for this public repository.
