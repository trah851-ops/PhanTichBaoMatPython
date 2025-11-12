# python_static_analyzer

Lightweight static analyzer (pure-Python).

## Quickstart
- Run CLI: `python cli.py path/to/file_or_dir --out-html report.html --out-json report.json`
- Rules: edit `custom_rules.json`
- Tests: sample tests in `tests/` (requires pytest)


## Rule discovery helper

You can generate candidate rules from a codebase using `rule_discovery.py`:

```
python rule_discovery.py path/to/code --out candidates.json --min-count 2
```

Review `candidates.json` and add useful patterns to `custom_rules.json`.
