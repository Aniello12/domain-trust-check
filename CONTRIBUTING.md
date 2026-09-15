# Contributing

Thanks for improving TrustCheck.

1. Create a focused branch.
2. Keep changes small and describe their security trade-off.
3. Add regression coverage for every scoring, normalisation, cache, or collection change.
4. Run `python3 -m unittest discover -v` before opening a pull request.

Prefer passive, public, licence-compatible data sources. Never commit credentials, personal data, or response dumps containing sensitive material. Make every score contribution explainable, and optimise for analyst triage rather than automatic enforcement.

For normal bugs or ideas, open an issue with a minimal reproducible example. Do not include sensitive data. See [SECURITY.md](SECURITY.md) for vulnerabilities.
