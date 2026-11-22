# Security

Please report security issues privately to support@getkeysentry.com. Do not open a public issue.

How releases are built: every version of `@keysentry/cli` is published from this repository by the
`publish` GitHub Actions workflow using npm trusted publishing. Each release carries npm provenance,
which shows the exact commit and workflow that built it. The package has no dependencies and no
install scripts.
