# Security Header Checker — Roadmap

## Project overview

A Python CLI for inspecting HTTP security headers, TLS configuration and response
metadata, with actionable findings and TXT/JSON/CSV reports.

Checkboxes describe implementation status, not verified security or automated
validation. Scores are project heuristics, not an industry standard or a full audit.

## Version history

### v0.0.1 — Initial release

- [x] argparse CLI and HTTP(S) URL validation
- [x] Basic security-header checks and per-header reports
- [x] Coloured terminal output
- [x] Weighted scores and overall security assessment
- [x] Initial error handling

### v0.0.2 — Expanded features

- [x] --output with TXT, JSON and CSV export
- [x] Verbose explanations, recommendations and configuration examples
- [x] --timeout, --user-agent, --follow-redirects and --version
- [x] Server and X-Powered-By disclosure checks
- [x] Cache-Control, Set-Cookie and Clear-Site-Data checks
- [x] COEP, COOP and CORP checks
- [x] CORS headers and legacy-browser header checks
- [x] Initial certificate, TLS protocol and negotiated-cipher analysis
- [x] URL lists from --file and --urls
- [x] --parallel, --batch-size and bulk summaries
- [x] Response status, server metadata and additional response headers

These entries record the original implementation. Export, TLS and bulk behavior
required corrections delivered in v0.0.3.

### v0.0.3 — Stabilization

- [x] Session.max_redirects in both HTTP modules
- [x] Case-insensitive headers and explicit HTTP connection cleanup
- [x] Correct single/bulk --ssl-only and --response-only execution
- [x] Mutually exclusive modes, URL validation and positive CLI limits
- [x] WARNING summary handling and detailed module errors
- [x] Independent module execution during partial failures
- [x] Bulk ranking restricted to available scores
- [x] Bounded batches and worker counts
- [x] Composed single/bulk TXT, JSON and CSV reports
- [x] Certificate trust/hostname verification and separate DER retrieval on failure
- [x] URL parsing with urlsplit, including IPv6
- [x] SUPPORTED / UNSUPPORTED / UNKNOWN TLS probe results
- [x] Reachable TLS score denominator and documented limitations
- [x] .gitignore, removal of tracked bytecode and unused dependencies
- [x] Version and README link corrections
- [x] Removal of tests, pytest configuration and test CI at the user's request

Before removal, 88 tests passed locally on Windows / Python 3.14. The full
OS/Python matrix and remote CI were not verified. That historical result does
not validate v0.0.4. Local v0.0.3 commits exist; no push or release was published.

### v0.0.4 — Structured CSP, HSTS and cookie analysis

- [x] Preserve separate repeated header values before response cleanup
- [x] Read each Set-Cookie field without splitting Expires on commas
- [x] Preserve the final response URL for HTTPS applicability
- [x] Parse HSTS directives, validate max-age and identify disabled/short policies
- [x] Treat includeSubDomains/preload as optional; do not claim preload registration
- [x] Parse CSP directives and source tokens, retaining the first duplicate directive
- [x] Evaluate script-src-elem/attr and script-src/default-src fallback
- [x] Contextual nonce/hash, unsafe-inline, unsafe-eval and strict-dynamic findings
- [x] Separate object-src and base-uri scoring
- [x] Parse multiple enforced policies separately without claiming a combined assessment
- [x] Report-only CSP diagnostics without enforcement credit
- [x] Per-cookie Secure, HttpOnly and SameSite analysis
- [x] Exclude missing cookies and valid cookie deletions from scoring
- [x] Aggregate cookie scores using the worst applicable cookie
- [x] Structured findings, parsed data and applicability metadata
- [x] Findings and recommendations in CLI, TXT, JSON and CSV
- [x] Individual cookie CSV rows with names and ordinal numbers
- [x] Contextual max_score and N/A when no score is available
- [x] Version 0.0.4 in CLI, User-Agent and both READMEs
- [x] English roadmap with preserved version history

Implementation has been reviewed by reading changes and checking diff formatting,
version references and documentation links. No automated tests or runtime checks
were created or run for v0.0.4, at the user's request. Test infrastructure remains
absent. The user approved a local commit. No push or release publication is authorized.

## Future work

### 1. Analysis quality — high priority

- [ ] Model the combined enforcement of multiple CSP policies
- [ ] Browser/content-aware validation of CSP nonces, hashes and source lists
- [ ] Contextual CORS, Cache-Control and cross-origin header rules
- [ ] Account for CSP frame-ancestors in framing-protection assessment
- [ ] HTML / API / static-resource profiles
- [ ] Remove X-Requested-With and X-UA-Compatible from the core rating
- [ ] Revisit obsolete headers and X-XSS-Protection recommendations
- [ ] Version the rule set and scoring model
- [ ] More detailed certificate chain, key, algorithm and SAN inspection
- [ ] Broader TLS assessment using an established external engine

### 2. Reliability and documentation — high priority

- [ ] Retry/backoff and rate limiting
- [ ] Reuse one HTTP response for header and response analysis
- [ ] Detailed interpretation guide and FAQ
- [ ] More report and server-configuration examples
- [ ] Reintroduce automated validation and CI only if explicitly requested

Tests and test CI are deferred at the user's request. The basic
--response-analysis option and server identification already exist.

### 3. Usability and automation — medium priority

- [ ] --format and --quiet / --no-color
- [ ] --fail-on / --min-score for automation
- [ ] Markdown reports and comparison with a previous JSON report
- [ ] Filtering, sorting and contextual recommendations
- [ ] HTML reports and user templates
- [ ] Configuration files and custom rule settings
- [ ] Logging and additional summaries

### 4. Extensions — deferred until a demonstrated need

- [ ] DNS inspection
- [ ] File/directory discovery
- [ ] General --full-scan / --quick-scan modes
- [ ] FastAPI web API
- [ ] Expanded technology detection
- [ ] Safe OPTIONS / HEAD / CORS preflight inspection
- [ ] Charts and security trends
- [ ] Asynchronous HTTP only after performance measurements

PUT/DELETE in Allow alone is not evidence of a vulnerability. pandas, matplotlib
and aiohttp will not be added without a concrete use case.

## Current stack and limitations

Target Python versions: 3.10–3.14. Runtime dependencies: requests, colorama and
cryptography. Standard-library components include argparse, ssl and
concurrent.futures. No new dependencies are required by v0.0.4.

HSTS has a maximum of 10 points, CSP 15 and cookies 4. Checks marked INFO with
applicable=false are excluded from the denominator. Percentages across different
releases or different applicability sets are not directly comparable.

CSP evaluation is a configuration heuristic, not browser emulation. Multiple
policies are parsed separately; their combined effect is not scored. Policy-level
findings for those policies are observations, not a conclusion about the complete
response. Report-only policies never earn enforcement points. Nonce randomness,
hash-to-content matching and page functionality are not verified. X-Frame-Options
scoring is unchanged. Other headers still use basic matching.

Cookies are assessed only from the final response; their application purpose is
unknown. Lack of HttpOnly is a contextual warning. Absence of cookies and valid
deletion cookies are not security failures.

TLS behavior is unchanged in v0.0.4. UNKNOWN probes depend on client/network
capabilities and do not establish lack of server support. Only the negotiated
cipher is inspected. The TLS scale has a maximum of 95, and incomplete probe
results are labelled Incomplete.

## References

- [CSP Level 3](https://www.w3.org/TR/CSP3/)
- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)

Last updated: October 5, 2026
Project version: 0.0.4
Roadmap version: 1.5
