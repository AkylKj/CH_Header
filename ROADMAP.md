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
absent. A local v0.0.4 commit was created; no push or release was published.

### v0.0.5 — Effective framing protection and shared HTTP response

- [x] Account for enforced CSP frame-ancestors in the existing X-Frame-Options assessment
- [x] Exact XFO value matching and consistent handling of duplicate/conflicting values
- [x] Guaranteed framing restriction from an enforced policy without claiming a complete CSP intersection
- [x] Remove X-Requested-With and X-UA-Compatible from the core rating
- [x] Revisit X-XSS-Protection: informational only, no enable-filter recommendations
- [x] Keep all three legacy headers in reports as INFO with applicable=false
- [x] Reuse one detached HTTP response for header and response analysis
- [x] Preserve repeated header values, final URL, status, header timing and redirect chain
- [x] Share transport errors without retrying; keep analysis errors and TLS independent
- [x] Preserve CLI options, report fields and CSV columns; add response final_url
- [x] Version 0.0.5 in CLI, User-Agent and both READMEs

Only source changes, documentation links, version references and diff formatting
were reviewed. The program, tests and runtime checks were not run, at the user's
request. Rule-set/scoring-model versioning was explicitly excluded. These changes
are approved by the user for a local commit; no push or release publication is planned.

## Future work

### 1. Analysis quality — high priority

- [ ] Model the combined enforcement of multiple CSP policies
- [ ] Browser/content-aware validation of CSP nonces, hashes and source lists
- [ ] Contextual CORS, Cache-Control and cross-origin header rules
- [ ] HTML / API / static-resource profiles
- [ ] Version the rule set and scoring model — excluded from v0.0.5 by request
- [ ] More detailed certificate chain, key, algorithm and SAN inspection
- [ ] Broader TLS assessment using an established external engine

### 2. Reliability and documentation — high priority

- [ ] Retry/backoff and rate limiting
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
concurrent.futures. No new dependencies are required by v0.0.5.

HSTS has a maximum of 10 points, CSP 15 and cookies 4. Checks marked INFO with
applicable=false are excluded from the denominator. Percentages across different
releases or different applicability sets are not directly comparable.

CSP evaluation is a configuration heuristic, not browser emulation. Multiple
policies are parsed separately; their combined effect is not scored. Policy-level
findings for those policies are observations, not a conclusion about the complete
response. Report-only policies never earn enforcement points. Nonce randomness,
hash-to-content matching and page functionality are not verified. X-Frame-Options
assessment now represents effective CSP frame-ancestors or fallback XFO protection,
with one 8-point maximum. Report-only and default-src do not provide an ancestor
restriction. Empty lists, none/self and specific HTTP(S) sources earn 8; broad
scheme/wildcard lists earn 4; invalid values earn 0. A restrictive enforced policy
provides a guaranteed bound even when other policies are present. The full CSP
intersection is still not modelled. Other scored headers still use basic matching.

Cookies are assessed only from the final response; their application purpose is
unknown. Lack of HttpOnly is a contextual warning. Absence of cookies and valid
deletion cookies are not security failures.

X-Requested-With, X-UA-Compatible and X-XSS-Protection are informational, with
zero score and applicable=false whether present or missing. Their previous total
weight of 7 is no longer included in the denominator. Existing scores and
percentages should not be compared directly to earlier versions.

Both HTTP analyzers use the same detached snapshot. One GET operation can include
multiple allowed redirects; the final response body is not read. Transport errors
are recorded in all selected HTTP modules without a second fetch. Standalone
library calls retain their URL-based interface and fetch once per explicit call.

TLS behavior is unchanged in v0.0.5. UNKNOWN probes depend on client/network
capabilities and do not establish lack of server support. Only the negotiated
cipher is inspected. The TLS scale has a maximum of 95, and incomplete probe
results are labelled Incomplete.

## References

- [CSP Level 3](https://www.w3.org/TR/CSP3/)
- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)

Last updated: October 5, 2026
Project version: 0.0.5
Roadmap version: 1.6
