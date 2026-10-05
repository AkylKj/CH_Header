"""Contextual CSP, HSTS and Set-Cookie rules for v0.0.5.

This is a header configuration heuristic, not a browser or a vulnerability scan.
"""
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

YEAR = 31536000
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
NONCE_HASH = re.compile(r"'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'\Z", re.I)
SCHEME = re.compile(r'[A-Za-z][A-Za-z0-9+.-]*:\Z')
HOST_SOURCE = re.compile(r'(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:\*|(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)(?::(?:[0-9]+|\*))?(?:/[^\s]*)?\Z')
SOURCE_KEYWORDS = {"'none'", "'self'", "'unsafe-inline'", "'unsafe-eval'",
                   "'wasm-unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'",
                   "'report-sample'", "'inline-speculation-rules'", "'trusted-types-eval'"}
SOURCE_DIRECTIVES = {'default-src', 'script-src', 'script-src-elem', 'script-src-attr',
                     'object-src', 'base-uri', 'style-src', 'style-src-elem',
                     'style-src-attr', 'img-src', 'font-src', 'connect-src',
                     'media-src', 'frame-src', 'child-src', 'worker-src',
                     'manifest-src', 'frame-ancestors', 'prefetch-src'}


def finding(status, message, recommendation=''):
    return {'status': status, 'message': message, 'recommendation': recommendation}


def detail(value, score, status, description, parsed=None, findings=None, applicable=True):
    return {'value': value, 'score': score, 'status': status,
            'description': description, 'parsed': parsed or {},
            'findings': findings or [], 'applicable': applicable}


def analyze_hsts(values, final_url):
    value = '\n'.join(values) if values else 'Not found'
    findings, directives = [], {}
    if len(values) != 1:
        return detail(value, 0, 'BAD', 'HSTS requires one unambiguous header.',
                      findings=[finding('BAD', 'HSTS is missing or repeated.',
                                        'Serve one HSTS header on HTTPS with a valid max-age.')])
    for part in values[0].split(';'):
        if not part.strip():
            continue
        name, separator, argument = part.strip().partition('=')
        directives.setdefault(name.strip().lower(), []).append(argument.strip() if separator else None)
    ages = directives.get('max-age', [])
    valid_age = len(ages) == 1 and ages[0] is not None
    if valid_age:
        number = ages[0]
        if len(number) >= 2 and number.startswith('"') and number.endswith('"'):
            number = number[1:-1]
        valid_age = bool(re.fullmatch(r'[0-9]+', number)) and len(number) <= 100
    age = int(number) if valid_age else None
    parsed = {'directives': directives, 'max_age': age,
              'include_subdomains': directives.get('includesubdomains') == [None],
              'preload': directives.get('preload') == [None]}
    if age is None:
        findings.append(finding('BAD', 'max-age must occur once and be a non-negative integer.',
                                'Use max-age=31536000 on HTTPS.'))
    elif age == 0:
        findings.append(finding('BAD', 'max-age=0 removes the browser HSTS policy.',
                                'Use a positive max-age if HTTPS enforcement is intended.'))
    elif age < YEAR:
        findings.append(finding('WARNING', f'HSTS lifetime is {age} seconds, less than one year.',
                                'Increase max-age to at least 31536000 when ready.'))
    else:
        findings.append(finding('GOOD', f'HSTS lifetime is {age} seconds (at least one year).'))
    if urlsplit(final_url).scheme.lower() != 'https':
        findings.append(finding('BAD', 'Browsers ignore HSTS received over HTTP.',
                                'Serve the policy on the final HTTPS response.'))
    for key, label in [('includesubdomains', 'includeSubDomains'), ('preload', 'preload')]:
        if key in directives and directives[key] != [None]:
            findings.append(finding('INFO', f'{label} must be a bare, non-repeated directive; its value is not accepted here.'))
    if not parsed['include_subdomains']:
        findings.append(finding('INFO', 'includeSubDomains is not enabled; this does not reduce the score.',
                                'Enable it only after ensuring all subdomains support HTTPS.'))
    if parsed['preload']:
        findings.append(finding('INFO', 'The preload token does not prove inclusion in a browser preload list.'))
    else:
        findings.append(finding('INFO', 'preload is optional and does not reduce the score.'))
    bad = any(item['status'] == 'BAD' for item in findings)
    score = 0 if bad else 5 if age < YEAR else 10
    return detail(value, score, 'BAD' if bad else 'WARNING' if score == 5 else 'GOOD',
                  'HTTPS enforcement policy.', parsed, findings)


def _source_valid(token):
    return (token.lower() in SOURCE_KEYWORDS or bool(NONCE_HASH.fullmatch(token))
            or bool(SCHEME.fullmatch(token)) or bool(HOST_SOURCE.fullmatch(token)))


def _effective(directives, names):
    for name in names:
        if name in directives:
            return name, directives[name]
    return None, None


def _script_score(directives, findings):
    points = []
    for scope, names in [('elements', ('script-src-elem', 'script-src', 'default-src')),
                         ('attributes', ('script-src-attr', 'script-src', 'default-src'))]:
        name, sources = _effective(directives, names)
        if sources is None:
            points.append(0)
            findings.append(finding('BAD', f'Script {scope} have no source restriction.',
                                    'Define script-src or default-src; restrict inline scripts.'))
            continue
        lower = [token.lower() for token in sources]
        authentication = any(NONCE_HASH.fullmatch(token) for token in sources)
        dynamic = "'strict-dynamic'" in lower
        # CSP3 overrides unsafe-inline for both script elements and attributes.
        # A nonce itself authorizes elements only, not event-handler attributes.
        inline = "'unsafe-inline'" in lower and not (authentication or dynamic)
        if "'unsafe-inline'" in lower and not inline:
            findings.append(finding('INFO', f'{name}: unsafe-inline is overridden by nonce/hash or strict-dynamic in CSP3.'))
        if authentication:
            findings.append(finding('INFO', f'{name}: nonce/hash syntax detected; randomness and content matching are not checked.'))
        if scope == 'attributes' and authentication:
            findings.append(finding('INFO', f'{name}: nonces do not authorize event handlers; hashes need unsafe-hashes for attributes.'))
        if inline:
            points.append(0)
            findings.append(finding('BAD', f'{name} allows arbitrary inline script {scope}.',
                                    'Remove effective unsafe-inline; use nonces/hashes for elements or script-src-attr none for handlers.'))
        else:
            broad = any(token == '*' or SCHEME.fullmatch(token) or '*' in token
                        for token in sources if not token.startswith("'"))
            # Host and scheme sources are ignored by strict-dynamic for scripts.
            if scope == 'elements' and dynamic:
                broad = False
                findings.append(finding('INFO', f'{name}: CSP3 strict-dynamic ignores host/scheme allowlists and propagates script trust.'))
                if not authentication:
                    findings.append(finding('INFO', f'{name}: strict-dynamic has no nonce/hash bootstrap; parser-inserted scripts may be blocked.'))
            # Host allowlists do not authorize inline event handlers.
            if scope == 'attributes':
                broad = False
            points.append(4 if broad else 9)
            if broad:
                findings.append(finding('WARNING', f'{name} permits broad script sources.',
                                        'Restrict scripts to required origins or a nonce/hash policy.'))
            else:
                findings.append(finding('GOOD', f'Script {scope} are restricted by {name}.'))
    # Eval is governed by script-src/default-src, not script-src-elem/attr.
    name, sources = _effective(directives, ('script-src', 'default-src'))
    if sources is None or "'unsafe-eval'" in [token.lower() for token in sources]:
        points.append(0)
        findings.append(finding('BAD', 'JavaScript eval is unrestricted by script-src/default-src.',
                                'Set script-src without unsafe-eval.'))
    return min(points)


def _parse_policy(value):
    directives, findings = {}, []
    for part in value.split(';'):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if not re.fullmatch(r'[a-z0-9-]+', name):
            findings.append(finding('BAD', f'Invalid CSP directive name: {tokens[0]}.'))
            continue
        if name in directives:
            findings.append(finding('INFO', f'Duplicate {name}: the first occurrence is used.'))
            continue
        directives[name] = tokens[1:]
        if name in SOURCE_DIRECTIVES:
            for token in tokens[1:]:
                if not _source_valid(token):
                    findings.append(finding('BAD', f'{name}: invalid or unrecognised source token {token}.',
                                            'Correct the source expression before relying on this policy.'))
            if "'none'" in [token.lower() for token in tokens[1:]] and len(tokens[1:]) > 1:
                findings.append(finding('INFO', f'{name}: none mixed with other sources does not block all sources.'))
    if not directives:
        findings.append(finding('BAD', 'CSP is empty or has no valid directives.',
                                'Define an enforced CSP suited to the page.'))
    script_score = _script_score(directives, findings)
    score = script_score
    for name, fallbacks in [('object-src', ('object-src', 'default-src')),
                            ('base-uri', ('base-uri',))]:
        effective, sources = _effective(directives, fallbacks)
        # Empty source lists block everything, just like none.
        restricted = sources is not None and all(token.lower() in ("'none'", "'self'") for token in sources)
        if restricted:
            score += 3
            findings.append(finding('GOOD', f'{name} is restricted via {effective}.'))
        else:
            findings.append(finding('WARNING', f'{name} is missing or not limited to none/self.',
                                    f"Use {name} 'none' or {name} 'self' as appropriate."))
    invalid = any(item['status'] == 'BAD' and ('Invalid CSP' in item['message'] or
                  'invalid or unrecognised' in item['message'] or 'CSP is empty' in item['message'])
                  for item in findings)
    if invalid:
        score = 0
    status = 'BAD' if any(item['status'] == 'BAD' for item in findings) else 'WARNING' if score < 15 else 'GOOD'
    return {'directives': directives, 'score': score, 'status': status, 'findings': findings}


def analyze_csp(values, report_only=False):
    policies = [_parse_policy(policy.strip()) for value in values for policy in value.split(',')]
    value = '\n'.join(values) if values else 'Not found'
    findings = []
    for index, policy in enumerate(policies, 1):
        for item in policy['findings']:
            findings.append(dict(item, message=f"Policy #{index}: {item['message']}"))
    if report_only:
        findings.insert(0, finding('INFO', 'Report-only CSP is diagnostic and does not enforce protection.'))
        return detail(value, 0, 'INFO', 'Diagnostic CSP.', {'policies': policies}, findings, False)
    if not policies:
        return detail(value, 0, 'BAD', 'Enforced CSP is missing.',
                      findings=[finding('BAD', 'No enforced CSP was received.', 'Add an enforced Content-Security-Policy.')])
    if len(policies) > 1:
        findings.insert(0, finding('INFO', 'Multiple policies enforce together; their combined effect is not modelled. CSP is excluded from the score.'))
        return detail(value, 0, 'INFO', 'Combined CSP assessment unavailable.',
                      {'policies': policies}, findings, False)
    policy = policies[0]
    return detail(value, policy['score'], policy['status'], 'Enforced content security policy.',
                  {'policies': policies}, findings)


def _cookie(line, index):
    parts = line.split(';')
    name, separator, value = parts[0].strip().partition('=')
    attributes, findings = {}, []
    valid = bool(separator and TOKEN.fullmatch(name))
    cookie_value = value[1:-1] if len(value) >= 2 and value.startswith('"') and value.endswith('"') else value
    valid = valid and all(ord(char) == 0x21 or 0x23 <= ord(char) <= 0x2b or
                          0x2d <= ord(char) <= 0x3a or 0x3c <= ord(char) <= 0x5b or
                          0x5d <= ord(char) <= 0x7e for char in cookie_value)
    for part in parts[1:]:
        if not part.strip():
            continue
        attr, separator, argument = part.strip().partition('=')
        attr = attr.strip().lower()
        if not TOKEN.fullmatch(attr):
            valid = False
        if attr in attributes:
            findings.append(finding('INFO', f'Duplicate cookie attribute {attr}: the last occurrence is used.'))
        attributes[attr] = argument.strip() if separator else None
    parsed = {'name': name, 'attributes': attributes}
    if not valid:
        findings.append(finding('BAD', 'Malformed cookie name, value or attribute.', 'Send a valid separate Set-Cookie header.'))
        return dict(detail(line, 0, 'BAD', 'Malformed cookie.', parsed, findings), name=name or '(invalid)', index=index)
    max_age = attributes.get('max-age')
    expires = None
    valid_max_age = isinstance(max_age, str) and bool(re.fullmatch(r'-?[0-9]+', max_age)) and len(max_age) <= 100
    if isinstance(attributes.get('expires'), str):
        try:
            expires = parsedate_to_datetime(attributes['expires'])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, OverflowError):
            findings.append(finding('INFO', 'Expires is invalid and is not used to identify deletion.'))
    deletion = (int(max_age) <= 0 if valid_max_age else
                expires is not None and expires <= datetime.now(timezone.utc))
    parsed['deletion'] = deletion
    if deletion:
        findings.append(finding('INFO', 'Cookie deletes stored data; security flags are not scored.'))
        return dict(detail(line, 0, 'INFO', 'Cookie deletion.', parsed, findings, False), name=name, index=index)
    score, status = 4, 'GOOD'
    secure = 'secure' in attributes
    same_site = (attributes.get('samesite') or '').lower()
    if not secure:
        score, status = 0, 'BAD'
        findings.append(finding('BAD', 'Secure is missing.', 'Add Secure and deliver the cookie over HTTPS.'))
    else:
        findings.append(finding('GOOD', 'Secure is present.'))
    if same_site == 'none' and not secure:
        score, status = 0, 'BAD'
        findings.append(finding('BAD', 'SameSite=None requires Secure.', 'Add Secure or choose Lax/Strict if suitable.'))
    elif same_site not in ('none', 'lax', 'strict'):
        score = min(score, 2)
        if status != 'BAD':
            status = 'WARNING'
        findings.append(finding('WARNING', 'SameSite is missing or invalid.', 'Choose an explicit Lax, Strict or None policy.'))
    elif same_site == 'none':
        findings.append(finding('INFO', 'SameSite=None permits cross-site transmission; Secure is required.'))
    else:
        findings.append(finding('GOOD', f'SameSite={same_site.title()} is valid.'))
    if 'httponly' not in attributes:
        score = min(score, 3)
        if status != 'BAD':
            status = 'WARNING'
        findings.append(finding('WARNING', 'HttpOnly is absent; JavaScript access may be intentional.',
                                'Set HttpOnly for cookies that do not require JavaScript access.'))
    else:
        findings.append(finding('GOOD', 'HttpOnly is present.'))
    return dict(detail(line, score, status, 'Cookie security attributes.', parsed, findings), name=name, index=index)


def analyze_cookies(values):
    cookies = [_cookie(line, index) for index, line in enumerate(values, 1)]
    applicable = [cookie for cookie in cookies if cookie['applicable']]
    findings = [dict(item, message=f"Cookie #{cookie['index']} ({cookie['name']}): {item['message']}")
                for cookie in cookies for item in cookie['findings']]
    if not applicable:
        findings.insert(0, finding('INFO', 'No active cookies to assess; excluded from the score.'))
        result = detail('\n'.join(values) if values else 'Not found', 0, 'INFO',
                        'No applicable cookies.', findings=findings, applicable=False)
    else:
        worst = min(applicable, key=lambda cookie: cookie['score'])
        result = detail('\n'.join(values), worst['score'], worst['status'],
                        'Worst applicable cookie determines the score.', findings=findings)
    result['cookies'] = cookies
    result['parsed'] = {'count': len(cookies), 'applicable_count': len(applicable)}
    return result


LEGACY_HEADERS = {
    'X-Requested-With': 'A request convention for AJAX identification, not a response security control.',
    'X-UA-Compatible': 'A legacy browser compatibility setting, not a modern security control.',
    'X-XSS-Protection': 'Deprecated browser XSS filtering; absence or 0 is not a security weakness. Enabling the filter is not recommended.',
}


def analyze_legacy(name, values):
    message = LEGACY_HEADERS[name]
    return detail('\n'.join(values) if values else 'Not found', 0, 'INFO', message,
                  {'present': bool(values), 'values': values},
                  [finding('INFO', message)], False)


def _ancestor_policy(value, index):
    sources = None
    observations = []
    for part in value.split(';'):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() == 'frame-ancestors':
            if sources is None:
                sources = tokens[1:]
            else:
                observations.append(finding('INFO', f'Policy #{index}: duplicate frame-ancestors; the first occurrence is used.'))
    if sources is None:
        return None
    valid = True
    broad = False
    lower = [source.lower() for source in sources]
    if "'none'" in lower and len(sources) > 1:
        observations.append(finding('INFO', f'Policy #{index}: none is ignored when mixed with other ancestor sources.'))
    for source in sources:
        if source.lower() in ("'none'", "'self'"):
            continue
        if SCHEME.fullmatch(source):
            if source.lower() not in ('http:', 'https:'):
                valid = False
            broad = True
        elif HOST_SOURCE.fullmatch(source):
            # Bare hosts inherit a scheme. Explicit host schemes must be HTTP(S).
            if '://' in source and source.split('://', 1)[0].lower() not in ('http', 'https'):
                valid = False
            if '*' in source:
                broad = True
        else:
            valid = False
    score = 0 if not valid else 4 if broad else 8
    status = 'BAD' if not valid else 'WARNING' if broad else 'GOOD'
    if not valid:
        message = f'Policy #{index}: frame-ancestors has invalid or unsupported ancestor sources.'
        recommendation = "Use frame-ancestors 'none', 'self', or required HTTP(S) origins."
    elif broad:
        message = f'Policy #{index}: frame-ancestors permits broad scheme/wildcard sources.'
        recommendation = 'Restrict framing to required origins.'
    else:
        message = f'Policy #{index}: frame-ancestors restricts framing to an explicit set (or denies all).'
        recommendation = ''
    observations.append(finding(status, message, recommendation))
    return {'index': index, 'sources': sources, 'score': score,
            'status': status, 'findings': observations}


def analyze_framing(xfo_values, csp_values):
    """Score effective framing control once, under the existing XFO record."""
    policies = []
    for index, policy in enumerate((part for value in csp_values for part in value.split(',')), 1):
        result = _ancestor_policy(policy, index)
        if result is not None:
            policies.append(result)
    value = '\n'.join(xfo_values) if xfo_values else 'Not found'
    if policies:
        # Any restrictive enforced policy gives a guaranteed bound; other policies
        # cannot broaden it. This does not compute the complete intersection.
        best = max(policies, key=lambda policy: policy['score'])
        observations = [finding('INFO', 'Enforced frame-ancestors takes precedence over X-Frame-Options; default-src and report-only do not provide framing protection.')]
        observations.extend(item for policy in policies for item in policy['findings'])
        if len(policies) > 1:
            observations.append(finding('INFO', 'A restrictive policy provides a guaranteed bound; the full policy intersection is not modelled.'))
        return detail(value, best['score'], best['status'], 'Effective CSP framing protection.',
                      {'source': 'Content-Security-Policy', 'policies': policies,
                       'xfo_values': xfo_values}, observations)
    # A proxy may combine identical repeated XFO values into a comma-separated field.
    tokens = [token.strip().upper() for value in xfo_values for token in value.split(',')]
    valid = bool(tokens) and len(set(tokens)) == 1 and tokens[0] in ('DENY', 'SAMEORIGIN')
    observations = [finding('GOOD' if valid else 'BAD',
                           'X-Frame-Options provides framing protection.' if valid else
                           'No enforced frame-ancestors or valid unambiguous X-Frame-Options protection.',
                           '' if valid else "Set an enforced frame-ancestors policy or X-Frame-Options: DENY / SAMEORIGIN.")]
    return detail(value, 8 if valid else 0, 'GOOD' if valid else 'BAD',
                  'Effective X-Frame-Options framing protection.',
                  {'source': 'X-Frame-Options', 'values': tokens}, observations)
