"""Contextual HTTP header rules for v0.0.6.

This is a header configuration heuristic, not a browser or a vulnerability scan.
"""
import ipaddress
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


CORS_HEADERS = (
    'Access-Control-Allow-Origin', 'Access-Control-Allow-Methods',
    'Access-Control-Allow-Headers', 'Access-Control-Max-Age',
    'Access-Control-Allow-Credentials',
)
CONTEXTUAL_HEADERS = frozenset((*CORS_HEADERS, 'Cache-Control', 'Clear-Site-Data'))


def _contextual(values, description, parsed, findings):
    status = ('BAD' if any(item['status'] == 'BAD' for item in findings)
              else 'WARNING' if any(item['status'] == 'WARNING' for item in findings)
              else 'INFO')
    return detail('\n'.join(values) if values else 'Not found', 0, status,
                  description, parsed, findings, False)


def _split_http_list(values):
    """Split combined fields without splitting quoted commas or escaped quotes."""
    items, current = [], []
    quoted = escaped = False
    for char in ','.join(values):
        if escaped:
            escaped = False
        elif quoted and char == '\\':
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == ',' and not quoted:
            items.append(''.join(current).strip())
            current = []
            continue
        current.append(char)
    items.append(''.join(current).strip())
    return [item for item in items if item], not (quoted or escaped)


def _argument(value):
    """Return decoded HTTP token/quoted-string, validity and whether it was quoted."""
    if TOKEN.fullmatch(value):
        return value, True, False
    if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        return value, False, False
    decoded, escaped = [], False
    for char in value[1:-1]:
        code = ord(char)
        if escaped:
            if not (char == '\t' or 32 <= code <= 126 or 128 <= code <= 255):
                return value, False, True
            decoded.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '"' or not (char == '\t' or code == 32 or code == 33
                                  or 35 <= code <= 91 or 93 <= code <= 126
                                  or 128 <= code <= 255):
            return value, False, True
        else:
            decoded.append(char)
    return ''.join(decoded), not escaped, True


def _delta_seconds(value):
    # Bound integer conversion consistently with the existing HSTS parser.
    return bool(re.fullmatch(r'[0-9]{1,100}', value))


def _valid_origin(value):
    if value in ('*', 'null'):
        return True
    if not value.isascii() or any(char.isspace() for char in value):
        return False
    match = re.fullmatch(r'(https?)://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]+))?', value)
    if not match:
        return False
    host, port = match.group(2), match.group(3)
    if port and (len(port) > 5 or not 0 <= int(port) <= 65535):
        return False
    if host.startswith('['):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return False
    elif host.endswith('..') or len(host) > 254 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                 for label in host.rstrip('.').split('.')):
        return False
    elif re.fullmatch(r'[0-9.]+', host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
    return True


def analyze_cors(values_by_name, vary_values=()):
    """Inspect received CORS fields; never infer a successful CORS exchange."""
    results = {}
    credentials_values = values_by_name.get('access-control-allow-credentials', [])
    credentials = len(credentials_values) == 1 and credentials_values[0].strip() == 'true'
    vary = [token.strip().lower() for value in vary_values for token in value.split(',')]
    for name in CORS_HEADERS:
        values = values_by_name.get(name.lower(), [])
        parsed = {'raw_values': list(values)}
        findings = [finding('INFO', 'This GET sends no Origin and performs no preflight; actual CORS behavior and intended sharing are not verified.')]
        if not values:
            findings.append(finding('INFO', 'Header is absent; CORS is optional and absence is not a security failure.'))
        elif name in ('Access-Control-Allow-Methods', 'Access-Control-Allow-Headers'):
            tokens = [token.strip() for value in values for token in value.split(',') if token.strip()]
            parsed['tokens'] = tokens
            if any(not TOKEN.fullmatch(token) for token in tokens):
                findings.append(finding('BAD', 'CORS lists must contain HTTP tokens, not quoted values or phrases.', 'Use a comma-separated list of methods or header names.'))
            if '*' in tokens:
                message = 'Wildcard applies only without credentials; with credentials it is a literal token.'
                if name == 'Access-Control-Allow-Headers':
                    message += ' Authorization must always be explicitly listed.'
                findings.append(finding('WARNING' if credentials else 'INFO', message))
            findings.append(finding('INFO', 'Listed methods or headers do not establish a vulnerability or successful preflight.'))
        else:
            if len(values) != 1:
                findings.append(finding('BAD' if name == 'Access-Control-Allow-Origin' else 'WARNING', 'Repeated single-value CORS header is ambiguous; no value is selected.', 'Send one unambiguous header field.'))
                if name == 'Access-Control-Allow-Credentials' and any(value.strip() != 'true' for value in values):
                    findings.append(finding('BAD', 'Allow-Credentials accepts only the case-sensitive value true.'))
                elif name == 'Access-Control-Max-Age' and any(not _delta_seconds(value.strip()) for value in values):
                    findings.append(finding('BAD', 'Each Max-Age value must be a non-negative integer (up to 100 digits).'))
            else:
                value = values[0].strip()
                parsed['value'] = value
                if name == 'Access-Control-Allow-Origin':
                    if not _valid_origin(value):
                        findings.append(finding('BAD', 'Allow-Origin must be *, null, or one HTTP(S) origin without path, query, fragment or userinfo.', 'Send a single valid origin, not a list.'))
                    elif value == '*':
                        findings.append(finding('WARNING' if credentials else 'INFO', 'Wildcard permits sharing without credentials; it cannot authorize credentialed sharing, even with Allow-Credentials: true. This does not demonstrate a data leak.'))
                    elif value == 'null':
                        findings.append(finding('WARNING', 'null can match several opaque origins; intended access cannot be established.', 'Use null only when sharing with opaque origins is intentional.'))
                    elif 'origin' not in vary and '*' not in vary:
                        findings.append(finding('INFO', 'If the allowed origin changes with the request Origin, use Vary: Origin. A fixed origin does not require it.'))
                elif name == 'Access-Control-Allow-Credentials':
                    parsed['allows_credentials'] = value == 'true'
                    if value != 'true':
                        findings.append(finding('BAD', 'Allow-Credentials accepts only the case-sensitive value true.', 'Omit the header when credentialed sharing is not intended.'))
                elif not _delta_seconds(value):
                    findings.append(finding('BAD', 'Max-Age must be a non-negative integer (up to 100 digits).', 'Use an integer number of seconds.'))
                else:
                    parsed['seconds'] = int(value)
                    findings.append(finding('INFO', 'Preflight cache lifetime is a performance setting; browsers can impose their own limits.'))
        results[name] = _contextual(values, 'Context-dependent CORS configuration.', parsed, findings)
    return results


def analyze_cache_control(values):
    directives, findings = {}, []
    items, balanced = _split_http_list(values)
    if not values:
        findings.append(finding('INFO', 'Cache-Control is absent; appropriate caching depends on resource sensitivity and purpose.'))
    elif not balanced or not items:
        findings.append(finding('BAD', 'Cache-Control has an empty value or an unterminated quoted-string.'))
    numeric = ('max-age', 's-maxage', 'stale-while-revalidate', 'stale-if-error')
    bare = {'no-store', 'public', 'must-revalidate', 'proxy-revalidate', 'must-understand', 'immutable'}
    for item in items:
        name, separator, argument = item.partition('=')
        name = name.strip().lower()
        if not TOKEN.fullmatch(name):
            findings.append(finding('BAD', f'Invalid cache directive: {item}.'))
            continue
        decoded, valid, quoted = _argument(argument.strip()) if separator else (None, True, False)
        directives.setdefault(name, []).append(decoded)
        if not valid:
            findings.append(finding('BAD', f'{name} has an invalid token or quoted-string argument.'))
        elif name in numeric and (decoded is None or not _delta_seconds(decoded)):
            findings.append(finding('BAD', f'{name} requires a non-negative integer (up to 100 digits).'))
        elif name in bare and separator:
            findings.append(finding('BAD', f'{name} does not take an argument.'))
        elif name in ('private', 'no-cache') and separator:
            fields = [field.strip() for field in decoded.split(',') if field.strip()]
            if not quoted or any(not TOKEN.fullmatch(field) for field in fields):
                findings.append(finding('BAD', f'{name} requires a quoted list of field names when qualified.'))
    for name in numeric:
        if len(directives.get(name, [])) > 1:
            findings.append(finding('WARNING', f'{name} is repeated; freshness is ambiguous and no value is selected.'))
    if 'public' in directives and 'private' in directives:
        findings.append(finding('WARNING', 'public and private occur together; shared-cache policy is ambiguous.'))
    explanations = {
        'no-store': 'When valid, no-store forbids storing this response; it does not erase previously stored data.',
        'no-cache': 'When valid, no-cache allows storage but requires validation before reuse; a qualified list applies to the listed fields.',
        'private': 'When valid, private restricts shared-cache storage; browser storage is allowed. A qualified list restricts only the listed fields.',
        'public': 'When valid, public permits shared-cache storage; this can be intentional for public resources.',
    }
    for name, message in explanations.items():
        if name in directives:
            findings.append(finding('INFO', message))
    extensions = {name: arguments for name, arguments in directives.items()
                  if name not in set(numeric) | bare | {'private', 'no-cache'}}
    if extensions:
        findings.append(finding('INFO', 'Unknown cache extensions are retained; their semantics are not evaluated.'))
    findings.append(finding('INFO', 'Data sensitivity is unknown; caching directives receive no security points. For data that must not be stored, consider no-store rather than no-cache.'))
    return _contextual(values, 'Context-dependent HTTP caching policy.',
                       {'directives': directives, 'extensions': extensions}, findings)


def analyze_clear_site_data(values, final_url):
    items, balanced = _split_http_list(values)
    types, unknown, findings = [], [], []
    known = {'cache', 'cookies', 'storage', 'executionContexts', '*'}
    if not values:
        findings.append(finding('INFO', 'Clear-Site-Data is optional; absence does not establish a logout or security failure.'))
    elif not balanced or not items:
        findings.append(finding('BAD', 'Clear-Site-Data requires a non-empty list of quoted strings.'))
    for item in items:
        value, valid, quoted = _argument(item)
        if not valid or not quoted or not value.isascii():
            findings.append(finding('BAD', f'Invalid Clear-Site-Data type: {item}; use ASCII double-quoted strings.'))
        elif value in known:
            types.append(value)
        else:
            unknown.append(value)
    if unknown:
        findings.append(finding('WARNING', 'Unknown types are retained; browsers may ignore them and support varies.'))
    parsed_url = urlsplit(final_url)
    host = (parsed_url.hostname or '').lower().rstrip('.')
    local = host == 'localhost' or host.endswith('.localhost')
    try:
        local = local or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    trustworthy = parsed_url.scheme == 'https' or (parsed_url.scheme == 'http' and local)
    if values:
        if not trustworthy:
            findings.append(finding('WARNING', 'Clear-Site-Data requires a potentially trustworthy origin; ordinary HTTP does not qualify. HTTPS and local loopback/localhost origins are treated separately.'))
        elif parsed_url.scheme == 'http':
            findings.append(finding('INFO', 'Local HTTP may be potentially trustworthy; browser support and policy still apply.'))
        findings.append(finding('INFO', 'These types request browser data clearing; execution and logout intent are not verified. Do not add clearing to every response.'))
    return _contextual(values, 'Optional browser data-clearing request.',
                       {'types': types, 'unknown_types': unknown,
                        'potentially_trustworthy': trustworthy, 'final_url': final_url}, findings)


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
