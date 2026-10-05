"""Export the same composed report to JSON, TXT or CSV."""
import csv
import json
from pathlib import Path

COLUMNS = ['URL', 'Module', 'Check', 'Value', 'Status', 'Score', 'Error']


def _finding_text(item):
    message = item['message']
    if item.get('recommendation'):
        message += ' Recommendation: ' + item['recommendation']
    return message


def report_rows(report):
    sites = report.get('results', [report])
    for site in sites:
        url = site.get('url', '')
        # Also accept the original flat header result for library callers.
        modules = {'headers': site} if 'total_score' in site else {
            name: site.get(name) for name in ('headers', 'ssl', 'response')}
        for module, data in modules.items():
            if data is None:
                continue
            def row(check, value='', status='INFO', score='', error=''):
                return dict(zip(COLUMNS, (url, module, check, value, status, score, error)))
            if not data.get('success'):
                yield row('analysis', status='ERROR', error=data.get('error', 'Analysis incomplete'))
            if module == 'headers':
                for name, detail in data.get('headers', {}).items():
                    yield row(name, detail.get('value', ''), detail.get('status', 'INFO'), detail.get('score', ''))
                    for index, item in enumerate(detail.get('findings', []), 1):
                        yield row(f'{name}/finding#{index}', _finding_text(item), item['status'])
                    for cookie in detail.get('cookies', []):
                        label = f"Set-Cookie/#{cookie['index']} ({cookie['name']})"
                        yield row(label, cookie['value'], cookie['status'], cookie['score'])
                if 'total_score' in data:
                    value = f"{data['total_score']}/{data['max_score']}" if data['max_score'] else 'N/A (no applicable checks)'
                    yield row('score', value, 'INFO', data['total_score'] if data['max_score'] else '')
                if data.get('final_url'):
                    yield row('final_url', data['final_url'])
            elif module == 'ssl':
                for name in ('certificate', 'protocols', 'ciphers'):
                    detail = data.get(name)
                    if detail is None:
                        continue
                    yield row(name, json.dumps(detail, ensure_ascii=False),
                              'INFO' if detail.get('success') else 'ERROR',
                              error=detail.get('error') or detail.get('verification_error', ''))
                if data.get('score'):
                    score = data['score']
                    yield row('score', f"{score['total_score']}/{score['max_score']}",
                              'INFO', score['total_score'])
            else:
                if data.get('success'):
                    yield row('status_code', data['status_code'])
                    yield row('response_time', data['response_time'])
                    for name, detail in data.get('security_headers', {}).items():
                        yield row(name, detail.get('value') or '', 'PRESENT' if detail['present'] else 'ABSENT')
                    for name, value in data.get('additional_headers', {}).items():
                        yield row(name, value)
                    for name in ('server_info', 'redirect_chain'):
                        yield row(name, json.dumps(data.get(name), ensure_ascii=False))
        if site.get('error') and not any(data and not data.get('success') for data in modules.values()):
            yield dict(zip(COLUMNS, (url, 'site', 'analysis', '', 'ERROR', '', site['error'])))


def save_to_json(result, filepath):
    try:
        with open(filepath, 'w', encoding='utf-8') as target:
            json.dump(result, target, indent=2, ensure_ascii=False)
        return True
    except (OSError, TypeError, ValueError) as exc:
        print(f'Error saving JSON: {exc}')
        return False


def save_to_csv(result, filepath):
    try:
        with open(filepath, 'w', encoding='utf-8', newline='') as target:
            writer = csv.DictWriter(target, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(report_rows(result))
        return True
    except (OSError, TypeError, ValueError, KeyError) as exc:
        print(f'Error saving CSV: {exc}')
        return False


def save_to_txt(result, filepath):
    try:
        with open(filepath, 'w', encoding='utf-8') as target:
            target.write('Security Header Checker Results\n')
            target.write(f"Generated at: {result.get('timestamp', '')}\n")
            if result.get('summary'):
                target.write('Summary: ' + json.dumps(result['summary'], ensure_ascii=False) + '\n')
            for row in report_rows(result):
                target.write(' | '.join(f'{key}: {value}' for key, value in row.items()) + '\n')
        return True
    except (OSError, TypeError, ValueError, KeyError) as exc:
        print(f'Error saving TXT: {exc}')
        return False


def export_results(result, filepath):
    saver = {'.txt': save_to_txt, '.json': save_to_json, '.csv': save_to_csv}.get(Path(filepath).suffix.lower())
    if saver is None:
        print(f'Error: Unsupported file extension: {Path(filepath).suffix}')
        return False
    return saver(result, filepath)
