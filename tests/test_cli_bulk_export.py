import csv
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import main
from src import bulk_checker as bulk
from src.exporter import export_results


def header_result():
    return {'success': True, 'total_score': 5, 'max_score': 10,
            'headers': {'Test-Header': {'value': 'a,b', 'status': 'GOOD', 'score': 5,
                                      'description': 'Test'}},
            'summary': {'good': 1, 'bad': 0, 'info': 0, 'warning': 0}}


def response_result():
    return {'success': True, 'status_code': 200, 'status_message': 'OK',
            'response_time': 0.01, 'server_info': {}, 'security_headers': {},
            'additional_headers': {}, 'redirect_chain': []}


def ssl_result():
    return {'success': True, 'score': {'total_score': 95, 'max_score': 95,
            'percentage': 100, 'security_level': 'Excellent', 'limitations': 'Test heuristic'},
            'certificate': {'success': True}, 'protocols': {'success': True, 'protocols': {}},
            'ciphers': {'success': False, 'error': 'test detail'}}


@pytest.fixture
def mock_checks(monkeypatch):
    calls = []
    def header(url, **kwargs):
        calls.append(('headers', url))
        return header_result()
    def ssl(url, timeout):
        calls.append(('ssl', url))
        return ssl_result()
    def response(self, url, **kwargs):
        calls.append(('response', url))
        return response_result()
    monkeypatch.setattr(bulk, 'check_security_headers', header)
    monkeypatch.setattr(bulk, 'analyze_ssl_security', ssl)
    monkeypatch.setattr(bulk.ResponseAnalyzer, 'analyze_response_headers', response)
    return calls


@pytest.mark.parametrize('count', [1, 2])
@pytest.mark.parametrize('flags,modules', [([], {'headers'}),
    (['--ssl-only', '--response-analysis'], {'ssl'}),
    (['--response-only', '--ssl-check'], {'response'}),
    (['--ssl-check', '--response-analysis'], {'headers','ssl','response'})])
def test_modes(mock_checks, tmp_path, capsys, count, flags, modules):
    urls = [f'https://site{i}.invalid' for i in range(count)]
    output = tmp_path / 'report.json'
    assert main.main(['--urls', ','.join(urls), '--output', str(output)] + flags) == 0
    assert {module for module, _ in mock_checks} == modules
    assert len(mock_checks) == count * len(modules)
    report = json.loads(output.read_text(encoding='utf-8'))
    sites = report.get('results', [report])
    for site in sites:
        assert all((site[module] is not None) == (module in modules)
                   for module in ('headers','ssl','response'))
    text = capsys.readouterr().out
    assert ('Security Header Check Results:' in text) == ('headers' in modules)
    assert ('SSL/TLS Security Results:' in text) == ('ssl' in modules)
    assert ('HTTP Response Analysis:' in text) == ('response' in modules)


@pytest.mark.parametrize('flag', ['--timeout','--parallel','--batch-size','--max-redirects'])
@pytest.mark.parametrize('value', ['0','-1','invalid'])
def test_positive_cli_parameters(flag, value):
    with pytest.raises(SystemExit) as exc:
        main.main(['https://example.invalid', flag, value])
    assert exc.value.code == 2


@pytest.mark.parametrize('args', [['--ssl-only','--response-only'],
    ['https://example.invalid','--urls','https://other.invalid'],
    ['--file','urls.txt','--urls','https://other.invalid'],
    ['https://'],['ftp://example.invalid'],['https://example.invalid:bad']])
def test_cli_invalid_combinations(args):
    with pytest.raises(SystemExit) as exc:
        main.main(args)
    assert exc.value.code == 2


def test_partial_module_failure(monkeypatch):
    monkeypatch.setattr(bulk, 'check_security_headers', lambda *a, **k: {'success':False,'error':'Timeout: headers'})
    monkeypatch.setattr(bulk.ResponseAnalyzer, 'analyze_response_headers', lambda *a, **k: response_result())
    def fail(*args, **kwargs):
        raise RuntimeError('TLS failure')
    monkeypatch.setattr(bulk, 'analyze_ssl_security', fail)
    result = bulk.BulkChecker().check_single_site('https://example.invalid', check_ssl=True, check_response=True)
    assert not result['success']
    assert result['response']['success']
    assert result['errors'] == {'headers':'Timeout: headers','ssl':'RuntimeError: TLS failure'}


def test_mixed_summary():
    results = [{'url':'good','success':True,'headers':header_result(),'ssl':None},
               {'url':'bad','success':False,'headers':None,'ssl':None},
               {'url':'partial','success':False,'headers':header_result(),'ssl':{'success':False}}]
    summary = bulk.BulkChecker().generate_summary_report(results)
    assert summary['successful_checks'] == 1
    assert summary['failed_checks'] == 2
    assert set(summary['best_sites']) == {'good','partial'}
    assert summary['average_header_score'] == 5
    assert bulk.BulkChecker().generate_summary_report([])['success_rate'] == 0


@pytest.mark.parametrize('workers,batch_size', [(4,2),(2,5),(1,3)])
def test_bounded_batches(monkeypatch, workers, batch_size):
    submitted, finished = [], set()
    lock = threading.Lock()
    active, peak = 0, 0
    class RecordingExecutor(ThreadPoolExecutor):
        def submit(self, fn, url, **kwargs):
            with lock:
                if len(submitted) and len(submitted) % batch_size == 0:
                    assert set(submitted).issubset(finished)
                submitted.append(url)
            return super().submit(fn,url,**kwargs)
    monkeypatch.setattr(bulk, 'ThreadPoolExecutor', RecordingExecutor)
    checker = bulk.BulkChecker(workers,batch_size)
    def run(url, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        with lock:
            active -= 1
            finished.add(url)
        return {'url':url,'success':True}
    monkeypatch.setattr(checker,'check_single_site',run)
    urls = [str(i) for i in range(7)]
    assert [r['url'] for r in checker.check_multiple_sites(urls)] == urls
    assert peak <= min(workers,batch_size)


@pytest.mark.parametrize('bulk_report', [False,True])
@pytest.mark.parametrize('mode', ['headers','ssl','response','partial'])
@pytest.mark.parametrize('ext', ['json','txt','csv'])
def test_composed_export(tmp_path, bulk_report, mode, ext):
    site = {'url':'https://example.invalid','headers':None,'ssl':None,'response':None,
            'success':True,'timestamp':'test','error':None}
    if mode == 'partial':
        site.update(headers=header_result(),response={'success':False,'error':'Timeout: response'},
                    success=False,error='response: Timeout')
    else:
        site[mode] = {'headers':header_result,'ssl':ssl_result,'response':response_result}[mode]()
    report = {'results':[site,dict(site,url='https://other.invalid')],'summary':{'total_sites':2}} if bulk_report else site
    target = tmp_path / ('report.'+ext)
    assert export_results(report,target)
    text = target.read_text(encoding='utf-8')
    if ext == 'json':
        assert json.loads(text) == report
    elif ext == 'csv':
        with target.open(encoding='utf-8',newline='') as source:
            rows = list(csv.DictReader(source))
        assert rows
        assert set(rows[0]) == {'URL','Module','Check','Value','Status','Score','Error'}
        if mode == 'headers':
            assert rows[0]['Value'] == 'a,b'
        if mode == 'partial':
            assert any(row['Error'] == 'Timeout: response' for row in rows)
    else:
        assert 'Security Header Checker Results' in text
        if mode == 'partial':
            assert 'Timeout: response' in text
    if ext != 'json' and mode not in ('partial',):
        for disabled in {'headers','ssl','response'} - {mode}:
            assert f'Module: {disabled}' not in text


@pytest.mark.parametrize('ext', ['txt','json','csv'])
def test_write_failure(tmp_path, ext):
    assert not export_results({'url':'x','headers':header_result()},tmp_path/'missing'/('report.'+ext))
    directory = tmp_path / ('directory.'+ext)
    directory.mkdir()
    assert not export_results({'url':'x'},directory)


def test_unknown_export(tmp_path):
    target = tmp_path/'report.md'
    assert not export_results({},target)
    assert not target.exists()


def test_cli_failure_export(mock_checks, monkeypatch, tmp_path):
    monkeypatch.setattr(bulk,'check_security_headers',lambda *a,**k:{'success':False,'error':'unreachable'})
    target = tmp_path/'failed.json'
    assert main.main(['https://example.invalid','--response-analysis','-o',str(target)]) == 1
    report = json.loads(target.read_text(encoding='utf-8'))
    assert report['response']['success']
    assert report['headers']['error'] == 'unreachable'
    assert main.main(['https://example.invalid','--response-only','-o',str(tmp_path/'missing'/'report.txt')]) == 1


def test_url_file_and_empty(mock_checks, tmp_path):
    source=tmp_path/'urls.txt'
    source.write_text('# comment\n\nexample.invalid\nhttps://other.invalid\n',encoding='utf-8')
    assert main.main(['--file',str(source)]) == 0
    source.write_text('# only comments\n',encoding='utf-8')
    with pytest.raises(SystemExit):
        main.main(['--file',str(source)])
