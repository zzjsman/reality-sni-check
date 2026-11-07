import importlib.util
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import ssl

spec=importlib.util.spec_from_file_location('check', str(pathlib.Path(__file__).resolve().parents[1]/'check.py'))
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def args(**kw):
    a=dict(rounds=3, timeout=1, family='4', port=443, cafile=None, xray=None)
    a.update(kw)
    return SimpleNamespace(**a)

def sample(alpn='h2'):
    return dict(ok=True,tls='TLSv1.3',alpn=alpn,peer='127.0.0.1',elapsed_ms=12)

class Tests(unittest.TestCase):
    def setUp(self):
        mocker=patch.object(m,'group_probe',return_value={'ok':True})
        mocker.start()
        self.addCleanup(mocker.stop)

    def test_domains(self):
        domains=m.load_domains(str(pathlib.Path(__file__).resolve().parents[1]/'domains.txt'))
        self.assertEqual(len(domains),61)
        self.assertEqual(domains.count('www.swift.com'),1)
        self.assertEqual(domains.count('academy.nvidia.com'),1)
    def test_normalize(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'domains.txt'
            p.write_text('# test\n HTTPS://WWW.APPLE.COM/a\nwww.apple.com\n')
            self.assertEqual(m.load_domains(p),['www.apple.com'])
            p.write_text('bad;echo.example\n')
            with self.assertRaises(ValueError): m.load_domains(p)
    def test_pass_and_redirect(self):
        with patch.object(m,'bounded',side_effect=[sample(),sample(),sample(),dict(ok=True,http_status=302,location='https://example.org/')]):
            r=m.evaluate('example.com',args())
            self.assertEqual(r['status'],'TLS_PREFLIGHT_PASS')
            self.assertEqual(r['http']['http_status'],302)
    def test_partial_not_pass(self):
        with patch.object(m,'bounded',side_effect=[sample(),{'ok':False,'error':'TIMEOUT'},sample(),{}]):
            self.assertEqual(m.evaluate('example.com',args())['status'],'PARTIAL_SUCCESS')
    def test_h2_not_pass(self):
        with patch.object(m,'bounded',side_effect=[sample('http/1.1')]*3+[{}]):
            self.assertEqual(m.evaluate('example.com',args())['status'],'H2_NOT_CONSISTENT')
    def test_tls_error_does_not_mean_unsupported(self):
        with patch.object(m,'bounded',return_value={'ok':False,'error':'TLS_ERROR'}):
            self.assertEqual(m.evaluate('example.com',args())['status'],'NO_SUCCESS_IN_SAMPLES')
    def test_cert_separate(self):
        with patch.object(m,'context',side_effect=ssl.SSLCertVerificationError(1,'hostname mismatch')):
            r=m.probe('example.com','4',1)
            self.assertEqual(r['error'],'CERTIFICATE_VERIFY_FAILED')
            self.assertIn('hostname mismatch',r['detail'])
    def test_timeout_bounds_dns_worker(self):
        with patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('test',2)):
            self.assertEqual(m.bounded('example.com',args(),'tls')['error'],'TIMEOUT_DNS_TCP_TLS_OR_HTTP')
    def test_cli_exports(self):
        with tempfile.TemporaryDirectory() as d:
            file=pathlib.Path(d)/'domains.txt'; file.write_text('example.com\n')
            argv=['check.py','-f',str(file),'--out',d,'--region','test','--rounds','1']
            with patch.object(m.ssl,'HAS_TLSv1_3',True), patch.object(m.sys,'argv',argv), patch.object(m,'bounded',side_effect=[sample(),{'ok':True,'http_status':403}]):
                m.main()
            self.assertEqual(len(list(pathlib.Path(d).glob('*.json'))),1)
            self.assertEqual(len(list(pathlib.Path(d).glob('*.csv'))),1)

class RankingTests(unittest.TestCase):
    def result(self, host='example.com', **kw):
        r=dict(domain=host,status='TLS_PREFLIGHT_PASS',rounds=5,success=5,median_ms=10,p95_ms=12,http={'ok':True,'http_status':200},x25519={'ok':True})
        r.update(kw)
        return r
    def test_no_forced_recommendation(self):
        self.assertIn('没有满足',m.recommendations([self.result(status='PARTIAL_SUCCESS')],443))
    def test_redirect_review(self):
        self.assertTrue(m.review_reasons(self.result(http={'ok':True,'http_status':301})))
    def test_control_review(self):
        self.assertTrue(m.review_reasons(self.result('dl.google.com')))
    def test_order(self):
        rs=[self.result('slow.example',median_ms=90),self.result('fast.example')]
        report=m.recommendations(rs,443)
        self.assertIn('首选: fast.example',report)
    def test_embedded_defaults(self):
        self.assertEqual(len(m.load_domains(None)),61)

if __name__ == '__main__': unittest.main()
