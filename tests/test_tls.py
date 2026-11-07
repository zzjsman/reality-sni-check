"""Offline integration: real TLS server, trust, hostname and X25519 checks."""
import importlib.util
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('check', Path(__file__).resolve().parents[1]/'check.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

@unittest.skipUnless(ssl.HAS_TLSv1_3 and shutil.which('openssl'), 'requires modern TLS runtime')
class TLSIntegration(unittest.TestCase):
    def test_actual_tls_and_hostname(self):
        with tempfile.TemporaryDirectory() as d:
            key, cert = str(Path(d)/'key.pem'), str(Path(d)/'cert.pem')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                            '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
                            '-keyout',key,'-out',cert],check=True,capture_output=True)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version=ssl.TLSVersion.TLSv1_3
            ctx.set_alpn_protocols(['h2','http/1.1'])
            ctx.load_cert_chain(cert,key)
            listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(5)
            listener.settimeout(2)
            port=listener.getsockname()[1]; stop=threading.Event()
            def serve():
                while not stop.is_set():
                    try: raw,_=listener.accept()
                    except socket.timeout: continue
                    except OSError: break
                    try:
                        raw.settimeout(2)
                        with ctx.wrap_socket(raw,server_side=True) as tls:
                            if tls.selected_alpn_protocol()=='http/1.1':
                                tls.recv(4096)
                                tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    except (ssl.SSLError,OSError): raw.close()
            thread=threading.Thread(target=serve,daemon=True); thread.start()
            try:
                good=m.probe('localhost','4',3,port=port,cafile=cert)
                self.assertTrue(good['ok'],good)
                self.assertEqual(good['tls'],'TLSv1.3'); self.assertEqual(good['alpn'],'h2')
                wrong=m.probe('127.0.0.1','4',3,port=port,cafile=cert)
                self.assertEqual(wrong['error'],'CERTIFICATE_VERIFY_FAILED')
                http=m.probe('localhost','4',3,mode='http',port=port,cafile=cert)
                self.assertEqual(http['http_status'],200)
                group=m.group_probe('localhost',SimpleNamespace(port=port,family='4',cafile=cert,timeout=3))
                self.assertTrue(group['ok'],group)
                worker=m.bounded('localhost',SimpleNamespace(port=port,family='4',cafile=cert,timeout=3),'tls')
                self.assertTrue(worker['ok'],worker)
            finally:
                stop.set(); listener.close(); thread.join(3)
