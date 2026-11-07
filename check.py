#!/usr/bin/env python3
"""Direct TLS preflight; never claims GFW or REALITY compatibility."""
import argparse
import concurrent.futures
import csv
import datetime
import http.client
import json
import math
import os
from pathlib import Path
import re
import socket
import shutil
import ssl
import statistics
import subprocess
import sys
import time
from urllib.parse import urlsplit


DEFAULT_DOMAINS = '# Apple\ngateway.icloud.com\nitunes.apple.com\nswdist.apple.com\nswcdn.apple.com\nupdates.cdn-apple.com\nmensura.cdn-apple.com\nosxapps.itunes.apple.com\naod.itunes.apple.com\n# Mozilla\ndownload-installer.cdn.mozilla.net\naddons.mozilla.org\n# CDN\ns0.awsstatic.com\nd1.awsstatic.com\ncdn-dynmedia-1.microsoft.com\n# Amazon / media\nimages-na.ssl-images-amazon.com\nm.media-amazon.com\nplayer.live-video.net\n# Anime / game\none-piece.com\nlol.secure.dyn.riotcdn.net\nwww.lovelive-anime.jp\n# NVIDIA\nacademy.nvidia.com\n# Microsoft\nsoftware.download.prss.microsoft.com\n# Google: control candidates; not presumed unblocked\ndl.google.com\nwww.google-analytics.com\n# Universities\nwww.caltech.edu\nwww.calstatela.edu\nwww.suny.edu\nwww.suffolk.edu\n# Technology\nwww.python.org\nvuejs-jp.org\nvuejs.org\nzh-hk.vuejs.org\nreact.dev\nwww.java.com\nwww.oracle.com\nwww.mysql.com\nwww.mongodb.com\nredis.io\n# DNS infrastructure: do not presume an HTTPS target\ncname.vercel-dns.com\nvercel-dns.com\n# Other\nwww.swift.com\nwww.cisco.com\nwww.asus.com\nwww.samsung.com\nwww.amd.com\nwww.umcg.nl\nwww.fom-international.com\nwww.u-can.co.jp\ngithub.io\n# Earlier backup candidates\nwww.apple.com\nwww.bing.com\nwww.samsung.com\nwww.nvidia.com\nwww.ibm.com\nwww.sony.com\nwww.adobe.com\nwww.intel.com\nwww.dell.com\nwww.autodesk.com\n# 233boy/Xray built-in candidates, reviewed 2026-11-07\nwww.amazon.com\nwww.ebay.com\nwww.paypal.com\naws.amazon.com\n'

def context(alpn, cafile=None):
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(alpn)
    return ctx


def connect(host, port, family, timeout):
    start = time.monotonic()
    af = {'4': socket.AF_INET, '6': socket.AF_INET6, 'auto': socket.AF_UNSPEC}[family]
    addresses = socket.getaddrinfo(host, port, af, socket.SOCK_STREAM)
    dns_ms = round((time.monotonic() - start) * 1000, 1)
    last = None
    for af, kind, proto, _, address in addresses:
        sock = socket.socket(af, kind, proto)
        try:
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                raise TimeoutError('DNS/TCP deadline exceeded')
            sock.settimeout(remaining)
            sock.connect(address)
            return sock, dns_ms, start
        except OSError as exc:
            sock.close()
            last = exc
    raise last or OSError('No address available')


def probe(host, family, timeout, mode='tls', port=443, cafile=None):
    start = time.monotonic()
    try:
        ctx = context(['h2', 'http/1.1'] if mode == 'tls' else ['http/1.1'], cafile)
        raw, dns_ms, connect_start = connect(host, port, family, timeout)
        with raw:
            raw.settimeout(max(0.05, timeout - (time.monotonic() - connect_start)))
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                result = dict(ok=True, tls=tls.version(), alpn=tls.selected_alpn_protocol(),
                              peer=tls.getpeername()[0], dns_ms=dns_ms,
                              elapsed_ms=round((time.monotonic() - start) * 1000, 1),
                              certificate_verified=True,
                              cert_expires=tls.getpeercert().get('notAfter'))
                if mode == 'http':
                    # HEAD only; no redirects, cookies, proxy environment, or response body download.
                    tls.sendall(('HEAD / HTTP/1.1\r\nHost: ' + host +
                                 '\r\nUser-Agent: SNI-Preflight/1.0\r\nConnection: close\r\n\r\n').encode('ascii'))
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    result.update(http_status=response.status,
                                  location=response.getheader('Location', '')[:1000])
                    response.close()
                return result
    except ssl.SSLCertVerificationError as exc:
        kind = 'CERTIFICATE_VERIFY_FAILED'
        detail = str(exc)
    except socket.gaierror as exc:
        kind = 'DNS_ERROR'
        detail = str(exc)
    except (socket.timeout, TimeoutError) as exc:
        kind = 'TIMEOUT'
        detail = str(exc)
    except ssl.SSLError as exc:
        kind = 'TLS_ERROR'
        detail = str(exc)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        kind = 'NETWORK_OR_HTTP_ERROR'
        detail = str(exc)
    return dict(ok=False, error=kind, detail=detail[:1500])


def bounded(host, args, mode):
    cmd = [sys.executable, str(Path(__file__).resolve()), '--worker', host,
           '--family', args.family, '--timeout', str(args.timeout), '--mode', mode,
           '--port', str(args.port)]
    if args.cafile:
        cmd += ['--cafile', args.cafile]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout + 1)
        if proc.returncode:
            return dict(ok=False, error='LOCAL_WORKER_ERROR', detail=proc.stderr[-1200:])
        return json.loads(proc.stdout)
    except subprocess.TimeoutExpired:
        return dict(ok=False, error='TIMEOUT_DNS_TCP_TLS_OR_HTTP')
    except (ValueError, OSError) as exc:
        return dict(ok=False, error='LOCAL_WORKER_ERROR', detail=str(exc))


def load_domains(path):
    result = []
    for line in (Path(path).read_text(encoding='utf-8') if path else DEFAULT_DOMAINS).splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        host = urlsplit(line if '://' in line else '//' + line).hostname
        host = (host or '').rstrip('.').encode('idna').decode('ascii').lower()
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                     for label in host.split('.')) or '.' not in host:
            raise ValueError('Invalid hostname: ' + line)
        if host not in result:
            result.append(host)
    if not result:
        raise ValueError('Empty domain file')
    return result


def group_probe(host, args):
    executable = shutil.which('openssl')
    if not executable:
        return dict(ok=False, error='OPENSSL_NOT_INSTALLED')
    cmd = [executable, 's_client', '-connect', '%s:%d' % (host, args.port),
           '-servername', host, '-tls1_3', '-groups', 'X25519', '-alpn', 'h2',
           '-verify_return_error', '-verify_hostname', host]
    if args.family != 'auto':
        cmd.append('-' + args.family)
    if args.cafile:
        cmd += ['-CAfile', args.cafile]
    try:
        run = subprocess.run(cmd, input='', capture_output=True, text=True, timeout=args.timeout + 1)
        output = run.stdout + run.stderr
        # Some OpenSSL versions report an EOF error after an otherwise valid handshake.
        # Require explicit negotiated group, TLS version, ALPN and verification evidence.
        ok = bool(re.search(r'(?:Server Temp Key|Peer Temp Key): X25519', output)) and \
             'TLSv1.3' in output and 'ALPN protocol: h2' in output and \
             ('Verify return code: 0 (ok)' in output or 'Verification: OK' in output)
        return dict(ok=ok, returncode=run.returncode, output=output[-16000:])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return dict(ok=False, error=str(exc))


def evaluate(host, args):
    samples = [bounded(host, args, 'tls') for _ in range(args.rounds)]
    successful = [s for s in samples if s.get('ok') and s.get('tls') == 'TLSv1.3']
    h2 = sum(s.get('alpn') == 'h2' for s in successful)
    times = sorted(s['elapsed_ms'] for s in successful)
    if h2 == args.rounds:
        status = 'TLS_PREFLIGHT_PASS'
    elif not successful:
        status = 'NO_SUCCESS_IN_SAMPLES'
    elif len(successful) < args.rounds:
        status = 'PARTIAL_SUCCESS'
    else:
        status = 'H2_NOT_CONSISTENT'
    http = bounded(host, args, 'http') if successful else {'skipped': True}
    result = dict(domain=host, status=status, success=len(successful), rounds=args.rounds,
                  h2_success=h2, median_ms=round(statistics.median(times), 1) if times else None,
                  p95_ms=times[math.ceil(len(times) * .95)-1] if times else None,
                  peers=sorted({s['peer'] for s in successful}), samples=samples, http=http)
    if status == 'TLS_PREFLIGHT_PASS':
        result['x25519'] = group_probe(host, args)
    if args.xray and status == 'TLS_PREFLIGHT_PASS':
        try:
            run = subprocess.run([args.xray, 'tls', 'ping', host + ':' + str(args.port)],
                                 capture_output=True, text=True, timeout=30)
            result['xray'] = dict(returncode=run.returncode, output=(run.stdout + run.stderr)[-20000:])
        except (OSError, subprocess.TimeoutExpired) as exc:
            result['xray'] = dict(error=str(exc))
    return result


def review_reasons(r):
    reasons = []
    if r['status'] != 'TLS_PREFLIGHT_PASS':
        reasons.append(r['status'])
    if r['rounds'] < 3:
        reasons.append('fewer than 3 samples')
    if r['domain'] in {'dl.google.com', 'cname.vercel-dns.com', 'vercel-dns.com', 'github.io'}:
        reasons.append('control/infrastructure candidate: manual review required')
    if not r.get('x25519', {}).get('ok'):
        reasons.append('X25519 + TLS1.3 + h2 diagnostic not confirmed')
    h = r['http']
    if not h.get('ok'):
        reasons.append('HTTP root check unavailable')
    elif 300 <= h.get('http_status', 0) < 400:
        reasons.append('HTTP root redirects: inspect destination')
    if r.get('xray', {}).get('error') or r.get('xray', {}).get('returncode', 0) != 0:
        reasons.append('Xray diagnostic failed: inspect raw output')
    return reasons


def recommendations(results, port):
    for r in results:
        r['review_reasons'] = review_reasons(r)
    results.sort(key=lambda r: (bool(r['review_reasons']), r['status'] != 'TLS_PREFLIGHT_PASS',
                               -r['success'], r['median_ms'] if r['median_ms'] is not None else float('inf'),
                               r['p95_ms'] if r['p95_ms'] is not None else float('inf')))
    selected = [r for r in results if not r['review_reasons']][:6]
    lines = ['=== 本机线路 TLS 初筛优选（不是 GFW / REALITY 成功保证）===']
    for i, r in enumerate(selected):
        lines.append(('%s: %s | median=%s ms | p95=%s ms' %
                     ('首选' if i == 0 else '备用%d' % i, r['domain'], r['median_ms'], r['p95_ms'])))
    if selected:
        host = selected[0]['domain']
        lines += ['配置参考（需另行验证 Xray 与大陆客户端）:',
                  json.dumps({'target': '%s:%d' % (host, port), 'serverNames': [host]}, ensure_ascii=False)]
    else:
        lines.append('没有满足优选条件的候选；请查看复核原因，不自动放宽条件。')
    lines += ['ALPN h2 仅证明协商成功，未发送 HTTP/2 请求。',
              'X25519 已单独调用 OpenSSL 检查；X25519MLKEM768 请使用 --xray /真实/core/路径 获取 tls ping 原始诊断。',
              '大陆 SNI 阻断、实际 REALITY 握手及长连接稳定性：未检测，须在大陆客户端验证。',
              '=== 需要复核 ===']
    lines += [r['domain'] + ': ' + '; '.join(r['review_reasons']) for r in results if r['review_reasons']]
    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('-f', '--file', default=None)
    p.add_argument('--region', default='unspecified')
    p.add_argument('--family', choices=['4', '6', 'auto'], default='4')
    p.add_argument('--timeout', type=float, default=5)
    p.add_argument('--rounds', type=int, default=5)
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--out', default='results')
    p.add_argument('--xray', help='Explicit path to Xray core, NOT the 233boy management script')
    p.add_argument('--cafile', help='Optional trusted CA bundle, mainly for controlled tests')
    p.add_argument('--port', type=int, default=443)
    p.add_argument('--worker', help=argparse.SUPPRESS)
    p.add_argument('--mode', choices=['tls', 'http'], default='tls', help=argparse.SUPPRESS)
    args = p.parse_args()
    if not ssl.HAS_TLSv1_3 or not ssl.HAS_ALPN:
        p.error('This Python/OpenSSL lacks TLS 1.3 or ALPN; use a modern Python 3 on your VPS.')
    if args.timeout <= 0 or args.rounds < 1 or not 1 <= args.workers <= 16 or not 1 <= args.port <= 65535:
        p.error('Invalid timeout, rounds, workers (1..16), or port')
    if args.worker:
        print(json.dumps(probe(args.worker, args.family, args.timeout, args.mode, args.port, args.cafile)))
        return
    try:
        hosts = load_domains(args.file)
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    if args.xray and not (Path(args.xray).is_file() and os.access(args.xray, os.X_OK)):
        p.error('--xray must be an existing executable core path')
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    label = re.sub(r'[^A-Za-z0-9_-]', '_', args.region)
    base = out / (label + '-ipv' + args.family + '-' + stamp)
    metadata = dict(region=args.region, family=args.family, python=sys.version.split()[0],
                    openssl=ssl.OPENSSL_VERSION, started_utc=stamp,
                    timeout=args.timeout, rounds=args.rounds, workers=args.workers,
                    note='Direct socket TLS preflight only. No GFW verdict or REALITY guarantee. Timing includes DNS and setup. Transparent VPN/TUN may still affect routes.')
    results = []
    print('Testing %d domains, region=%s, family=%s' % (len(hosts), args.region, args.family), flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(evaluate, host, args) for host in hosts]
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            results.append(r)
            print('%-42s %-24s TLS %d/%d H2 %d/%d median=%s ms' %
                  (r['domain'], r['status'], r['success'], args.rounds, r['h2_success'], args.rounds, r['median_ms']), flush=True)
    report = recommendations(results, args.port)
    base.with_suffix('.txt').write_text(report + '\n', encoding='utf-8')
    print(report)
    base.with_suffix('.json').write_text(json.dumps(dict(metadata=metadata, results=results), ensure_ascii=False, indent=2), encoding='utf-8')
    fields = ['domain', 'status', 'success', 'rounds', 'h2_success', 'median_ms', 'p95_ms', 'peers', 'http_status', 'location', 'errors', 'review_reasons']
    with base.with_suffix('.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            row = {k: r.get(k, '') for k in fields}
            row['review_reasons'] = ';'.join(r['review_reasons'])
            row['peers'] = ';'.join(r['peers'])
            row['http_status'] = r['http'].get('http_status', '')
            row['location'] = r['http'].get('location', '')
            row['errors'] = ';'.join(sorted({s.get('error', '') for s in r['samples'] if not s.get('ok')}))
            writer.writerow(row)
    print('Saved:', base.with_suffix('.json'), base.with_suffix('.csv'))

if __name__ == '__main__':
    main()
