"""Disposable hosting probe: synthetic marker, package imports, password-free TLS."""
import hashlib
import importlib
from importlib.metadata import version
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import struct
import subprocess
from uuid import UUID, uuid4

PACKAGES = {
    'fastapi': 'fastapi', 'uvicorn': 'uvicorn', 'psycopg': 'psycopg',
    'psycopg-pool': 'psycopg_pool', 'argon2-cffi': 'argon2',
    'httpx': 'httpx', 'cryptography': 'cryptography', 'pyotp': 'pyotp',
    'qrcode': 'qrcode', 'boto3': 'boto3', 'paramiko': 'paramiko',
}

def imports():
    result = {}
    for package, module in PACKAGES.items():
        try:
            importlib.import_module(module)
            result[package] = {'state': 'ok', 'version': version(package)}
        except Exception:
            result[package] = {'state': 'failed'}
    return result

def marker_report(root):
    try:
        folder = Path(root)
        if folder.is_symlink():
            raise ValueError()
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        marker = folder / 'marker.txt'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        try:
            fd = os.open(marker, flags, 0o600)
        except FileExistsError:
            state = 'reused'
        else:
            with os.fdopen(fd, 'w', encoding='ascii') as stream:
                stream.write(str(uuid4()))
            state = 'created'
        if marker.is_symlink() or not marker.is_file():
            raise ValueError()
        with os.fdopen(os.open(marker, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
            raw = stream.read(128)
        if str(UUID(raw.decode('ascii'))) != raw.decode('ascii'):
            raise ValueError()
        return {'state': state, 'sha256': hashlib.sha256(raw).hexdigest()}
    except Exception:
        return {'state': 'failed'}

def tls_report(host, *, port=5432, server_name=None, cafile=None):
    if not host:
        return {'state': 'not-configured'}
    try:
        context = ssl.create_default_context(cafile=cafile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=8) as connection:
            connection.sendall(struct.pack('!II', 8, 80877103))
            response = connection.recv(1)
            if response == b'N':
                return {'state': 'ssl-not-supported'}
            if response != b'S':
                return {'state': 'unexpected-ssl-response'}
            with context.wrap_socket(connection, server_hostname=server_name or host) as secured:
                return {'state': 'verified', 'version': secured.version(),
                        'certificate_sha256': hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()}
    except ssl.SSLCertVerificationError:
        return {'state': 'certificate-validation-failed'}
    except ssl.SSLError:
        return {'state': 'tls-handshake-failed'}
    except (OSError, ValueError):
        return {'state': 'connect-or-trust-store-failed'}

def make_server(report, *, host, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Liveness is separate from compatibility. Failed checks must remain inspectable.
            data, status = (report, 200) if self.path in ('/', '/health') else ({'error': 'not-found'}, 404)
            body = json.dumps(data, ensure_ascii=True).encode('ascii')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_):
            pass
    return HTTPServer((host, port), Handler)

def main():
    dependencies = imports()
    try:
        node = subprocess.run(['node', '--version'], check=True, capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        node = 'failed'
    tls = tls_report(os.environ.get('EPIZ_PROBE_DB_HOST'),
                     server_name=os.environ.get('EPIZ_PROBE_DB_SERVER_NAME'),
                     cafile=os.environ.get('EPIZ_PROBE_DB_CA_FILE'))
    report = {'scope': 'disposable-hostim-probe', 'python': platform.python_version(),
              'platform': platform.system(), 'node': node, 'dependencies': dependencies,
              'local_marker': marker_report('/tmp/epiz-hostim-probe'), 'database_tls': tls,
              'authentication': 'not-tested', 'migrations': 'not-tested', 'backup_restore': 'not-tested',
              'runtime_ok': all(item['state'] == 'ok' for item in dependencies.values()) and node != 'failed',
              'database_ready': tls['state'] == 'verified'}
    print(json.dumps(report), flush=True)
    make_server(report, host='0.0.0.0', port=int(os.environ.get('PORT', '8080'))).serve_forever()

if __name__ == '__main__':
    main()
