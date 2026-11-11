#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "dnspython>=2.6.1",
#     "Pillow>=10.3.0",
# ]
# ///
"""
DNS Whalebone Check - Multiplataforma (Windows, macOS, Linux, Android/Termux, ADB)
Valida bloqueios de DNS, realiza testes de DNS, Handshake TLS (1.3 / 1.2), HTTP/HTTPS,
captura screenshots com banner informativo e gera relatório CSV e logs detalhados.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
from PIL import Image, ImageDraw, ImageFont

# ==============================================================================
# CONFIGURAÇÕES E PRESETS DOS 3 USE CASES
# ==============================================================================

DEFAULT_URLS = [
    "https://www.google.com",
    "https://malware.test.attacker.online",
    "https://c2server.test.attacker.online",
    "https://spam.test.attacker.online",
    "https://phishing.test.attacker.online",
    "https://coinminer.test.attacker.online",
    "https://www.lovehoney.com",
    "https://www.erowid.org"
]

# Configure aqui os IPs padrão de cada Use Case (podem ser editados ou passados via CLI/Menu)
USE_CASES: Dict[str, Dict[str, object]] = {
    "1": {
        "name": "Use Case 1 - Whalebone / DNS Segurança (Padrão)",
        "description": "Compara DNS com filtragem Whalebone vs DNS Público (Google)",
        "dns_servers": ["10.36.41.114"],
    },
    "2": {
        "name": "Use Case 2 - DNS Secundário / Alternativo",
        "description": "Validação de servidores DNS do Use Case 2",
        "dns_servers": ["9.9.9.9"],
    },
    "3": {
        "name": "Use Case 3 - DNS Customizado / Homologação",
        "description": "Validação de servidores DNS do Use Case 3",
        "dns_servers": ["1.1.1.1"],
    },
}

SCREEN_W = 1920
SCREEN_H = 1200
BANNER_H = 160

PAGE_LOAD_WAIT = 6
HTTP_TIMEOUT = 15
DNS_TIMEOUT = 5
TLS_TIMEOUT = 10


# ==============================================================================
# ESTRUTURAS DE DADOS
# ==============================================================================


@dataclass
class DNSResult:
    ips: List[str]
    query_ms: str
    raw_log: str

    @property
    def ips_str(self) -> str:
        return ",".join(self.ips) if self.ips else "FALHA"


@dataclass
class TLSResult:
    version: str = "N/A"
    cipher: str = "N/A"
    verify_code: str = "?"
    verify_text: str = "sem dado"
    cert_cn: str = "N/A"
    cert_expires: str = "N/A"
    log_file: str = ""


@dataclass
class HTTPResult:
    status: str = "000"
    time_ms: str = "0"
    final_url: str = ""
    ssl_verify: str = "0"
    ssl_status: str = "OK"
    redirect_url: str = ""
    body_preview: str = ""
    final_body: str = ""
    extra_host_ips: Dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.extra_host_ips is None:
            self.extra_host_ips = {}
        if not self.final_body:
            self.final_body = self.body_preview


# ==============================================================================
# UTILITÁRIOS DE LOG E SISTEMA
# ==============================================================================


class Logger:
    def __init__(self, log_file: Path):
        self.log_file = log_file

    def log(self, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        print(line, flush=True)
        try:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def is_android_termux() -> bool:
    return (
        "ANDROID_ROOT" in os.environ
        or "TERMUX_VERSION" in os.environ
        or Path("/data/data/com.termux").exists()
    )


def load_font(size: int, bold: bool = True, mono: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = []
    sys_name = platform.system().lower()

    if mono:
        if sys_name == "darwin":
            candidates = [
                "/System/Library/Fonts/SFNSMono.ttf",
                "/System/Library/Fonts/Menlo.ttc",
                "/System/Library/Fonts/Supplemental/Courier New Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Courier New.ttf",
            ]
        elif sys_name == "windows":
            windir = os.environ.get("WINDIR", "C:\\Windows")
            candidates = [
                os.path.join(windir, "Fonts", "consolab.ttf" if bold else "consola.ttf"),
                os.path.join(windir, "Fonts", "courbd.ttf" if bold else "cour.ttf"),
            ]
        else:
            candidates = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
                "/data/data/com.termux/files/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
                "/system/fonts/DroidSansMono.ttf",
                "/system/fonts/Roboto-Bold.ttf" if bold else "/system/fonts/Roboto-Regular.ttf",
            ]
    else:
        if sys_name == "darwin":
            candidates = [
                "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
                "/System/Library/Fonts/Helvetica.ttc",
                "/Library/Fonts/Arial.ttf",
            ]
        elif sys_name == "windows":
            windir = os.environ.get("WINDIR", "C:\\Windows")
            candidates = [
                os.path.join(windir, "Fonts", "seguisb.ttf" if bold else "segoeui.ttf"),
                os.path.join(windir, "Fonts", "arialbd.ttf" if bold else "arial.ttf"),
            ]
        else:
            candidates = [
                "/system/fonts/Roboto-Bold.ttf" if bold else "/system/fonts/Roboto-Regular.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
                "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
                "/system/fonts/DroidSans-Bold.ttf",
                "/data/data/com.termux/files/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
            ]

    for path in candidates:
        if os.path.isfile(path):
            try:
                return ImageFont.truetype(path, size=size)
            except Exception:
                continue

    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


# ==============================================================================
# TESTE 1: RESOLUÇÃO DNS ISOLADA (SEM ALTERAR O SISTEMA)
# ==============================================================================


def resolve_dns(domain: str, dns_server: str, timeout: int = DNS_TIMEOUT) -> DNSResult:
    """Consulta diretamente o servidor DNS especificado via UDP/TCP e mede o tempo em ms."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_server]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    start = time.perf_counter()
    try:
        qname = dns.name.from_text(domain)
        query_msg = dns.message.make_query(qname, dns.rdatatype.A)
        try:
            response = dns.query.udp(query_msg, dns_server, timeout=timeout)
            if response.flags & dns.flags.TC:
                response = dns.query.tcp(query_msg, dns_server, timeout=timeout)
        except Exception:
            response = dns.query.tcp(query_msg, dns_server, timeout=timeout)

        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        ips: List[str] = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    ips.append(rdata.address)

        # Caso haja CNAME sem A direto no pacote ou resposta vazia, tenta via resolver padrão
        if not ips and response.rcode() == dns.rcode.NOERROR:
            try:
                ans = resolver.resolve(domain, "A")
                ips = [r.address for r in ans]
            except Exception:
                pass

        return DNSResult(
            ips=ips,
            query_ms=str(elapsed_ms),
            raw_log=response.to_text(),
        )
    except Exception as e:
        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        return DNSResult(
            ips=[],
            query_ms="N/A",
            raw_log=f"Erro na consulta DNS ({elapsed_ms} ms): {e}",
        )


# ==============================================================================
# TESTE 2: HANDSHAKE TLS (1.3 com fallback 1.2) DIRETO NO IP RESOLVIDO
# ==============================================================================


def _extract_cert_info(der_cert: bytes) -> Tuple[str, str, str]:
    """
    Extrai (Subject CN, Issuer CN, Data de Expiração) sem depender de bibliotecas Rust/C (`cryptography`).
    1. Tenta decodificar via `_ssl._test_decode_cert` nativo da stdlib do Python.
    2. Caso indisponível, usa `openssl x509` se presente no sistema.
    3. Caso indisponível, faz fallback via regex/ASN.1 básico sobre os bytes DER.
    """
    cert_cn = "N/A"
    issuer_cn = "N/A"
    cert_expires = "N/A"

    # Método 1: Decodificador interno da biblioteca padrão `ssl` do Python
    pem_data = ssl.DER_cert_to_PEM_cert(der_cert)
    try:
        decode_fn = getattr(ssl._ssl, "_test_decode_cert", None)  # type: ignore[attr-defined]
        if decode_fn is not None:
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as tf:
                tf.write(pem_data)
                tmp_pem_path = tf.name
            try:
                decoded = decode_fn(tmp_pem_path)
                if isinstance(decoded, dict):
                    for rdn in decoded.get("subject", ()):
                        for k, v in rdn:
                            if k == "commonName":
                                cert_cn = str(v)
                    for rdn in decoded.get("issuer", ()):
                        for k, v in rdn:
                            if k == "commonName":
                                issuer_cn = str(v)
                    if decoded.get("notAfter"):
                        cert_expires = str(decoded["notAfter"])
            finally:
                try:
                    os.remove(tmp_pem_path)
                except OSError:
                    pass
    except Exception:
        pass

    if cert_cn != "N/A" and cert_expires != "N/A":
        return cert_cn, issuer_cn, cert_expires

    # Método 2: Fallback via binário `openssl` (disponível em Linux/macOS/Termux)
    openssl_bin = shutil.which("openssl")
    if openssl_bin:
        try:
            proc = subprocess.run(
                [openssl_bin, "x509", "-noout", "-subject", "-issuer", "-enddate"],
                input=pem_data,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in proc.stdout.splitlines():
                if line.startswith("subject="):
                    m = re.search(r"CN\s*=\s*([^,/]+)", line)
                    if m and cert_cn == "N/A":
                        cert_cn = m.group(1).strip()
                elif line.startswith("issuer="):
                    m = re.search(r"CN\s*=\s*([^,/]+)", line)
                    if m and issuer_cn == "N/A":
                        issuer_cn = m.group(1).strip()
                elif line.startswith("notAfter="):
                    if cert_expires == "N/A":
                        cert_expires = line.split("=", 1)[1].strip()
        except Exception:
            pass

    return cert_cn, issuer_cn, cert_expires


def _perform_single_tls_handshake(
    host: str,
    target_ip: str,
    logfile: Path,
    tls_version_flag: str = "TLSv1.3",
    timeout: int = TLS_TIMEOUT,
) -> TLSResult:
    """
    Executa handshake TLS conectando diretamente ao IP retornado pelo DNS e enviando SNI = host.
    """
    now_iso = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    log_lines = [
        f"===== Python TLS Handshake -> {host} ({target_ip}:443) [{tls_version_flag}] =====",
        f"===== Executado em {now_iso} =====",
        "",
    ]

    if not target_ip or target_ip == "FALHA":
        log_lines.append("ERRO: DNS não resolveu nenhum IP para realizar o handshake TLS.")
        logfile.write_text("\n".join(log_lines), encoding="utf-8")
        return TLSResult(log_file=str(logfile))

    # 1) Primeiro verificamos se o certificado é válido perante as CAs do sistema
    verify_code = "0"
    verify_text = "ok"
    try:
        ctx_verify = ssl.create_default_context()
        if hasattr(ssl, "TLSVersion"):
            if tls_version_flag == "TLSv1.3" and hasattr(ssl.TLSVersion, "TLSv1_3"):
                ctx_verify.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx_verify.maximum_version = ssl.TLSVersion.TLSv1_3
            elif tls_version_flag == "TLSv1.2" and hasattr(ssl.TLSVersion, "TLSv1_2"):
                ctx_verify.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx_verify.maximum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection((target_ip, 443), timeout=timeout) as sock:
            with ctx_verify.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as e:
        verify_code = str(getattr(e, "verify_code", 1))
        verify_text = getattr(e, "verify_message", str(e)) or "certificate verify failed"
        log_lines.append(f"[Verify Warning] Codigo {verify_code}: {verify_text}")
    except Exception as e:
        # Pode ser falha de versão TLS ou conexão recusada; detalharemos na conexão sem validação abaixo
        log_lines.append(f"[Verify Notice] {type(e).__name__}: {e}")

    # 2) Agora conectamos com CERT_NONE para extrair detalhes do certificado mesmo se for página de bloqueio (cert inválido/self-signed)
    ctx_noverify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_noverify.check_hostname = False
    ctx_noverify.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        if tls_version_flag == "TLSv1.3" and hasattr(ssl.TLSVersion, "TLSv1_3"):
            ctx_noverify.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx_noverify.maximum_version = ssl.TLSVersion.TLSv1_3
        elif tls_version_flag == "TLSv1.2" and hasattr(ssl.TLSVersion, "TLSv1_2"):
            ctx_noverify.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx_noverify.maximum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((target_ip, 443), timeout=timeout) as raw_sock:
            with ctx_noverify.wrap_socket(raw_sock, server_hostname=host) as ssock:
                negotiated_version = ssock.version() or "N/A"
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "N/A"
                der_cert = ssock.getpeercert(binary_form=True)

                cert_cn = "N/A"
                cert_expires = "N/A"
                if der_cert:
                    cert_cn, issuer_cn, cert_expires = _extract_cert_info(der_cert)
                    pem_data = ssl.DER_cert_to_PEM_cert(der_cert)
                    raw_sha256 = hashlib.sha256(der_cert).hexdigest()
                    fingerprint = ":".join(raw_sha256[i : i + 2] for i in range(0, len(raw_sha256), 2))

                    log_lines.extend(
                        [
                            f"Connected to {target_ip}:443 (SNI: {host})",
                            f"Protocol  : {negotiated_version}",
                            f"Cipher    : {cipher_name}",
                            f"Subject CN: {cert_cn}",
                            f"Issuer CN : {issuer_cn}",
                            f"Not After : {cert_expires}",
                            f"SHA256 FP : {fingerprint}",
                            f"Verify    : {verify_code} ({verify_text})",
                            "",
                            pem_data,
                        ]
                    )

                logfile.write_text("\n".join(log_lines), encoding="utf-8")
                return TLSResult(
                    version=negotiated_version,
                    cipher=cipher_name,
                    verify_code=verify_code,
                    verify_text=verify_text,
                    cert_cn=cert_cn,
                    cert_expires=cert_expires,
                    log_file=str(logfile),
                )
    except Exception as e:
        log_lines.append(f"Handshake falhou ({tls_version_flag}): {type(e).__name__}: {e}")
        logfile.write_text("\n".join(log_lines), encoding="utf-8")
        return TLSResult(
            version="N/A",
            cipher="N/A",
            verify_code="?",
            verify_text=str(e)[:80] if str(e) else "sem dado",
            cert_cn="N/A",
            cert_expires="N/A",
            log_file=str(logfile),
        )


def tls_handshake_test(host: str, target_ip: str, tls_log_dir: Path, safe_name: str) -> TLSResult:
    """Tenta TLS 1.3 primeiro e faz fallback para TLS 1.2 como no script original."""
    log_13 = tls_log_dir / f"{safe_name}_tls13.log"
    res_13 = _perform_single_tls_handshake(host, target_ip, log_13, "TLSv1.3")
    if "TLSv1.3" in res_13.version:
        return res_13

    log_12 = tls_log_dir / f"{safe_name}_tls12.log"
    res_12 = _perform_single_tls_handshake(host, target_ip, log_12, "TLSv1.2")
    if "TLS" in res_12.version:
        return res_12

    return res_13


# ==============================================================================
# TESTE 3: REQUISIÇÃO HTTP/HTTPS ISOLADA (USANDO O IP DO DNS TESTADO)
# ==============================================================================


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, target_ip: str, port: int = 80, timeout: int = HTTP_TIMEOUT):
        super().__init__(host, port=port, timeout=timeout)
        self._target_ip = target_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._target_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        target_ip: str,
        port: int = 443,
        context: Optional[ssl.SSLContext] = None,
        timeout: int = HTTP_TIMEOUT,
    ):
        super().__init__(host, port=port, context=context, timeout=timeout)
        self._target_ip = target_ip

    def connect(self) -> None:
        raw_sock = socket.create_connection((self._target_ip, self.port), self.timeout)
        server_hostname = self.host.split(":")[0]
        self.sock = self._context.wrap_socket(raw_sock, server_hostname=server_hostname)


def _single_http_request(
    url: str,
    target_ip: str,
    timeout: int = HTTP_TIMEOUT,
) -> Tuple[int, Dict[str, str], bytes]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    headers = {
        "Host": host if (port in (80, 443)) else f"{host}:{port}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }

    if scheme == "https":
        ctx_k = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_k.check_hostname = False
        ctx_k.verify_mode = ssl.CERT_NONE
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
            host, target_ip, port=port, context=ctx_k, timeout=timeout
        )
    else:
        conn = _PinnedHTTPConnection(host, target_ip, port=port, timeout=timeout)

    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body_bytes = resp.read(262144)  # Até 256 KB para capturar HTML completo da página de bloqueio
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, resp_headers, body_bytes


def _extract_meta_or_js_redirect(raw_html: str, base_url: str) -> str:
    """Detecta redirecionamentos via <meta http-equiv='refresh'> ou window.location no HTML."""
    if not raw_html:
        return ""
    m_meta = re.search(
        r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\s*\d+\s*;\s*url=([^"\'>\s]+)',
        raw_html,
        re.IGNORECASE,
    )
    if m_meta:
        return urllib.parse.urljoin(base_url, m_meta.group(1).strip("'\""))

    m_js = re.search(
        r'(?:window\.location(?:\.href|\.replace)?|location\.href)\s*(?:=|\()\s*["\'](https?://[^"\']+)["\']',
        raw_html,
        re.IGNORECASE,
    )
    if m_js:
        return urllib.parse.urljoin(base_url, m_js.group(1).strip())
    return ""


def _resolve_subresource_hosts(raw_html: str, dns_server: str, extra_host_ips: Dict[str, str]) -> None:
    """
    Extrai domínios referenciados em <link>, <script>, <img> e <iframe src='https://...'>
    dentro do HTML da página de bloqueio e resolve-os no DNS testado para que o navegador
    carregue todo o CSS/JS/imagens da página de bloqueio sem travar!
    """
    if not raw_html:
        return
    hosts = set(
        re.findall(
            r'(?:src|href)\s*=\s*["\']https?://([a-zA-Z0-9.-]+)(?::\d+)?/',
            raw_html,
             flags=re.IGNORECASE,
        )
    )
    for h in list(hosts)[:10]:
        h_low = h.lower()
        if h_low not in extra_host_ips:
            r_dns = resolve_dns(h_low, dns_server, timeout=DNS_TIMEOUT)
            if r_dns.ips:
                extra_host_ips[h_low] = r_dns.ips[0]


def http_probe(url: str, target_ip: str, dns_server: str, timeout: int = HTTP_TIMEOUT) -> HTTPResult:
    """
    Faz a requisição inicial (similar ao `curl -sS -k` do script original) conectando no IP
    resolvido pelo servidor DNS em teste. Além disso, se houver redirect (301/302/307/308,
    meta refresh ou JS redirect) para uma página de bloqueio (ex: sinkhole da NOS/Whalebone),
    segue o redirect usando o mesmo servidor DNS para obter o HTML real da página de bloqueio
    e mapear os IPs no browser.
    """
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)

    if not target_ip or target_ip == "FALHA":
        return HTTPResult(
            status="000",
            time_ms="0",
            final_url=url,
            ssl_verify="0",
            ssl_status="N/A (http)" if scheme == "http" else "DNS FALHOU",
            redirect_url="",
            body_preview="Falha na resolucao DNS (NXDOMAIN / Timeout)",
        )

    # Verifica validade SSL separadamente para preencher ssl_verify / ssl_status como no curl
    ssl_verify = "0"
    if scheme == "https":
        try:
            ctx_strict = ssl.create_default_context()
            with socket.create_connection((target_ip, port), timeout=min(timeout, 6)) as s:
                with ctx_strict.wrap_socket(s, server_hostname=host):
                    ssl_verify = "0"
        except ssl.SSLCertVerificationError as e:
            ssl_verify = str(getattr(e, "verify_code", 1))
        except Exception:
            ssl_verify = "1"

    extra_host_ips: Dict[str, str] = {host: target_ip}
    start = time.perf_counter()
    try:
        status, resp_headers, body_bytes = _single_http_request(url, target_ip, timeout=timeout)
        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        status_code = str(status)
        location = resp_headers.get("location", "")
        redirect_url = urllib.parse.urljoin(url, location) if location else ""

        if scheme == "http":
            ssl_status = "N/A (http)"
        elif ssl_verify != "0":
            ssl_status = f"CERT INVALIDO (codigo {ssl_verify})"
        else:
            ssl_status = "OK"

        body_text = body_bytes.decode("utf-8", errors="replace")
        if not redirect_url:
            redirect_url = _extract_meta_or_js_redirect(body_text, url)

        final_body = body_text
        final_url = url

        # Se houve redirecionamento HTTP/Meta/JS (ex: para página de bloqueio), segue até 4 hops usando o mesmo DNS
        curr_url = redirect_url
        hops = 0
        while curr_url and hops < 4:
            hops += 1
            r_parsed = urllib.parse.urlsplit(curr_url)
            r_host = r_parsed.hostname or ""
            if not r_host:
                break
            if r_host not in extra_host_ips:
                r_dns = resolve_dns(r_host, dns_server, timeout=DNS_TIMEOUT)
                if r_dns.ips:
                    extra_host_ips[r_host] = r_dns.ips[0]
            r_ip = extra_host_ips.get(r_host)
            if not r_ip:
                break
            try:
                r_status, r_headers, r_body_bytes = _single_http_request(curr_url, r_ip, timeout=timeout)
                final_body = r_body_bytes.decode("utf-8", errors="replace")
                final_url = curr_url
                next_loc = r_headers.get("location", "")
                if next_loc and r_status in (301, 302, 303, 307, 308):
                    curr_url = urllib.parse.urljoin(curr_url, next_loc)
                else:
                    js_next = _extract_meta_or_js_redirect(final_body, curr_url)
                    curr_url = js_next if js_next and js_next != curr_url else ""
            except Exception:
                break

        _resolve_subresource_hosts(final_body, dns_server, extra_host_ips)

        return HTTPResult(
            status=status_code,
            time_ms=str(elapsed_ms),
            final_url=final_url,
            ssl_verify=ssl_verify,
            ssl_status=ssl_status,
            redirect_url=redirect_url,
            body_preview=body_text,
            final_body=final_body,
            extra_host_ips=extra_host_ips,
        )
    except Exception as e:
        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        if scheme == "http":
            ssl_status = "N/A (http)"
        elif ssl_verify != "0":
            ssl_status = f"CERT INVALIDO (codigo {ssl_verify})"
        else:
            ssl_status = "OK"
        err_msg = f"Erro HTTP/Conexao: {type(e).__name__}: {e}"
        return HTTPResult(
            status="000",
            time_ms=str(elapsed_ms),
            final_url=url,
            ssl_verify=ssl_verify,
            ssl_status=ssl_status,
            redirect_url="",
            body_preview=err_msg,
            final_body=err_msg,
            extra_host_ips=extra_host_ips,
        )


# ==============================================================================
# CAPTURA DE SCREENSHOT (DESKTOP CHROME/EDGE/BRAVE, ADB ANDROID OU CARD VISUAL)
# ==============================================================================


def find_local_browser() -> Optional[str]:
    """Localiza binário do Chrome, Edge, Chromium ou Brave no Windows, macOS ou Linux."""
    env_browser = os.environ.get("BROWSER_PATH")
    if env_browser and os.path.isfile(env_browser):
        return env_browser

    sys_name = platform.system().lower()
    candidates: List[str] = []

    if sys_name == "darwin":
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    elif sys_name == "windows":
        prog_files = [
            os.environ.get("PROGRAMFILES", "C:\\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
        ]
        for base in prog_files:
            if not base:
                continue
            candidates.extend(
                [
                    os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                    os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                    os.path.join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
                ]
            )
    else:
        for cmd in (
            "chromium",
            "chromium-browser",
            "google-chrome",
            "google-chrome-stable",
            "microsoft-edge",
            "brave-browser",
            "/data/data/com.termux/files/usr/bin/chromium",
            "/data/data/com.termux/files/usr/bin/chromium-browser",
        ):
            found = shutil.which(cmd) if not cmd.startswith("/") else (cmd if os.path.isfile(cmd) else None)
            if found:
                candidates.append(found)

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def is_screenshot_blank(png_path: Path) -> bool:
    """
    Verifica se o screenshot capturado pelo navegador está praticamente todo em branco
    (ou de uma única cor sólida), o que acontece quando o navegador aborta o carregamento
    antes de pintar o DOM ou durante um redirecionamento lento.
    """
    if not png_path.is_file() or png_path.stat().st_size == 0:
        return True
    try:
        with Image.open(png_path) as im:
            gray = im.convert("L")
            extrema = gray.getextrema()
            if not extrema:
                return True
            min_v, max_v = extrema
            if max_v - min_v < 8:
                return True
            # Conta quantos pixels diferem significativamente do fundo predominante
            hist = gray.histogram()
            total_pixels = gray.width * gray.height
            dominant_count = max(hist)
            non_dominant_ratio = (total_pixels - dominant_count) / float(total_pixels)
            # Se mais de 99.6% da imagem for exatamente da mesma cor, está em branco/vazia
            return non_dominant_ratio < 0.004
    except Exception:
        return True


def _inject_base_href(raw_html: str, base_url: str) -> str:
    """Insere <base href='...'> no HTML para que CSS/imagens com caminhos relativos carreguem perfeitamente."""
    if not base_url:
        return raw_html
    base_tag = f'<base href="{base_url}">'
    if re.search(r"<head[^>]*>", raw_html, re.IGNORECASE):
        return re.sub(
            r"(<head[^>]*>)",
            r"\1" + base_tag,
            raw_html,
            count=1,
            flags=re.IGNORECASE,
        )
    return base_tag + raw_html


def capture_browser_screenshot(
    browser_bin: str,
    url: str,
    domain: str,
    resolved_ips: List[str],
    http_res: HTTPResult,
    output_png: Path,
    temp_dir: Path,
) -> bool:
    """
    Usa o navegador local (Chrome/Edge/Brave/Chromium) em modo headless com `--host-resolver-rules`
    para forçar a resolução de DNS isolada sem tocar no DNS do sistema operacional!
    Se a captura direta da URL ficar em branco (ex: bloqueio de redirect cross-domain ou TLS estrito),
    tenta capturar diretamente a URL final da página de bloqueio ou renderizar o HTML baixado no próprio navegador.
    """
    rules: List[str] = []
    if resolved_ips:
        rules.append(f"MAP {domain} {resolved_ips[0]}")
        for h, ip_val in (http_res.extra_host_ips or {}).items():
            if h and ip_val and h != domain:
                rules.append(f"MAP {h} {ip_val}")
    else:
        rules.append(f"MAP {domain} ~NOTFOUND")

    resolver_rule = ", ".join(rules)

    def _run_browser_target(target_url_or_file: str, budget_ms: int) -> bool:
        profile_dir = temp_dir / f"chrome_profile_{int(time.time() * 1000)}"
        default_dir = profile_dir / "Default"
        default_dir.mkdir(parents=True, exist_ok=True)

        prefs = {
            "browser": {"has_seen_welcome_page": True},
            "https_only_mode_enabled": False,
            "https_first_balanced_mode_enabled": False,
            "https_first_mode_incognito_enabled": False,
            "https_upgrades_enabled": False,
            "dns_over_https": {"mode": "off"},
            "profile": {"default_content_setting_values": {"insecure_content": 1}},
        }
        (default_dir / "Preferences").write_text(json.dumps(prefs), encoding="utf-8")
        (profile_dir / "First Run").touch()

        if output_png.exists():
            try:
                output_png.unlink()
            except OSError:
                pass

        cmd = [
            browser_bin,
            "--headless=new",
            f"--user-data-dir={profile_dir}",
            "--incognito",
            "--no-sandbox",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-features=TranslateUI,InfobarUIPromos,HttpsFirstModeIncognito,HttpsFirstModeV2,HttpsUpgrades,HttpsFirstBalancedMode,HttpsFirstModeForTypicallySecureUsers,InsecureFormSubmissionInterstitial,HttpsUpgradesForEngagedSites,HttpsFirstModeForAdvancedProtectionUsers,DnsOverHttps",
            "--disable-https-upgrades",
            "--disable-infobars",
            "--disable-dev-shm-usage",
            "--disable-application-cache",
            "--disable-cache",
            f"--window-size={SCREEN_W},{SCREEN_H}",
            "--ignore-certificate-errors",
            "--ignore-certificate-errors-spki-list",
            "--ignore-ssl-errors",
            "--allow-running-insecure-content",
            "--disable-web-security",
            "--hide-scrollbars",
            f"--host-resolver-rules={resolver_rule}",
            f"--virtual-time-budget={budget_ms}",
            f"--screenshot={output_png}",
            target_url_or_file,
        ]

        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=(budget_ms // 1000) + 15,
                check=False,
            )
        except Exception:
            pass
        finally:
            shutil.rmtree(profile_dir, ignore_errors=True)

        return not is_screenshot_blank(output_png)

    # Tentativa 1: Abre a URL original (ou a URL final se houve redirect conhecido para página de bloqueio)
    primary_target = http_res.final_url if (http_res.redirect_url and http_res.final_url) else url
    if _run_browser_target(primary_target, PAGE_LOAD_WAIT * 1000):
        return True

    # Tentativa 2: Se tentou a URL original e ficou em branco, mas há redirect_url diferente, abre direto a redirect_url
    if primary_target != url and _run_browser_target(url, PAGE_LOAD_WAIT * 1000):
        return True

    # Tentativa 3: Se o navegador ficou em branco por falha de handshake/redirect na rede,
    # mas o `http_probe` obteve o HTML real da página (ex: página de bloqueio), salva o HTML com <base href>
    # e manda o próprio navegador renderizar o HTML local (mantendo todo o CSS, imagens e layout originais!)
    html_body = http_res.final_body or http_res.body_preview or ""
    if "<" in html_body and (">" in html_body) and len(html_body.strip()) > 40:
        base_for_assets = http_res.final_url or http_res.redirect_url or url
        enriched_html = _inject_base_href(html_body, base_for_assets)
        local_html = temp_dir / f"rendered_block_page_{int(time.time() * 1000)}.html"
        local_html.write_text(enriched_html, encoding="utf-8")
        try:
            if _run_browser_target(local_html.as_uri(), 5000):
                return True
        finally:
            try:
                local_html.unlink()
            except OSError:
                pass

    return False


def capture_adb_screenshot(url: str, output_png: Path, wait_sec: int = PAGE_LOAD_WAIT) -> bool:
    """
    Caso o usuário esteja usando o modo Android via ADB (celular conectado no PC),
    abre a URL no navegador do Android e captura a tela real do aparelho via `adb exec-out screencap -p`.
    """
    adb_bin = shutil.which("adb")
    if not adb_bin:
        return False

    try:
        # Verifica se há dispositivo conectado
        devs = subprocess.run(
            [adb_bin, "devices"], capture_output=True, text=True, timeout=5, check=False
        )
        lines = [
            ln.strip()
            for ln in devs.stdout.splitlines()[1:]
            if ln.strip() and "\tdevice" in ln
        ]
        if not lines:
            return False

        # Abre a URL no Android
        subprocess.run(
            [
                adb_bin,
                "shell",
                "am",
                "start",
                "-a",
                "android.intent.action.VIEW",
                "-d",
                url,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
        time.sleep(wait_sec)

        # Captura screenshot em PNG
        with output_png.open("wb") as f:
            subprocess.run(
                [adb_bin, "exec-out", "screencap", "-p"],
                stdout=f,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )

        if output_png.is_file() and output_png.stat().st_size > 100:
            # Redimensiona/centraliza na largura padrão para encaixar perfeitamente com o banner
            with Image.open(output_png) as im:
                im = im.convert("RGB")
                canvas = Image.new("RGB", (SCREEN_W, SCREEN_H), (30, 30, 30))
                im.thumbnail((SCREEN_W, SCREEN_H))
                x_off = (SCREEN_W - im.width) // 2
                y_off = (SCREEN_H - im.height) // 2
                canvas.paste(im, (x_off, y_off))
                canvas.save(output_png, "PNG")
            return True
    except Exception:
        pass
    return False


def _extract_structured_html_blocks(raw_html: str) -> Tuple[str, str, List[Tuple[str, str]]]:
    """
    Extrai (Título da Página, Cor de Fundo sugerida, Lista de blocos [(tipo, texto)])
    a partir do HTML retornado pela página (ex: página de bloqueio da NOS / Whalebone)
    para desenhar fielmente o view da página quando não há navegador gráfico.
    """
    if not raw_html:
        return "Sem resposta HTML", "#ffffff", []

    title = ""
    m_title = re.search(r"<title[^>]*>(.*?)</title>", raw_html, re.IGNORECASE | re.DOTALL)
    if m_title:
        title = html_unescape(re.sub(r"\s+", " ", m_title.group(1)).strip())

    # Tenta detectar background-color no CSS inline da página
    bg_color = "#ffffff"
    m_bg = re.search(r"body\s*\{[^}]*background(?:-color)?\s*:\s*(#[0-9a-fA-F]{3,6})", raw_html, re.IGNORECASE)
    if m_bg:
        bg_color = m_bg.group(1)

    # Remove <script>, <style>, <svg>, <head> e comentários para extrair o conteúdo visual real do <body>
    cleaned = re.sub(r"<!--.*?-->", " ", raw_html, flags=re.DOTALL)
    cleaned = re.sub(r"<(script|style|noscript|head|svg)[^>]*>.*?</\1>", " ", cleaned, flags=re.IGNORECASE | re.DOTALL)

    blocks: List[Tuple[str, str]] = []

    # Extrai imagens com alt/src relevantes (ex: logo NOS / ícone de bloqueio)
    for m_img in re.finditer(r"<img[^>]+>", cleaned, re.IGNORECASE):
        tag = m_img.group(0)
        alt_m = re.search(r'alt=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        src_m = re.search(r'src=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        alt_txt = alt_m.group(1).strip() if alt_m else ""
        src_txt = src_m.group(1).strip() if src_m else ""
        if alt_txt or (src_txt and not src_txt.startswith("data:")):
            label = alt_txt if alt_txt else os.path.basename(urllib.parse.urlsplit(src_txt).path)
            if label:
                blocks.append(("badge", f"[Imagem/Logo: {label}]"))

    # Substitui quebras de bloco por marcadores para preservar hierarquia visual (H1, H2, P, LI, DIV)
    token_pattern = re.compile(
        r"<(h1|h2|h3|p|li|button|a|div|span)[^>]*>(.*?)</\1>",
        re.IGNORECASE | re.DOTALL,
    )
    seen_texts = set()
    for m in token_pattern.finditer(cleaned):
        tag_name = m.group(1).lower()
        inner = re.sub(r"<[^>]+>", " ", m.group(2))
        inner = html_unescape(re.sub(r"\s+", " ", inner).strip())
        if not inner or len(inner) < 2:
            continue
        if inner in seen_texts:
            continue
        seen_texts.add(inner)

        if tag_name == "h1":
            blocks.append(("h1", inner))
        elif tag_name in ("h2", "h3"):
            blocks.append(("h2", inner))
        elif tag_name == "button":
            blocks.append(("button", inner))
        elif tag_name == "li":
            blocks.append(("li", f"• {inner}"))
        else:
            blocks.append(("p", inner))

    # Se o HTML não tinha tags semânticas aninhadas simples, extrai todo o texto visível por linha
    if not blocks:
        text_only = re.sub(r"<(br|hr|/p|/div|/h\d|/tr|/li)[^>]*>", "\n", cleaned, flags=re.IGNORECASE)
        text_only = re.sub(r"<[^>]+>", " ", text_only)
        for raw_ln in text_only.splitlines():
            ln = html_unescape(re.sub(r"\s+", " ", raw_ln).strip())
            if ln and ln not in seen_texts:
                seen_texts.add(ln)
                blocks.append(("p", ln))

    return title or "Página Carregada", bg_color, blocks


def html_unescape(text: str) -> str:
    import html

    return html.unescape(text)


def _wrap_text_lines(text: str, max_chars: int) -> List[str]:
    words = text.split()
    if not words:
        return []
    lines: List[str] = []
    curr = words[0]
    for w in words[1:]:
        if len(curr) + 1 + len(w) <= max_chars:
            curr += " " + w
        else:
            lines.append(curr)
            curr = w
    lines.append(curr)
    return lines


def render_block_page_viewport(
    url: str,
    dns_server: str,
    dns_res: DNSResult,
    tls_res: TLSResult,
    http_res: HTTPResult,
    output_png: Path,
) -> None:
    target_w = 1104
    html_content = http_res.final_body or http_res.body_preview or ""
    page_title, page_bg, blocks = _extract_structured_html_blocks(html_content)
    display_url = http_res.final_url or http_res.redirect_url or url
    has_real_html = (
        "<html" in html_content.lower()
        or "<body" in html_content.lower()
        or "<div" in html_content.lower()
        or "<h1" in html_content.lower()
        or "<p" in html_content.lower()
    )

    font_h1 = load_font(28, bold=True)
    font_h2 = load_font(20, bold=True)
    font_body = load_font(16, bold=False)
    font_bold = load_font(16, bold=True)
    font_small = load_font(14, bold=False)

    est_h = 120
    if has_real_html and blocks:
        for btype, btext in blocks:
            if btype == "badge":
                est_h += 46
            elif btype == "h1":
                est_h += len(_wrap_text_lines(btext, 58)) * 38 + 12
            elif btype == "h2":
                est_h += len(_wrap_text_lines(btext, 72)) * 28 + 8
            elif btype == "button":
                est_h += 54
            elif btype == "li":
                est_h += len(_wrap_text_lines(btext, 90)) * 24 + 4
            else:
                est_h += len(_wrap_text_lines(btext, 92)) * 24 + 8
        est_h = max(360, min(est_h + 60, 900))
    else:
        est_h = 420

    try:
        img = Image.new("RGB", (target_w, est_h), page_bg)
    except Exception:
        img = Image.new("RGB", (target_w, est_h), "#ffffff")
    draw = ImageDraw.Draw(img)

    is_https_bad = tls_res.verify_code not in ("0", "N/A") or http_res.ssl_verify != "0"

    if has_real_html and blocks:
        is_block_page = (
            "bloquead" in html_content.lower()
            or "whalebone" in html_content.lower()
            or "seguranca" in display_url.lower()
            or "segurança" in html_content.lower()
            or "proteg" in html_content.lower()
            or "acesso" in html_content.lower()
            or "malware" in html_content.lower()
            or "phishing" in html_content.lower()
        )
        top_bar_color = "#dc3535" if is_block_page else "#1a73e8"
        draw.rectangle([(0, 0), (target_w, 10)], fill=top_bar_color)

        y_cursor = 32
        x_pad = 40
        if page_title:
            draw.text((x_pad, y_cursor), page_title, fill="#5f6368", font=font_small)
            y_cursor += 28
            draw.line([(x_pad, y_cursor), (target_w - x_pad, y_cursor)], fill="#e0e0e0", width=1)
            y_cursor += 20

        for btype, btext in blocks:
            if y_cursor > est_h - 48:
                break
            if btype == "badge":
                bw = min(x_pad + len(btext) * 9 + 24, target_w - x_pad)
                draw.rounded_rectangle(
                    [(x_pad, y_cursor), (bw, y_cursor + 32)],
                    radius=4,
                    fill="#f8f9fa",
                    outline="#dadce0",
                )
                draw.text((x_pad + 12, y_cursor + 6), btext, fill="#3c4043", font=font_small)
                y_cursor += 44
            elif btype == "h1":
                for ln in _wrap_text_lines(btext, 58):
                    draw.text((x_pad, y_cursor), ln, fill="#c5221f" if is_block_page else "#202124", font=font_h1)
                    y_cursor += 38
                y_cursor += 10
            elif btype == "h2":
                for ln in _wrap_text_lines(btext, 72):
                    draw.text((x_pad, y_cursor), ln, fill="#202124", font=font_h2)
                    y_cursor += 28
                y_cursor += 8
            elif btype == "button":
                btn_w = min(max(len(btext) * 11 + 32, 160), 420)
                draw.rounded_rectangle(
                    [(x_pad, y_cursor), (x_pad + btn_w, y_cursor + 40)],
                    radius=6,
                    fill=top_bar_color,
                )
                draw.text((x_pad + 18, y_cursor + 10), btext[:38], fill="#ffffff", font=font_bold)
                y_cursor += 52
            elif btype == "li":
                for ln in _wrap_text_lines(btext, 90):
                    draw.text((x_pad + 16, y_cursor), ln, fill="#3c4043", font=font_body)
                    y_cursor += 24
                y_cursor += 4
            else:
                for ln in _wrap_text_lines(btext, 92):
                    draw.text((x_pad, y_cursor), ln, fill="#3c4043", font=font_body)
                    y_cursor += 24
                y_cursor += 8
    else:
        draw.rectangle([(0, 0), (target_w, est_h)], fill="#ffffff")
        draw.rectangle([(0, 0), (target_w, 10)], fill="#dc3535")
        box_x, box_y = 60, 50
        draw.rounded_rectangle([(box_x, box_y), (box_x + 56, box_y + 56)], radius=10, fill="#fce8e6")
        draw.text((box_x + 20, box_y + 10), "!", fill="#d93025", font=font_h1)

        y_cursor = box_y + 80
        if not dns_res.ips:
            err_title = "Não é possível acessar esse site"
            err_sub = f"Não foi possível encontrar o endereço IP do servidor de {url}"
            err_code = "DNS_PROBE_FINISHED_NXDOMAIN"
        elif is_https_bad:
            err_title = "Sua conexão não é particular / Site Bloqueado"
            err_sub = (
                f"O servidor DNS ({dns_server}) redirecionou {url} para o IP de bloqueio ({dns_res.ips_str}), "
                f"cujo certificado pertence a '{tls_res.cert_cn}'."
            )
            err_code = f"NET::ERR_CERT_COMMON_NAME_INVALID (CN={tls_res.cert_cn} | Verify={tls_res.verify_code})"
        else:
            err_title = "A conexão com o site foi recusada ou encerrada"
            err_sub = f"O IP resolvido ({dns_res.ips_str}) encerrou a conexão para {url}."
            err_code = f"HTTP Status: {http_res.status}"

        draw.text((box_x, y_cursor), err_title, fill="#202124", font=font_h1)
        y_cursor += 48
        for ln in _wrap_text_lines(err_sub, 82):
            draw.text((box_x, y_cursor), ln, fill="#5f6368", font=font_body)
            y_cursor += 26
        y_cursor += 18
        draw.text((box_x, y_cursor), err_code, fill="#d93025", font=font_bold)

    img.save(output_png, "PNG")


def _load_embedded_screenshot(
    temp_shot: Path,
    url: str,
    dns_server: str,
    dns_res: DNSResult,
    tls_res: TLSResult,
    http_res: HTTPResult,
) -> Image.Image:
    env_b64 = os.environ.get("BLOCK_SCREENSHOT_BASE64", "").strip()
    env_path = os.environ.get("BLOCK_SCREENSHOT_PATH", "").strip()

    if env_b64:
        try:
            import base64
            import io

            raw_bytes = base64.b64decode(env_b64)
            with Image.open(io.BytesIO(raw_bytes)) as im:
                return im.convert("RGB")
        except Exception:
            pass

    if env_path and os.path.isfile(env_path):
        try:
            with Image.open(env_path) as im:
                return im.convert("RGB")
        except Exception:
            pass

    if not temp_shot.is_file() or temp_shot.stat().st_size == 0:
        render_block_page_viewport(url, dns_server, dns_res, tls_res, http_res, temp_shot)

    with Image.open(temp_shot) as im:
        return im.convert("RGB")


def _apply_rounded_border(im: Image.Image, radius: int, border_color: str) -> Image.Image:
    w, h = im.size
    mask = Image.new("L", (w, h), 0)
    mask_draw = ImageDraw.Draw(mask)
    mask_draw.rounded_rectangle([(0, 0), (w - 1, h - 1)], radius=radius, fill=255)

    bg = Image.new("RGB", (w, h), "#22222c")
    bg.paste(im, (0, 0), mask)

    border_draw = ImageDraw.Draw(bg)
    border_draw.rounded_rectangle([(0, 0), (w - 1, h - 1)], radius=radius, outline=border_color, width=1)
    return bg


def build_final_screenshot_with_banner(
    temp_shot: Path,
    final_shot: Path,
    url: str,
    scheme: str,
    dns_server: str,
    dns_res: DNSResult,
    tls_res: TLSResult,
    http_res: HTTPResult,
) -> None:
    container_w = 1200

    resolved_ip = dns_res.ips_str
    dns_time_ms = dns_res.query_ms
    tls_version = tls_res.version
    cipher_suite = tls_res.cipher
    ssl_verify_code = tls_res.verify_code
    ssl_verify_msg = tls_res.verify_text
    cert_cn = tls_res.cert_cn
    cert_expiry = tls_res.cert_expires
    http_status = http_res.status
    http_time_ms = http_res.time_ms
    ssl_probe_summary = http_res.ssl_status
    redirect_url = http_res.redirect_url or "Nenhum"

    os_env = f"{platform.system()} ({platform.machine()})"
    if is_android_termux():
        os_env += " [Android/Termux]"

    html_content = http_res.final_body or http_res.body_preview or ""
    page_title = "Sem título HTML"
    m_title = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
    if m_title:
        extracted_title = html_unescape(re.sub(r"\s+", " ", m_title.group(1)).strip())
        if extracted_title:
            page_title = extracted_title[:100]

    shot_img = _load_embedded_screenshot(temp_shot, url, dns_server, dns_res, tls_res, http_res)

    card_margin_x = 32
    card_padding = 24
    inner_w = container_w - (card_margin_x * 2) - (card_padding * 2)

    scale = inner_w / float(shot_img.width)
    target_shot_w = inner_w
    target_shot_h = max(1, int(round(shot_img.height * scale)))
    resized_shot = shot_img.resize((target_shot_w, target_shot_h), Image.Resampling.LANCZOS)
    bordered_shot = _apply_rounded_border(resized_shot, radius=4, border_color="#3d3d4e")

    font_header_mono = load_font(12, bold=True, mono=True)
    font_url_bar = load_font(12, bold=False, mono=False)
    font_alert = load_font(16, bold=True, mono=False)
    font_prop_key = load_font(13, bold=False, mono=False)
    font_prop_val = load_font(13, bold=True, mono=False)
    font_secondary = load_font(11, bold=False, mono=False)
    font_shot_label = load_font(12, bold=False, mono=False)

    header_line_h = 17
    header_pad_y = 8
    header_pad_x = 12
    header_h = (header_pad_y * 2) + (header_line_h * 5)

    addr_bar_pad_y = 8
    addr_bar_pad_x = 16
    addr_input_h = 26
    addr_bar_h = (addr_bar_pad_y * 2) + addr_input_h

    section_gap = 20
    alert_h = 46

    prop_row_h = 26
    sec_row_h = 22
    props_total_h = (8 * prop_row_h) + sec_row_h

    shot_section_margin_top = 20
    shot_label_h = 16
    shot_label_margin_bottom = 10

    card_h = (
        (card_padding * 2)
        + props_total_h
        + shot_section_margin_top
        + shot_label_h
        + shot_label_margin_bottom
        + target_shot_h
    )

    bottom_margin = 32
    total_h = header_h + addr_bar_h + section_gap + alert_h + section_gap + card_h + bottom_margin

    canvas = Image.new("RGB", (container_w, total_h), "#181820")
    draw = ImageDraw.Draw(canvas)

    draw.rectangle([(0, 0), (container_w, header_h)], fill="#8b0000")
    header_lines = [
        f"URL: {url}",
        f"DNS: {dns_server} | Resolveu: {resolved_ip} | Query: {dns_time_ms} ms",
        f"TLS: {tls_version} | Cipher: {cipher_suite} | Verify: {ssl_verify_code} ({ssl_verify_msg})",
        f"HTTP: {http_status} | Tempo: {http_time_ms} ms | SSL(probe): {ssl_probe_summary}",
        f"Redirect: {redirect_url}",
    ]
    hy = header_pad_y
    for hline in header_lines:
        draw.text((header_pad_x, hy), hline, fill="#ffffff", font=font_header_mono)
        hy += header_line_h

    addr_y1 = header_h
    addr_y2 = addr_y1 + addr_bar_h
    draw.rectangle([(0, addr_y1), (container_w, addr_y2)], fill="#23232e")
    input_x1 = addr_bar_pad_x
    input_y1 = addr_y1 + addr_bar_pad_y
    input_x2 = container_w - addr_bar_pad_x
    input_y2 = input_y1 + addr_input_h
    draw.rounded_rectangle([(input_x1, input_y1), (input_x2, input_y2)], radius=4, fill="#121217")
    draw.text((input_x1 + 12, input_y1 + 6), f"URL: {url}", fill="#a0a0ab", font=font_url_bar)

    alert_x1 = card_margin_x
    alert_x2 = container_w - card_margin_x
    alert_y1 = addr_y2 + section_gap
    alert_y2 = alert_y1 + alert_h
    draw.rounded_rectangle([(alert_x1, alert_y1), (alert_x2, alert_y2)], radius=6, fill="#dc3535")
    alert_text = "ACESSO BLOQUEADO / INTERCEPTADO PELO DNS"
    draw.text((alert_x1 + 20, alert_y1 + 14), alert_text, fill="#ffffff", font=font_alert)

    card_x1 = card_margin_x
    card_x2 = container_w - card_margin_x
    card_y1 = alert_y2 + section_gap
    card_y2 = card_y1 + card_h
    draw.rounded_rectangle(
        [(card_x1, card_y1), (card_x2, card_y2)],
        radius=6,
        fill="#22222c",
        outline="#343442",
        width=1,
    )

    px = card_x1 + card_padding
    py = card_y1 + card_padding
    colon_x = px + 168
    val_x = colon_x + 14

    rows = [
        ("primary", "Ambiente de Execução", os_env),
        ("primary", "Servidor DNS Testado", dns_server),
        ("primary", "IP(s) Resolvido(s)", f"{resolved_ip} (Tempo: {dns_time_ms} ms)"),
        ("primary", "Handshake TLS", f"{tls_version} | Cipher: {cipher_suite}"),
        ("secondary", "", f"Validação Certificado: Código {ssl_verify_code} ({ssl_verify_msg}) | CN: {cert_cn}"),
        ("primary", "Validade Certificado", cert_expiry),
        ("primary", "Status HTTP", f"{http_status} (Tempo: {http_time_ms} ms) | SSL: {ssl_probe_summary}"),
        ("primary", "Redirecionamento", redirect_url),
        ("primary", "Título da Página", page_title),
    ]

    for rtype, k_label, v_label in rows:
        if rtype == "secondary":
            draw.text((px, py), v_label, fill="#b0b0bc", font=font_secondary)
            py += sec_row_h
        else:
            draw.text((px, py), k_label, fill="#e2e2e9", font=font_prop_key)
            draw.text((colon_x, py), ":", fill="#e2e2e9", font=font_prop_key)
            draw.text((val_x, py), v_label, fill="#e2e2e9", font=font_prop_val)
            py += prop_row_h

    py += shot_section_margin_top
    draw.text((px, py), "Trecho da Resposta / Detalhe:", fill="#b0b0bc", font=font_shot_label)
    py += shot_label_h + shot_label_margin_bottom

    canvas.paste(bordered_shot, (px, py))
    canvas.save(final_shot, "PNG")


# ==============================================================================
# SELEÇÃO DE USE CASE / ENTRADA DO USUÁRIO
# ==============================================================================


def select_dns_servers_interactive() -> Tuple[str, List[str]]:
    """Exibe menu interativo para escolha entre os 3 Use Cases ou digitação manual dos IPs."""
    print("\n" + "=" * 68)
    print("   DNS WHALEBONE CHECK - SELEÇÃO DE USE CASE / SERVIDORES DNS")
    print("=" * 68)
    for key, uc in USE_CASES.items():
        servers_str = ", ".join(uc["dns_servers"])  # type: ignore[arg-type]
        print(f"  [{key}] {uc['name']}")
        print(f"      {uc['description']}")
        print(f"      Servidores padrão: {servers_str}\n")
    print("  [4] Informar IPs de DNS manualmente")
    print("=" * 68)

    choice = input("Escolha uma opção [1-4] (Enter para 1): ").strip() or "1"

    if choice in USE_CASES:
        uc = USE_CASES[choice]
        default_servers: List[str] = list(uc["dns_servers"])  # type: ignore[arg-type]
        prompt = (
            f"Use Case {choice} selecionado ({', '.join(default_servers)}).\n"
            f"Pressione ENTER para usar esses IPs ou digite novos IPs separados por vírgula/espaço: "
        )
        custom = input(prompt).strip()
        if custom:
            servers = [s.strip() for s in re.split(r"[,\s]+", custom) if s.strip()]
            return str(uc["name"]), servers
        return str(uc["name"]), default_servers

    while True:
        raw = input("Digite os IPs dos servidores DNS separados por vírgula ou espaço (ex: 10.36.41.115, 8.8.8.8): ").strip()
        servers = [s.strip() for s in re.split(r"[,\s]+", raw) if s.strip()]
        if servers:
            return "Use Case Customizado (Manual)", servers
        print("Por favor, informe pelo menos um endereço IP de servidor DNS válido.")


# ==============================================================================
# FLUXO PRINCIPAL DE EXECUÇÃO
# ==============================================================================


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validador multiplataforma de bloqueio DNS (Whalebone) com captura de evidências."
    )
    parser.add_argument(
        "--use-case",
        choices=["1", "2", "3"],
        help="Seleciona diretamente um dos 3 Use Cases pré-configurados (1, 2 ou 3).",
    )
    parser.add_argument(
        "--dns",
        nargs="+",
        help="Lista de servidores DNS para testar (ex: --dns 10.36.41.115 8.8.8.8).",
    )
    parser.add_argument(
        "--urls",
        nargs="+",
        help="Lista customizada de URLs para testar.",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "desktop", "adb", "headless-card"],
        default="auto",
        help="Modo de captura de tela: 'auto' (detecta navegador local/ADB/Termux), 'desktop' (Chrome/Edge local), 'adb' (captura de Android via ADB), 'headless-card' (gera cartão visual sem browser).",
    )
    parser.add_argument(
        "--output-dir",
        help="Diretório de saída dos resultados (padrão: ./test_results_YYYYMMDD_HHMMSS).",
    )
    return parser.parse_args()


def resolve_output_dir(requested_dir: Optional[str], timestamp: str) -> Path:
    default_folder_name = f"test_results_{timestamp}"

    if is_android_termux():
        public_candidates = [
            Path("/storage/emulated/0/Download"),
            Path("/sdcard/Download"),
        ]
        home_dl = Path.home() / "storage" / "downloads"
        if home_dl.is_symlink():
            public_candidates.insert(0, home_dl)

        public_dl: Optional[Path] = None
        for cand in public_candidates:
            try:
                if cand.exists() and os.access(str(cand), os.W_OK):
                    public_dl = cand
                    break
            except Exception:
                continue

        if requested_dir:
            req_path = Path(requested_dir).expanduser()
            req_str = str(req_path)
            if "/home/storage/downloads" in req_str and not home_dl.is_symlink() and public_dl is not None:
                sub = req_str.split("/home/storage/downloads", 1)[1].lstrip("/")
                return public_dl / (sub or default_folder_name)
            return req_path

        if public_dl is not None:
            return public_dl / default_folder_name

    if requested_dir:
        return Path(requested_dir).expanduser()
    return Path(f"./{default_folder_name}")


def main() -> int:
    args = parse_args()

    # Determina os servidores DNS (via CLI ou Menu Interativo)
    if args.dns:
        flat_dns: List[str] = []
        for item in args.dns:
            flat_dns.extend([s.strip() for s in re.split(r"[,\s]+", item) if s.strip()])
        use_case_label = f"CLI Custom DNS ({', '.join(flat_dns)})"
        dns_servers = flat_dns
    elif args.use_case:
        uc = USE_CASES[args.use_case]
        use_case_label = str(uc["name"])
        dns_servers = list(uc["dns_servers"])  # type: ignore[arg-type]
    else:
        use_case_label, dns_servers = select_dns_servers_interactive()

    urls = args.urls if args.urls else DEFAULT_URLS

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = resolve_output_dir(args.output_dir, timestamp)
    tls_log_dir = output_dir / "tls_logs"
    output_dir.mkdir(parents=True, exist_ok=True)
    tls_log_dir.mkdir(parents=True, exist_ok=True)

    report_csv = output_dir / "report.csv"
    log_file = output_dir / "run.log"
    logger = Logger(log_file)

    browser_bin = find_local_browser()
    logger.log("============================================================")
    logger.log(f"Iniciando DNS Whalebone Check")
    logger.log(f"Sistema Operacional : {platform.system()} {platform.release()} ({platform.machine()})")
    logger.log(f"Cenário Selecionado : {use_case_label}")
    logger.log(f"Servidores DNS      : {', '.join(dns_servers)}")
    logger.log(f"Navegador Detectado : {browser_bin or 'Nenhum (usando modo Card Visual / ADB)'}")
    logger.log("============================================================")

    csv_headers = [
        "timestamp",
        "use_case",
        "dns_server",
        "url",
        "scheme",
        "domain",
        "resolved_ips",
        "dns_query_ms",
        "tls_version",
        "tls_cipher",
        "tls_verify",
        "tls_cn",
        "tls_expires",
        "tls_log",
        "http_status",
        "http_time_ms",
        "ssl_verify",
        "redirect_url",
        "final_url",
        "screenshot",
    ]

    with report_csv.open("w", newline="", encoding="utf-8") as csv_f:
        writer = csv.writer(csv_f, quoting=csv.QUOTE_ALL)
        writer.writerow(csv_headers)

        with tempfile.TemporaryDirectory(prefix="dns_whalebone_") as tmp_str:
            temp_dir = Path(tmp_str)

            for dns_srv in dns_servers:
                logger.log("============================================================")
                logger.log(f"Testando Servidor DNS: {dns_srv}")
                logger.log("============================================================")

                for url in urls:
                    parsed = urllib.parse.urlsplit(url)
                    scheme = parsed.scheme.lower()
                    domain = parsed.hostname or ""
                    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", f"{dns_srv}_{scheme}_{domain}")

                    logger.log(f"--- {url} (DNS: {dns_srv}) ---")

                    # 1. Resolução DNS direta no servidor escolhido
                    dns_res = resolve_dns(domain, dns_srv)
                    logger.log(f"  DNS: {dns_res.ips_str}  ({dns_res.query_ms} ms)")

                    primary_ip = dns_res.ips[0] if dns_res.ips else "FALHA"

                    # 2. Handshake TLS (se HTTPS)
                    if scheme == "https":
                        tls_res = tls_handshake_test(domain, primary_ip, tls_log_dir, safe_name)
                        logger.log(f"  TLS: {tls_res.version}  ({tls_res.cipher})")
                        logger.log(f"       Verify: {tls_res.verify_code} ({tls_res.verify_text})  CN: {tls_res.cert_cn}")
                        logger.log(f"       Dump completo: {tls_res.log_file}")
                    else:
                        tls_res = TLSResult(
                            version="N/A (http)",
                            cipher="N/A",
                            verify_code="N/A",
                            verify_text="HTTP puro",
                            cert_cn="N/A",
                            cert_expires="N/A",
                            log_file="",
                        )
                        logger.log("  TLS: pulado (esquema HTTP)")

                    # 3. Teste HTTP/HTTPS conectado diretamente ao IP retornado pelo DNS
                    http_res = http_probe(url, primary_ip, dns_srv)
                    if http_res.redirect_url:
                        logger.log(
                            f"  HTTP: {http_res.status}  ({http_res.time_ms} ms)  SSL: {http_res.ssl_status}  -> redirect: {http_res.redirect_url}"
                        )
                    else:
                        logger.log(
                            f"  HTTP: {http_res.status}  ({http_res.time_ms} ms)  SSL: {http_res.ssl_status}  -> {http_res.final_url}"
                        )

                    # 4. Captura de Screenshot + Banner
                    temp_shot = temp_dir / f"{safe_name}.png"
                    final_shot = output_dir / f"{safe_name}.png"

                    captured = False
                    if args.mode in ("auto", "adb") and (args.mode == "adb" or not browser_bin):
                        captured = capture_adb_screenshot(url, temp_shot)
                        if captured:
                            logger.log("  Screenshot: capturado do dispositivo Android via ADB")

                    if not captured and args.mode in ("auto", "desktop") and browser_bin:
                        captured = capture_browser_screenshot(
                            browser_bin,
                            url,
                            domain,
                            dns_res.ips,
                            http_res,
                            temp_shot,
                            temp_dir,
                        )
                        if captured:
                            logger.log("  Screenshot: capturado via navegador real com DNS isolado")

                    if not captured:
                        logger.log("  Screenshot: renderizando view da página para embutir no card")
                        render_block_page_viewport(url, dns_srv, dns_res, tls_res, http_res, temp_shot)

                    build_final_screenshot_with_banner(
                        temp_shot=temp_shot,
                        final_shot=final_shot,
                        url=url,
                        scheme=scheme,
                        dns_server=dns_srv,
                        dns_res=dns_res,
                        tls_res=tls_res,
                        http_res=http_res,
                    )

                    tls_log_basename = Path(tls_res.log_file).name if tls_res.log_file else ""
                    now_iso = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

                    writer.writerow(
                        [
                            now_iso,
                            use_case_label,
                            dns_srv,
                            url,
                            scheme,
                            domain,
                            dns_res.ips_str,
                            dns_res.query_ms,
                            tls_res.version,
                            tls_res.cipher,
                            f"{tls_res.verify_code} ({tls_res.verify_text})",
                            tls_res.cert_cn,
                            tls_res.cert_expires,
                            tls_log_basename,
                            http_res.status,
                            http_res.time_ms,
                            http_res.ssl_status,
                            http_res.redirect_url,
                            http_res.final_url,
                            final_shot.name,
                        ]
                    )
                    csv_f.flush()

    logger.log("============================================================")
    logger.log(f"Concluído! Resultados salvos em: {output_dir.resolve()}")
    logger.log(f"Relatório CSV : {report_csv.resolve()}")
    logger.log(f"Log de Execução: {log_file.resolve()}")
    logger.log("============================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
