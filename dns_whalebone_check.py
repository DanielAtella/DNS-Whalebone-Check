#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "dnspython>=2.6.1",
#     "Pillow>=10.3.0",
#     "cryptography>=42.0.0",
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
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
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
        "dns_servers": ["8.8.8.8"],
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


def load_font(size: int, bold: bool = True) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Busca uma fonte legível no Windows, macOS, Linux ou Android."""
    candidates = []
    sys_name = platform.system().lower()

    if sys_name == "darwin":
        candidates = [
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/SFNSMono.ttf",
            "/Library/Fonts/Arial.ttf",
        ]
    elif sys_name == "windows":
        windir = os.environ.get("WINDIR", "C:\\Windows")
        candidates = [
            os.path.join(windir, "Fonts", "arialbd.ttf" if bold else "arial.ttf"),
            os.path.join(windir, "Fonts", "seguisb.ttf" if bold else "segoeui.ttf"),
            os.path.join(windir, "Fonts", "consolab.ttf" if bold else "consola.ttf"),
        ]
    else:
        candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
            "/system/fonts/Roboto-Bold.ttf" if bold else "/system/fonts/Roboto-Regular.ttf",
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


def _extract_cn(subject: x509.Name) -> str:
    attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        val = attrs[0].value
        return val if isinstance(val, str) else val.decode("utf-8", errors="replace")
    return "N/A"


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
                    cert_obj = x509.load_der_x509_certificate(der_cert)
                    cert_cn = _extract_cn(cert_obj.subject)
                    issuer_cn = _extract_cn(cert_obj.issuer)
                    try:
                        not_after = cert_obj.not_valid_after_utc
                    except AttributeError:
                        not_after = cert_obj.not_valid_after
                    cert_expires = not_after.strftime("%b %d %H:%M:%S %Y GMT")
                    pem_data = ssl.DER_cert_to_PEM_cert(der_cert)
                    fingerprint = cert_obj.fingerprint(hashes.SHA256()).hex(":")

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


def http_probe(url: str, target_ip: str, dns_server: str, timeout: int = HTTP_TIMEOUT) -> HTTPResult:
    """
    Faz uma requisição HTTP/HTTPS similar ao `curl -sS -k` do script original,
    conectando no IP resolvido pelo servidor DNS em teste.
    """
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

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

    start = time.perf_counter()
    try:
        headers = {
            "Host": host if (port in (80, 443)) else f"{host}:{port}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
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
        body_bytes = resp.read(16384)
        conn.close()

        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        status_code = str(resp.status)
        location = resp.getheader("Location") or ""
        redirect_url = urllib.parse.urljoin(url, location) if location else ""

        if scheme == "http":
            ssl_status = "N/A (http)"
        elif ssl_verify != "0":
            ssl_status = f"CERT INVALIDO (codigo {ssl_verify})"
        else:
            ssl_status = "OK"

        body_text = body_bytes.decode("utf-8", errors="replace")
        return HTTPResult(
            status=status_code,
            time_ms=str(elapsed_ms),
            final_url=url,
            ssl_verify=ssl_verify,
            ssl_status=ssl_status,
            redirect_url=redirect_url,
            body_preview=body_text,
        )
    except Exception as e:
        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        if scheme == "http":
            ssl_status = "N/A (http)"
        elif ssl_verify != "0":
            ssl_status = f"CERT INVALIDO (codigo {ssl_verify})"
        else:
            ssl_status = "OK"
        return HTTPResult(
            status="000",
            time_ms=str(elapsed_ms),
            final_url=url,
            ssl_verify=ssl_verify,
            ssl_status=ssl_status,
            redirect_url="",
            body_preview=f"Erro HTTP/Conexao: {type(e).__name__}: {e}",
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
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "brave-browser",
        ):
            found = shutil.which(cmd)
            if found:
                candidates.append(found)

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def capture_browser_screenshot(
    browser_bin: str,
    url: str,
    domain: str,
    resolved_ips: List[str],
    output_png: Path,
    temp_dir: Path,
) -> bool:
    """
    Usa o navegador local (Chrome/Edge/Brave) em modo headless com `--host-resolver-rules`
    para forçar a resolução de DNS isolada sem tocar no DNS do sistema operacional!
    """
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

    # Se o DNS resolveu para um IP, mapeamos o domínio diretamente para esse IP dentro do Chrome.
    # Se falhou (NXDOMAIN), mapeamos para ~NOTFOUND para o navegador exibir a tela real de erro DNS.
    if resolved_ips:
        target_ip = resolved_ips[0]
        resolver_rule = f"MAP {domain} {target_ip}"
    else:
        resolver_rule = f"MAP {domain} ~NOTFOUND"

    cmd = [
        browser_bin,
        "--headless=new",
        f"--user-data-dir={profile_dir}",
        "--incognito",
        "--no-sandbox",
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
        f"--virtual-time-budget={PAGE_LOAD_WAIT * 1000}",
        f"--screenshot={output_png}",
        url,
    ]

    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PAGE_LOAD_WAIT + 15,
            check=False,
        )
    except Exception:
        pass
    finally:
        shutil.rmtree(profile_dir, ignore_errors=True)

    return output_png.is_file() and output_png.stat().st_size > 0


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


def render_visual_evidence_card(
    url: str,
    dns_server: str,
    dns_res: DNSResult,
    tls_res: TLSResult,
    http_res: HTTPResult,
    output_png: Path,
) -> None:
    """
    Gera um cartão visual rico simulando a janela do navegador quando executado em ambiente
    sem interface gráfica (ex: Android Termux direto no celular ou servidor sem browser).
    """
    img = Image.new("RGB", (SCREEN_W, SCREEN_H), "#1e1e24")
    draw = ImageDraw.Draw(img)

    font_title = load_font(34, bold=True)
    font_sub = load_font(24, bold=True)
    font_body = load_font(20, bold=False)

    # Barra superior estilo navegador
    draw.rectangle([(0, 0), (SCREEN_W, 70)], fill="#2b2b36")
    draw.rounded_rectangle([(30, 14), (SCREEN_W - 30, 56)], radius=10, fill="#141419")
    draw.text((50, 22), f"URL: {url}", fill="#e0e0e0", font=font_body)

    # Determina status visual (Bloqueado / Permitido / Alerta)
    is_blocked = (
        not dns_res.ips
        or http_res.status == "000"
        or (tls_res.verify_code not in ("0", "N/A"))
        or (http_res.ssl_verify != "0")
        or ("whalebone" in http_res.body_preview.lower())
        or ("block" in http_res.body_preview.lower())
        or ("bloquead" in http_res.body_preview.lower())
    )

    status_label = "ACESSO BLOQUEADO / INTERCEPTADO PELO DNS" if is_blocked else "ACESSO PERMITIDO (CONEXÃO NORMAL)"
    status_color = "#d9383a" if is_blocked else "#1f9d55"

    draw.rounded_rectangle([(80, 120), (SCREEN_W - 80, 220)], radius=12, fill=status_color)
    draw.text((120, 150), status_label, fill="#ffffff", font=font_title)

    # Caixa de detalhes técnicos
    draw.rounded_rectangle([(80, 260), (SCREEN_W - 80, SCREEN_H - 80)], radius=12, fill="#262630", outline="#3e3e4f", width=2)

    # Extrai título HTML se existir no body_preview
    html_title = "Sem título HTML"
    m = re.search(r"<title[^>]*>(.*?)</title>", http_res.body_preview, re.IGNORECASE | re.DOTALL)
    if m:
        html_title = re.sub(r"\s+", " ", m.group(1)).strip()[:100]

    details = [
        f"Ambiente de Execução : {platform.system()} ({platform.machine()})" + (" [Android/Termux]" if is_android_termux() else ""),
        f"Servidor DNS Testado : {dns_server}",
        f"IP(s) Resolvido(s)   : {dns_res.ips_str} (Tempo: {dns_res.query_ms} ms)",
        f"Handshake TLS        : {tls_res.version} | Cipher: {tls_res.cipher}",
        f"Validação Certificado: Código {tls_res.verify_code} ({tls_res.verify_text}) | CN: {tls_res.cert_cn}",
        f"Validade Certificado : {tls_res.cert_expires}",
        f"Status HTTP          : {http_res.status} (Tempo: {http_res.time_ms} ms) | SSL: {http_res.ssl_status}",
        f"Redirecionamento     : {http_res.redirect_url or 'Nenhum'}",
        f"Título da Página     : {html_title}",
        "",
        "Trecho da Resposta / Detalhe:",
    ]

    y = 300
    for line in details:
        draw.text((120, y), line, fill="#f0f0f5", font=font_sub if " : " in line else font_body)
        y += 45

    # Preview limpo do corpo ou erro
    clean_preview = re.sub(r"<[^>]+>", " ", http_res.body_preview)
    clean_preview = re.sub(r"\s+", " ", clean_preview).strip()
    if not clean_preview:
        clean_preview = "(Sem conteúdo textual no corpo da resposta)"

    # Quebra em linhas de até 110 caracteres
    for i in range(0, min(len(clean_preview), 660), 110):
        draw.text((120, y), clean_preview[i : i + 110], fill="#a5a5b8", font=font_body)
        y += 32

    img.save(output_png, "PNG")


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
    """
    Cria o banner superior idêntico ao ImageMagick (`convert`) do script Bash original
    e concatena verticalmente com a captura de tela.
    """
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line1 = f"URL: {url}"
    line2 = f"DNS: {dns_server}  |  Resolveu: {dns_res.ips_str}  |  Query: {dns_res.query_ms} ms"
    line3 = f"TLS: {tls_res.version}  |  Cipher: {tls_res.cipher}  |  Verify: {tls_res.verify_code} ({tls_res.verify_text})"
    line4 = f"HTTP: {http_res.status}  |  Tempo: {http_res.time_ms} ms  |  SSL(probe): {http_res.ssl_status}"
    if http_res.redirect_url:
        line5 = f"Redirect: {http_res.redirect_url}  |  {now_str}"
    else:
        line5 = f"Final: {http_res.final_url}  |  {now_str}"

    tls_bad = scheme == "https" and tls_res.verify_code not in ("0", "N/A")
    ssl_bad = scheme == "https" and http_res.ssl_verify != "0"

    if tls_bad or ssl_bad:
        banner_color = "#960000"  # Vermelho (bloqueado / certificado inválido)
    elif http_res.status.startswith("2"):
        banner_color = "#0a6e0a"  # Verde (HTTP 2xx + SSL OK)
    elif http_res.status.startswith("3"):
        banner_color = "#b48c00"  # Amarelo (Redirect 3xx)
    else:
        banner_color = "#960000"  # Vermelho (Erro / Bloqueio)

    with Image.open(temp_shot) as shot_im:
        shot_rgb = shot_im.convert("RGB")
        w = shot_rgb.width
        h = shot_rgb.height

        banner_im = Image.new("RGB", (w, BANNER_H), banner_color)
        draw = ImageDraw.Draw(banner_im)
        font = load_font(20, bold=True)

        lines = [line1, line2, line3, line4, line5]
        y_pos = 10
        for ln in lines:
            draw.text((20, y_pos), ln, fill="white", font=font)
            y_pos += 28

        combined = Image.new("RGB", (w, BANNER_H + h))
        combined.paste(banner_im, (0, 0))
        combined.paste(shot_rgb, (0, BANNER_H))
        combined.save(final_shot, "PNG")


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
    output_dir = Path(args.output_dir) if args.output_dir else Path(f"./test_results_{timestamp}")
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
                            browser_bin, url, domain, dns_res.ips, temp_shot, temp_dir
                        )
                        if captured:
                            logger.log("  Screenshot: capturado via navegador com DNS isolado")

                    if not captured:
                        logger.log("  Screenshot: gerando cartão visual de evidência (modo sem navegador/Termux)")
                        render_visual_evidence_card(url, dns_srv, dns_res, tls_res, http_res, temp_shot)

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
