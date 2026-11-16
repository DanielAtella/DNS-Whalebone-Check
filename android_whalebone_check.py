#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "Pillow>=10.3.0",
# ]
# ///
"""
Android Whalebone Check - Execução nativa no Termux ou via ADB.

Funcionalidades principais:
1. Execução direta no Termux (sem necessidade de ADB remoto) ou via ADB local/USB.
2. Auditoria de DNS Privado (Private DNS) no Android OS e DNS Seguro (DoH) no
   Google Chrome, detetando possível bypass das políticas DNS/Whalebone.
3. Navegação similar a um utilizador nos aplicativos configurados via `.env`
   (por padrão: Reddit, Instagram e Netflix), confirmando se carregam ou foram
   bloqueados e capturando printscreens / evidências.
4. Navegação no Google Chrome pelas URLs de teste e geração de relatório
   consolidado (`report.json`, `report.csv`, `run.log` e `screenshots/`).
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont

    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

# ==============================================================================
# CONFIGURAÇÕES PADRÃO E CATÁLOGO DE APLICATIVOS
# ==============================================================================

DEFAULT_URLS: List[str] = [
    "https://www.google.com",
    "https://malware.test.attacker.online",
    "https://c2server.test.attacker.online",
    "https://spam.test.attacker.online",
    "https://phishing.test.attacker.online",
    "https://coinminer.test.attacker.online",
    "https://www.lovehoney.com",
    "https://www.erowid.org",
]

APP_CATALOG: Dict[str, Dict[str, object]] = {
    "reddit": {
        "name": "Reddit",
        "package": "com.reddit.frontpage",
        "probe_urls": ["https://www.reddit.com"],
    },
    "instagram": {
        "name": "Instagram",
        "package": "com.instagram.android",
        "probe_urls": ["https://www.instagram.com"],
    },
    "netflix": {
        "name": "Netflix",
        "package": "com.netflix.mediaclient",
        "probe_urls": ["https://www.netflix.com"],
    },
    "chrome": {
        "name": "Chrome",
        "package": "com.android.chrome",
        "probe_urls": ["https://www.google.com"],
    },
    "youtube": {
        "name": "YouTube",
        "package": "com.google.android.youtube",
        "probe_urls": ["https://www.youtube.com"],
    },
    "settings": {
        "name": "Settings",
        "package": "com.android.settings",
        "probe_urls": [],
    },
    "facebook": {
        "name": "Facebook",
        "package": "com.facebook.katana",
        "probe_urls": ["https://www.facebook.com"],
    },
    "tiktok": {
        "name": "TikTok",
        "package": "com.zhiliaoapp.musically",
        "probe_urls": ["https://www.tiktok.com"],
    },
    "spotify": {
        "name": "Spotify",
        "package": "com.spotify.music",
        "probe_urls": ["https://open.spotify.com"],
    },
}

DEFAULT_APP_KEYS: List[str] = ["reddit", "instagram", "netflix"]

CHROME_PACKAGE = "com.android.chrome"
CHROME_ACTIVITY = "com.google.android.apps.chrome.Main"

BLOCK_KEYWORDS = (
    "whalebone",
    "blocked",
    "bloqueado",
    "bloqueada",
    "access denied",
    "acesso negado",
    "site bloqueado",
    "malware",
    "phishing",
    "spam",
    "coinminer",
    "c2server",
    "policy",
    "política",
    "security",
    "segurança",
)

ERROR_KEYWORDS = (
    "err_name_not_resolved",
    "err_connection_refused",
    "err_connection_timed_out",
    "err_ssl",
    "err_cert_",
    "this site can't be reached",
    "não é possível aceder a este site",
    "não foi possível acessar esse site",
    "dns_probe_finished",
    "your connection is not private",
    "a sua ligação não é privada",
    "no internet",
    "sem ligação",
    "sem conexão",
    "can't connect",
    "try again",
    "tente novamente",
)

CHROME_SECURE_DNS_LABELS = (
    "use secure dns",
    "usar dns seguro",
    "dns seguro",
    "secure dns",
)

CHROME_PRIVACY_LABELS = (
    "privacy and security",
    "privacidade e segurança",
    "privacidade e seguranca",
)

CHROME_SETTINGS_LABELS = (
    "settings",
    "definições",
    "definicoes",
    "configurações",
    "configuracoes",
)

CHROME_CUSTOM_PROVIDER_HINTS = (
    "choose another provider",
    "escolher outro fornecedor",
    "escolher outro provedor",
    "custom",
    "personalizado",
    "cloudflare",
    "google (public dns)",
    "quad9",
    "nextdns",
    "opendns",
    "adguard",
)

CHROME_CURRENT_PROVIDER_HINTS = (
    "with your current service provider",
    "com o seu fornecedor de serviços atual",
    "com seu provedor de serviços atual",
    "automatic",
    "automático",
)

SINKHOLE_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


# ==============================================================================
# MODELOS DE DADOS
# ==============================================================================


@dataclass
class AndroidEnvConfig:
    apps: List[str] = field(default_factory=lambda: list(DEFAULT_APP_KEYS))
    urls: List[str] = field(default_factory=lambda: list(DEFAULT_URLS))
    backend: str = "auto"
    app_wait: int = 5
    page_wait: int = 6
    check_private_dns: bool = True
    check_chrome: bool = True
    simulate_scroll: bool = True
    output_dir: str = ""


@dataclass
class DeviceInfo:
    serial: str
    model: str = "Unknown"
    android_version: str = "Unknown"
    sdk: str = "Unknown"
    execution_mode: str = "adb"


@dataclass
class PrivateDNSStatus:
    android_mode: str = "unknown"  # off | opportunistic | hostname | null | unknown
    android_specifier: str = ""
    active_dns_servers: List[str] = field(default_factory=list)
    validated_private_dns_servers: List[str] = field(default_factory=list)
    chrome_secure_dns_state: str = "unknown"  # off | current_provider | custom_provider | unknown
    chrome_secure_dns_provider: str = ""
    bypass_risk: str = "UNKNOWN"  # SAFE | WARNING | BYPASS_DETECTED | UNKNOWN
    details: str = ""
    android_settings_screenshot: str = ""
    chrome_settings_screenshot: str = ""


@dataclass
class EndpointProbeResult:
    url: str
    resolved_ips: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    final_url: str = ""
    status: str = "UNKNOWN"  # LOADED | BLOCKED | ERROR | UNKNOWN
    matched_keywords: List[str] = field(default_factory=list)
    error: str = ""


@dataclass
class AppTestResult:
    app_name: str
    package: str
    installed: bool
    launched: bool
    foreground_verified: bool
    load_status: str  # LOADED | BLOCKED | ERROR | NOT_INSTALLED | UNKNOWN
    resolved_ips: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    duration_ms: int = 0
    screenshot_path: str = ""
    notes: str = ""


@dataclass
class ChromeURLResult:
    url: str
    opened: bool
    detected_status: str  # BLOCKED | ALLOWED | ERROR | UNKNOWN
    matched_keywords: List[str] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    page_snippet: str = ""
    duration_ms: int = 0
    screenshot_path: str = ""
    bypass_risk: str = "UNKNOWN"
    notes: str = ""


@dataclass
class UINode:
    text: str
    content_desc: str
    resource_id: str
    class_name: str
    checked: Optional[bool]
    clickable: bool
    bounds: Tuple[int, int, int, int]

    @property
    def center(self) -> Tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return ((x1 + x2) // 2, (y1 + y2) // 2)

    @property
    def label(self) -> str:
        return (self.text or self.content_desc or "").strip()


# ==============================================================================
# CARREGAMENTO DE .ENV E CATÁLOGO DE APPS
# ==============================================================================


def _parse_bool(raw: str, default: bool) -> bool:
    val = (raw or "").strip().lower()
    if val in ("1", "true", "yes", "sim", "on"):
        return True
    if val in ("0", "false", "no", "nao", "não", "off"):
        return False
    return default


def _split_list(raw: str) -> List[str]:
    return [item.strip() for item in re.split(r"[\s,;]+", raw.strip()) if item.strip()]


def load_android_env(custom_env_path: Optional[str] = None) -> AndroidEnvConfig:
    """Carrega configurações de `.env.android` (prioritário) ou `.env`."""
    cfg = AndroidEnvConfig()
    candidates: List[Path] = []
    if custom_env_path:
        candidates.append(Path(custom_env_path))
    else:
        candidates.extend([Path(".env.android"), Path(".env")])

    env_vars: Dict[str, str] = {}
    for path in candidates:
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, val = stripped.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if "#" in val and not val.startswith("http"):
                    val = val.split("#", 1)[0].strip()
                env_vars[key] = val
            break

    # Permite override por variáveis de ambiente do processo
    for key in (
        "ANDROID_APPS",
        "ANDROID_URLS",
        "DOMAINS",
        "ANDROID_BACKEND",
        "ANDROID_APP_WAIT",
        "ANDROID_PAGE_WAIT",
        "ANDROID_CHECK_PRIVATE_DNS",
        "ANDROID_CHECK_CHROME",
        "ANDROID_SIMULATE_SCROLL",
        "ANDROID_OUTPUT_DIR",
    ):
        if key in os.environ and os.environ[key].strip():
            env_vars[key] = os.environ[key].strip()

    if env_vars.get("ANDROID_APPS"):
        cfg.apps = _split_list(env_vars["ANDROID_APPS"])

    urls_raw = env_vars.get("ANDROID_URLS") or env_vars.get("DOMAINS")
    if urls_raw:
        parsed_urls = []
        for item in _split_list(urls_raw):
            parsed_urls.append(item if item.startswith(("http://", "https://")) else f"https://{item}")
        if parsed_urls:
            cfg.urls = parsed_urls

    if env_vars.get("ANDROID_BACKEND") in ("auto", "termux", "adb"):
        cfg.backend = env_vars["ANDROID_BACKEND"]
    if env_vars.get("ANDROID_APP_WAIT", "").isdigit():
        cfg.app_wait = int(env_vars["ANDROID_APP_WAIT"])
    if env_vars.get("ANDROID_PAGE_WAIT", "").isdigit():
        cfg.page_wait = int(env_vars["ANDROID_PAGE_WAIT"])

    cfg.check_private_dns = _parse_bool(env_vars.get("ANDROID_CHECK_PRIVATE_DNS", ""), cfg.check_private_dns)
    cfg.check_chrome = _parse_bool(env_vars.get("ANDROID_CHECK_CHROME", ""), cfg.check_chrome)
    cfg.simulate_scroll = _parse_bool(env_vars.get("ANDROID_SIMULATE_SCROLL", ""), cfg.simulate_scroll)
    cfg.output_dir = env_vars.get("ANDROID_OUTPUT_DIR", "")
    return cfg


def resolve_app_targets(tokens: Sequence[str]) -> List[Dict[str, object]]:
    """Converte nomes amigáveis (`reddit`, `instagram`, `netflix`) ou pacotes em definições completas."""
    resolved: List[Dict[str, object]] = []
    for token in tokens:
        key = token.strip().lower()
        if key in APP_CATALOG:
            resolved.append(dict(APP_CATALOG[key]))
        else:
            # Permite passar package name diretamente (ex: com.reddit.frontpage)
            friendly = token.split(".")[-1].capitalize() if "." in token else token
            resolved.append({"name": friendly, "package": token.strip(), "probe_urls": []})
    return resolved


# ==============================================================================
# BACKENDS ANDROID (TERMUX LOCAL & ADB)
# ==============================================================================


def is_termux_env() -> bool:
    return bool(os.environ.get("TERMUX_VERSION")) or Path("/data/data/com.termux").exists()


class AndroidBackend:
    """Interface comum para execução de comandos no Android (Termux local ou ADB)."""

    mode_name: str = "base"

    def is_available(self) -> bool:
        raise NotImplementedError

    def shell(self, args: Sequence[str], timeout: int = 15) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def get_device_info(self) -> DeviceInfo:
        model = self.shell(["getprop", "ro.product.model"], timeout=5).stdout.strip() or "Unknown"
        version = self.shell(["getprop", "ro.build.version.release"], timeout=5).stdout.strip() or "Unknown"
        sdk = self.shell(["getprop", "ro.build.version.sdk"], timeout=5).stdout.strip() or "Unknown"
        return DeviceInfo(serial="local-termux", model=model, android_version=version, sdk=sdk, execution_mode=self.mode_name)

    def screencap(self, output_png: Path, timeout: int = 15) -> bool:
        raise NotImplementedError

    def dump_ui_xml(self, remote_path: str = "/sdcard/whalebone_ui_dump.xml") -> str:
        self.shell(["uiautomator", "dump", remote_path], timeout=12)
        res = self.shell(["cat", remote_path], timeout=8)
        if res.returncode == 0 and "<hierarchy" in res.stdout:
            return res.stdout
        return ""

    def tap(self, x: int, y: int) -> None:
        self.shell(["input", "tap", str(x), str(y)], timeout=5)

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 350) -> None:
        self.shell(["input", "swipe", str(x1), str(y1), str(x2), str(y2), str(duration_ms)], timeout=8)

    def keyevent(self, keycode: str) -> None:
        self.shell(["input", "keyevent", keycode], timeout=5)

    def input_text(self, text: str) -> None:
        escaped = text.replace(" ", "%s").replace("&", "\\&").replace("?", "\\?")
        self.shell(["input", "text", escaped], timeout=8)


class ADBClient(AndroidBackend):
    """Backend via ADB (USB ou loopback local)."""

    mode_name = "adb"

    def __init__(self, adb_bin: Optional[str] = None, serial: Optional[str] = None):
        self.adb_bin = adb_bin or shutil.which("adb") or "adb"
        self.serial = serial

    def is_available(self) -> bool:
        return shutil.which(self.adb_bin) is not None or Path(self.adb_bin).is_file()

    def _base_cmd(self, with_serial: bool = True) -> List[str]:
        cmd = [self.adb_bin]
        if with_serial and self.serial:
            cmd.extend(["-s", self.serial])
        return cmd

    def run(
        self,
        args: Sequence[str],
        timeout: int = 15,
        with_serial: bool = True,
        binary: bool = False,
    ) -> subprocess.CompletedProcess:
        cmd = self._base_cmd(with_serial=with_serial) + list(args)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=not binary,
            timeout=timeout,
            check=False,
        )

    def shell(self, args: Sequence[str], timeout: int = 15) -> subprocess.CompletedProcess:
        return self.run(["shell", *args], timeout=timeout)

    def list_devices(self) -> List[str]:
        res = self.run(["devices"], timeout=8, with_serial=False)
        if res.returncode != 0:
            return []
        devices: List[str] = []
        for line in res.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        return devices

    def get_device_info(self) -> DeviceInfo:
        info = super().get_device_info()
        info.serial = self.serial or "default"
        return info

    def screencap(self, output_png: Path, timeout: int = 15) -> bool:
        output_png.parent.mkdir(parents=True, exist_ok=True)
        res = self.run(["exec-out", "screencap", "-p"], timeout=timeout, binary=True)
        if res.returncode != 0 or not res.stdout or len(res.stdout) < 100:
            return False
        output_png.write_bytes(res.stdout)
        return True


class TermuxBackend(AndroidBackend):
    """
    Backend nativo para execução direta dentro do Termux no Android,
    sem depender de ADB remoto. Usa `rish` (Shizuku) ou `su` se disponíveis
    para comandos privilegiados (`screencap`, `uiautomator`, `input`), e executa
    `am`, `pm`, `getprop`, `settings` e sondagens de rede diretamente.
    """

    mode_name = "termux"

    def __init__(self) -> None:
        self.rish_bin = shutil.which("rish")
        self.su_bin = shutil.which("su")

    def is_available(self) -> bool:
        return is_termux_env() or shutil.which("am") is not None or shutil.which("getprop") is not None

    def _run_local(self, args: Sequence[str], timeout: int = 15, binary: bool = False) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                list(args),
                capture_output=True,
                text=not binary,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return subprocess.CompletedProcess(args=list(args), returncode=127, stdout=b"" if binary else "", stderr="")
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(args=list(args), returncode=124, stdout=b"" if binary else "", stderr="timeout")

    def shell(self, args: Sequence[str], timeout: int = 15) -> subprocess.CompletedProcess:
        cmd_list = list(args)
        privileged_cmds = {"screencap", "uiautomator", "input", "dumpsys"}
        if cmd_list and cmd_list[0] in privileged_cmds:
            joined = " ".join(cmd_list)
            if self.rish_bin:
                res = self._run_local([self.rish_bin, "-c", joined], timeout=timeout)
                if res.returncode == 0:
                    return res
            if self.su_bin:
                res = self._run_local([self.su_bin, "-c", joined], timeout=timeout)
                if res.returncode == 0:
                    return res
        return self._run_local(cmd_list, timeout=timeout)

    def screencap(self, output_png: Path, timeout: int = 15) -> bool:
        output_png.parent.mkdir(parents=True, exist_ok=True)
        for prefix in ([self.rish_bin, "-c"] if self.rish_bin else None, [self.su_bin, "-c"] if self.su_bin else None):
            if not prefix:
                continue
            res = self._run_local([*prefix, "screencap -p"], timeout=timeout, binary=True)
            if res.returncode == 0 and res.stdout and len(res.stdout) > 100 and res.stdout.startswith(b"\x89PNG"):
                output_png.write_bytes(res.stdout)
                return True

        res = self._run_local(["screencap", "-p"], timeout=timeout, binary=True)
        if res.returncode == 0 and res.stdout and len(res.stdout) > 100 and res.stdout.startswith(b"\x89PNG"):
            output_png.write_bytes(res.stdout)
            return True
        return False


def create_backend(mode: str = "auto", serial: Optional[str] = None) -> AndroidBackend:
    """Seleciona o backend adequado (`termux` ou `adb`)."""
    if mode == "termux":
        return TermuxBackend()
    if mode == "adb":
        return ADBClient(serial=serial)

    # Modo auto: se estiver no Termux e não houver ADB local conectado, usa TermuxBackend
    if is_termux_env():
        adb = ADBClient(serial=serial)
        if adb.is_available() and adb.list_devices():
            if not adb.serial:
                adb.serial = adb.list_devices()[0]
            return adb
        return TermuxBackend()

    return ADBClient(serial=serial)


# ==============================================================================
# SONDAGEM DE REDE / CONFIRMAÇÃO DE CARREGAMENTO OU BLOQUEIO
# ==============================================================================


def probe_endpoint_connectivity(url: str, timeout: int = 10) -> EndpointProbeResult:
    """
    Executa resolução DNS + requisição HTTP/HTTPS usando o resolver ativo do Android
    para confirmar se o domínio/serviço carrega (`LOADED`) ou foi bloqueado (`BLOCKED`).
    """
    result = EndpointProbeResult(url=url)
    host_match = re.match(r"^https?://([^/:]+)", url)
    host = host_match.group(1) if host_match else url

    try:
        addr_info = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = []
        for item in addr_info:
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
        result.resolved_ips = ips
    except socket.gaierror as exc:
        result.status = "BLOCKED"
        result.error = f"DNS resolution failed: {exc}"
        return result

    if any(ip in SINKHOLE_IPS for ip in result.resolved_ips):
        result.status = "BLOCKED"
        result.matched_keywords = ["sinkhole_ip"]
        return result

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Linux; Android 14; Mobile) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
            )
        },
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result.http_status = resp.status
            result.final_url = resp.geturl()
            body = resp.read(16384).decode("utf-8", errors="ignore").lower()
            matched_block = [kw for kw in BLOCK_KEYWORDS if kw in body]
            if matched_block or any(kw in result.final_url.lower() for kw in ("whalebone", "block")):
                result.status = "BLOCKED"
                result.matched_keywords = matched_block or ["block_redirect"]
            else:
                result.status = "LOADED"
    except urllib.error.HTTPError as exc:
        result.http_status = exc.code
        result.final_url = exc.geturl() or url
        body = exc.read(8192).decode("utf-8", errors="ignore").lower() if exc.fp else ""
        matched_block = [kw for kw in BLOCK_KEYWORDS if kw in body]
        if matched_block or exc.code in (403, 451):
            result.status = "BLOCKED"
            result.matched_keywords = matched_block or [f"http_{exc.code}"]
        else:
            # Ex: 401/405/429 em endpoints de apps ainda indica que o servidor respondeu (não bloqueado por DNS)
            result.status = "LOADED"
    except ssl.SSLCertVerificationError as exc:
        result.status = "BLOCKED"
        result.error = f"SSL certificate mismatch/block: {exc}"
        result.matched_keywords = ["ssl_cert_error"]
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result.status = "ERROR"
        result.error = str(exc)

    return result


# ==============================================================================
# PARSING DE UI AUTOMATOR E CLASSIFICAÇÃO DE PRIVATE DNS
# ==============================================================================


_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def parse_bounds(bounds_str: str) -> Tuple[int, int, int, int]:
    match = _BOUNDS_RE.search(bounds_str or "")
    if not match:
        return (0, 0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4)))


def parse_ui_nodes(xml_content: str) -> List[UINode]:
    """Extrai nós relevantes de um dump XML do uiautomator."""
    if not xml_content or "<hierarchy" not in xml_content:
        return []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return []

    nodes: List[UINode] = []
    for elem in root.iter("node"):
        checked_raw = elem.attrib.get("checked")
        checked: Optional[bool]
        if checked_raw == "true":
            checked = True
        elif checked_raw == "false":
            checked = False
        else:
            checked = None

        nodes.append(
            UINode(
                text=elem.attrib.get("text", ""),
                content_desc=elem.attrib.get("content-desc", ""),
                resource_id=elem.attrib.get("resource-id", ""),
                class_name=elem.attrib.get("class", ""),
                checked=checked,
                clickable=elem.attrib.get("clickable", "false") == "true",
                bounds=parse_bounds(elem.attrib.get("bounds", "")),
            )
        )
    return nodes


def find_node_by_labels(nodes: Sequence[UINode], labels: Sequence[str]) -> Optional[UINode]:
    lowered = [lbl.lower() for lbl in labels]
    for node in nodes:
        txt = node.label.lower()
        if any(lbl in txt for lbl in lowered):
            return node
    return None


def parse_connectivity_dns(dumpsys_output: str) -> Tuple[List[str], List[str]]:
    """Extrai servidores DNS ativos e servidores Private DNS validados de `dumpsys connectivity`."""
    dns_servers: List[str] = []
    validated_private: List[str] = []

    for line in dumpsys_output.splitlines():
        dns_match = re.search(r"DnsAddresses:\s*\[([^\]]*)\]", line)
        if dns_match:
            found = re.findall(r"/([0-9a-fA-F:\.]+)", dns_match.group(1))
            for ip in found:
                if ("." in ip or ":" in ip) and ip not in dns_servers:
                    dns_servers.append(ip)
        if "ValidatedPrivateDns" in line or "PrivateDns" in line:
            ips_or_hosts = re.findall(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line)
            for item in ips_or_hosts:
                if item not in validated_private:
                    validated_private.append(item)

    return dns_servers, validated_private


def analyze_chrome_secure_dns_nodes(nodes: Sequence[UINode]) -> Tuple[str, str]:
    """Analisa os nós da tela de configurações de Segurança / DNS Seguro do Chrome."""
    if not nodes:
        return "unknown", ""

    all_labels = [n.label for n in nodes if n.label]
    joined_lower = " | ".join(all_labels).lower()

    switch_checked: Optional[bool] = None
    for idx, node in enumerate(nodes):
        cls_low = node.class_name.lower()
        if "switch" in cls_low or "checkbox" in cls_low:
            window = nodes[max(0, idx - 4) : min(len(nodes), idx + 4)]
            if any(any(lbl in w.label.lower() for lbl in CHROME_SECURE_DNS_LABELS) for w in window):
                switch_checked = node.checked
                break

    if switch_checked is False:
        return "off", "Disabled in Chrome settings"

    for idx, node in enumerate(nodes):
        lbl_low = node.label.lower()
        if node.checked is True:
            if any(h in lbl_low for h in CHROME_CUSTOM_PROVIDER_HINTS):
                nearby = " ".join(n.label for n in nodes[idx : min(len(nodes), idx + 4)] if n.label)
                return "custom_provider", nearby
            if any(h in lbl_low for h in CHROME_CURRENT_PROVIDER_HINTS):
                return "current_provider", node.label

    for hint in CHROME_CUSTOM_PROVIDER_HINTS:
        if hint in joined_lower and ("https://" in joined_lower or "cloudflare" in joined_lower or "google" in joined_lower or "quad9" in joined_lower):
            if switch_checked is True:
                return "custom_provider", hint

    if switch_checked is True:
        return "current_provider", "Enabled (current service provider / automatic)"

    return "unknown", ""


def evaluate_bypass_risk(
    android_mode: str,
    android_specifier: str,
    chrome_state: str,
) -> Tuple[str, str]:
    """Classifica o risco de bypass das políticas DNS/Whalebone."""
    mode = (android_mode or "unknown").strip().lower()
    spec = (android_specifier or "").strip()

    reasons: List[str] = []
    risk = "SAFE"

    if mode == "hostname":
        risk = "BYPASS_DETECTED"
        reasons.append(f"Android Private DNS ativo em modo estrito ('hostname': {spec or 'não especificado'})")
    elif mode in ("opportunistic", "null", ""):
        if risk != "BYPASS_DETECTED":
            risk = "WARNING"
        reasons.append(f"Android Private DNS em modo '{mode or 'null'}' (Automático - pode usar DoT se suportado)")
    elif mode == "off":
        reasons.append("Android Private DNS desativado ('off')")
    else:
        if risk == "SAFE":
            risk = "UNKNOWN"
        reasons.append(f"Android Private DNS em estado desconhecido ('{mode}')")

    if chrome_state == "custom_provider":
        risk = "BYPASS_DETECTED"
        reasons.append("Chrome Secure DNS (DoH) configurado com provedor personalizado")
    elif chrome_state == "current_provider":
        if risk == "SAFE":
            risk = "WARNING"
        reasons.append("Chrome Secure DNS ativado com provedor atual (pode usar DoH)")
    elif chrome_state == "off":
        reasons.append("Chrome Secure DNS desativado")
    else:
        reasons.append("Chrome Secure DNS não confirmado")

    return risk, "; ".join(reasons)


# ==============================================================================
# GERAÇÃO DE EVIDÊNCIA VISUAL (BANNER / FALLBACK CARD)
# ==============================================================================


def annotate_screenshot_with_banner(
    png_path: Path,
    title: str,
    subtitle: str,
    status: str,
    bypass_risk: str,
) -> None:
    """Adiciona um banner informativo no topo do screenshot se Pillow estiver disponível."""
    if not HAS_PILLOW or not png_path.is_file():
        return

    color_map = {
        "BLOCKED": (180, 35, 35),
        "ERROR": (190, 90, 20),
        "ALLOWED": (28, 125, 55),
        "LOADED": (28, 125, 55),
        "NOT_INSTALLED": (95, 95, 110),
        "UNKNOWN": (70, 80, 95),
    }
    bg_color = color_map.get(status, (70, 80, 95))
    banner_h = 110

    with Image.open(png_path) as img:
        img = img.convert("RGB")
        canvas = Image.new("RGB", (img.width, img.height + banner_h), bg_color)
        canvas.paste(img, (0, banner_h))
        draw = ImageDraw.Draw(canvas)
        font = ImageFont.load_default()
        draw.text((20, 14), f"[{status}] {title}", fill=(255, 255, 255), font=font)
        draw.text((20, 44), subtitle, fill=(240, 240, 240), font=font)
        draw.text((20, 74), f"Private DNS / Bypass Risk: {bypass_risk}", fill=(255, 230, 150), font=font)
        canvas.save(png_path)


def render_evidence_card(
    png_path: Path,
    title: str,
    status: str,
    bypass_risk: str,
    lines: Sequence[str],
) -> bool:
    """Gera um cartão PNG de evidência quando `screencap` não tem permissão no Termux."""
    if not HAS_PILLOW:
        return False

    png_path.parent.mkdir(parents=True, exist_ok=True)
    color_map = {
        "BLOCKED": (180, 35, 35),
        "ERROR": (190, 90, 20),
        "ALLOWED": (28, 125, 55),
        "LOADED": (28, 125, 55),
        "NOT_INSTALLED": (95, 95, 110),
        "UNKNOWN": (70, 80, 95),
    }
    header_bg = color_map.get(status, (70, 80, 95))
    width, height = 1080, 960

    canvas = Image.new("RGB", (width, height), (22, 26, 34))
    draw = ImageDraw.Draw(canvas)
    font = ImageFont.load_default()

    draw.rectangle([0, 0, width, 150], fill=header_bg)
    draw.text((32, 28), f"[{status}] {title}", fill=(255, 255, 255), font=font)
    draw.text((32, 68), f"Private DNS Bypass Risk: {bypass_risk}", fill=(255, 235, 160), font=font)
    draw.text((32, 104), "Modo: Termux Evidence Card (screencap sem permissao shell/root)", fill=(230, 230, 230), font=font)

    y = 195
    for line in lines:
        draw.text((36, y), str(line)[:110], fill=(220, 228, 240), font=font)
        y += 38

    canvas.save(png_path)
    return True


# ==============================================================================
# AUDITORIA DE PRIVATE DNS (ANDROID + CHROME)
# ==============================================================================


def check_android_private_dns(
    backend: AndroidBackend,
    output_dir: Path,
    check_ui: bool = True,
    logger: Optional[logging.Logger] = None,
) -> PrivateDNSStatus:
    """Verifica o estado de Private DNS no Android e no Google Chrome."""
    log = logger or logging.getLogger(__name__)
    status = PrivateDNSStatus()

    mode_res = backend.shell(["settings", "get", "global", "private_dns_mode"], timeout=8)
    spec_res = backend.shell(["settings", "get", "global", "private_dns_specifier"], timeout=8)
    if mode_res.returncode == 0 and mode_res.stdout.strip():
        status.android_mode = mode_res.stdout.strip()
    if spec_res.returncode == 0:
        raw_spec = spec_res.stdout.strip()
        status.android_specifier = "" if raw_spec in ("null", "None") else raw_spec

    # Fallback via getprop net.dns* (funciona mesmo em Termux sem permissões elevadas)
    for prop in ("net.dns1", "net.dns2"):
        p_res = backend.shell(["getprop", prop], timeout=4)
        ip = (p_res.stdout or "").strip()
        if ip and ip not in status.active_dns_servers:
            status.active_dns_servers.append(ip)

    conn_res = backend.shell(["dumpsys", "connectivity"], timeout=12)
    if conn_res.returncode == 0 and conn_res.stdout:
        dns_list, priv_list = parse_connectivity_dns(conn_res.stdout)
        for ip in dns_list:
            if ip not in status.active_dns_servers:
                status.active_dns_servers.append(ip)
        status.validated_private_dns_servers = priv_list

    log.info(
        "Android Private DNS: mode=%s specifier=%s active_dns=%s",
        status.android_mode,
        status.android_specifier or "-",
        status.active_dns_servers,
    )

    if check_ui:
        backend.shell(["am", "start", "-a", "android.settings.WIRELESS_SETTINGS"], timeout=8)
        time.sleep(2.5)
        android_png = output_dir / "screenshots" / "00_android_private_dns_settings.png"
        if backend.screencap(android_png):
            status.android_settings_screenshot = str(android_png)

        chrome_state, chrome_provider, chrome_png = inspect_chrome_secure_dns_ui(
            backend, output_dir / "screenshots" / "00_chrome_secure_dns.png", log
        )
        status.chrome_secure_dns_state = chrome_state
        status.chrome_secure_dns_provider = chrome_provider
        status.chrome_settings_screenshot = chrome_png

    status.bypass_risk, status.details = evaluate_bypass_risk(
        status.android_mode,
        status.android_specifier,
        status.chrome_secure_dns_state,
    )
    log.info("Private DNS Bypass Risk: %s (%s)", status.bypass_risk, status.details)
    return status


def inspect_chrome_secure_dns_ui(
    backend: AndroidBackend,
    screenshot_path: Path,
    log: logging.Logger,
) -> Tuple[str, str, str]:
    """Abre o Chrome e tenta inspecionar a configuração de DNS Seguro via `uiautomator dump`."""
    backend.shell(["am", "start", "-n", f"{CHROME_PACKAGE}/{CHROME_ACTIVITY}"], timeout=10)
    time.sleep(3)

    xml = backend.dump_ui_xml()
    nodes = parse_ui_nodes(xml)

    url_bar = next(
        (n for n in nodes if "url_bar" in n.resource_id or "search_box_text" in n.resource_id),
        None,
    )

    if url_bar:
        cx, cy = url_bar.center
        backend.tap(cx, cy)
        time.sleep(1)
        backend.input_text("chrome://settings/security")
        backend.keyevent("KEYCODE_ENTER")
        time.sleep(2.5)
        xml = backend.dump_ui_xml()
        nodes = parse_ui_nodes(xml)
    else:
        menu_btn = find_node_by_labels(nodes, ["more options", "mais opções", "mais opcoes"])
        if menu_btn:
            backend.tap(*menu_btn.center)
            time.sleep(1.5)
            nodes = parse_ui_nodes(backend.dump_ui_xml())
            settings_item = find_node_by_labels(nodes, CHROME_SETTINGS_LABELS)
            if settings_item:
                backend.tap(*settings_item.center)
                time.sleep(2)
                nodes = parse_ui_nodes(backend.dump_ui_xml())
                priv_item = find_node_by_labels(nodes, CHROME_PRIVACY_LABELS)
                if priv_item:
                    backend.tap(*priv_item.center)
                    time.sleep(2)
                    nodes = parse_ui_nodes(backend.dump_ui_xml())

    dns_node = find_node_by_labels(nodes, CHROME_SECURE_DNS_LABELS)
    if not dns_node and nodes:
        backend.swipe(500, 1400, 500, 600, 350)
        time.sleep(1.2)
        nodes = parse_ui_nodes(backend.dump_ui_xml())
        dns_node = find_node_by_labels(nodes, CHROME_SECURE_DNS_LABELS)

    if dns_node:
        backend.tap(*dns_node.center)
        time.sleep(2)
        nodes = parse_ui_nodes(backend.dump_ui_xml())

    state, provider = analyze_chrome_secure_dns_nodes(nodes)
    saved_png = str(screenshot_path) if backend.screencap(screenshot_path) else ""
    log.info("Chrome Secure DNS UI: state=%s provider=%s", state, provider or "-")
    return state, provider, saved_png


# ==============================================================================
# NAVEGAÇÃO EM APLICATIVOS (REDDIT, INSTAGRAM, NETFLIX, ETC.)
# ==============================================================================


def get_installed_packages(backend: AndroidBackend) -> set[str]:
    res = backend.shell(["pm", "list", "packages"], timeout=15)
    pkgs: set[str] = set()
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.add(line.split("package:", 1)[1].strip())
    return pkgs


def get_foreground_package(backend: AndroidBackend) -> str:
    res = backend.shell(["dumpsys", "activity", "activities"], timeout=10)
    for line in res.stdout.splitlines():
        if "mResumedActivity" in line or "topResumedActivity" in line:
            m = re.search(r"([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)/", line)
            if m:
                return m.group(1)
    return ""


def navigate_apps(
    backend: AndroidBackend,
    apps: Sequence[Dict[str, object]],
    output_dir: Path,
    private_dns: Optional[PrivateDNSStatus] = None,
    wait_sec: int = 5,
    simulate_scroll: bool = True,
    logger: Optional[logging.Logger] = None,
) -> List[AppTestResult]:
    """
    Lança os aplicativos (por padrão Reddit, Instagram, Netflix), interage como um
    utilizador, confirma se carregaram ou foram bloqueados e captura printscreen.
    """
    log = logger or logging.getLogger(__name__)
    installed_pkgs = get_installed_packages(backend)
    results: List[AppTestResult] = []
    bypass_risk = private_dns.bypass_risk if private_dns else "UNKNOWN"

    for idx, app in enumerate(apps, start=1):
        name = str(app.get("name", app["package"]))
        pkg = str(app["package"])
        probe_urls = list(app.get("probe_urls") or [])
        t0 = time.monotonic()

        # Sondagem de conectividade do serviço do aplicativo (DNS + HTTPS)
        probe = probe_endpoint_connectivity(probe_urls[0]) if probe_urls else EndpointProbeResult(url="")

        # Se `pm list packages` falhou por restrição do Termux, ainda tentamos lançar via `monkey`/`am`
        known_missing = bool(installed_pkgs) and (pkg not in installed_pkgs)
        if known_missing:
            log.warning("App não instalado: %s (%s) | Probe rede: %s", name, pkg, probe.status)
            safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", name.lower()).strip("_")
            png_path = output_dir / "screenshots" / f"app_{idx:02d}_{safe_name}.png"
            render_evidence_card(
                png_path,
                title=f"App {name} ({pkg})",
                status="NOT_INSTALLED",
                bypass_risk=bypass_risk,
                lines=[
                    f"Pacote: {pkg} (nao instalado no aparelho)",
                    f"Sondagem de dominio: {probe.url or '-'} -> {probe.status}",
                    f"IPs resolvidos: {', '.join(probe.resolved_ips) or '-'}",
                    f"HTTP status: {probe.http_status or '-'} | Erro: {probe.error or '-'}",
                ],
            )
            results.append(
                AppTestResult(
                    app_name=name,
                    package=pkg,
                    installed=False,
                    launched=False,
                    foreground_verified=False,
                    load_status="NOT_INSTALLED" if probe.status != "BLOCKED" else "BLOCKED",
                    resolved_ips=probe.resolved_ips,
                    http_status=probe.http_status,
                    duration_ms=int((time.monotonic() - t0) * 1000),
                    screenshot_path=str(png_path) if png_path.is_file() else "",
                    notes=f"Pacote não instalado; probe={probe.status}",
                )
            )
            continue

        backend.keyevent("KEYCODE_HOME")
        time.sleep(1)

        launch_res = backend.shell(
            ["monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout=10,
        )
        launched = launch_res.returncode == 0
        if not launched and probe_urls:
            # Fallback em Termux: abrir URL do serviço no app/navegador via `am start`
            am_res = backend.shell(["am", "start", "-a", "android.intent.action.VIEW", "-d", probe_urls[0]], timeout=10)
            launched = am_res.returncode == 0

        time.sleep(wait_sec)

        if simulate_scroll:
            backend.swipe(540, 1450, 540, 750, 400)
            time.sleep(1.5)

        fg_pkg = get_foreground_package(backend)
        fg_ok = fg_pkg == pkg

        # Verifica texto na tela via uiautomator quando disponível
        ui_nodes = parse_ui_nodes(backend.dump_ui_xml())
        ui_status, ui_kw, _ = classify_chrome_screen_text(ui_nodes)

        # Consolida veredito: LOADED vs BLOCKED vs ERROR
        if probe.status == "BLOCKED" or ui_status == "BLOCKED":
            load_status = "BLOCKED"
        elif probe.status == "ERROR" or ui_status == "ERROR":
            load_status = "ERROR"
        elif probe.status == "LOADED" or (launched and ui_status == "ALLOWED"):
            load_status = "LOADED"
        elif launched:
            load_status = "LOADED"
        else:
            load_status = "ERROR"

        safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", name.lower()).strip("_")
        png_path = output_dir / "screenshots" / f"app_{idx:02d}_{safe_name}.png"
        has_png = backend.screencap(png_path)
        if has_png:
            annotate_screenshot_with_banner(
                png_path,
                title=f"App: {name} ({pkg})",
                subtitle=f"IPs: {', '.join(probe.resolved_ips) or '-'} | HTTP: {probe.http_status or '-'}",
                status=load_status,
                bypass_risk=bypass_risk,
            )
        else:
            has_png = render_evidence_card(
                png_path,
                title=f"App {name} ({pkg})",
                status=load_status,
                bypass_risk=bypass_risk,
                lines=[
                    f"Pacote: {pkg} | Launched: {launched} | Foreground: {fg_pkg or '-'}",
                    f"URL sondada: {probe.url or '-'}",
                    f"IPs resolvidos: {', '.join(probe.resolved_ips) or '-'}",
                    f"HTTP status: {probe.http_status or '-'} | Keywords: {', '.join(ui_kw or probe.matched_keywords) or 'none'}",
                    f"Erro: {probe.error or '-'}",
                ],
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        log.info(
            "App %s (%s): status=%s launched=%s fg=%s http=%s ips=%s png=%s",
            name,
            pkg,
            load_status,
            launched,
            fg_ok,
            probe.http_status,
            probe.resolved_ips,
            png_path.name if has_png else "FAILED",
        )

        results.append(
            AppTestResult(
                app_name=name,
                package=pkg,
                installed=True,
                launched=launched,
                foreground_verified=fg_ok,
                load_status=load_status,
                resolved_ips=probe.resolved_ips,
                http_status=probe.http_status,
                duration_ms=duration_ms,
                screenshot_path=str(png_path) if has_png else "",
                notes=f"Foreground={fg_pkg or '-'}; probe={probe.status}; kw={','.join(ui_kw or probe.matched_keywords) or 'none'}",
            )
        )

    return results


# ==============================================================================
# NAVEGAÇÃO NO GOOGLE CHROME (URLS DE TESTE)
# ==============================================================================


def classify_chrome_screen_text(nodes: Sequence[UINode]) -> Tuple[str, List[str], str]:
    """Classifica o conteúdo visível no ecrã como BLOCKED, ERROR, ALLOWED ou UNKNOWN."""
    texts = [n.label for n in nodes if n.label]
    if not texts:
        return "UNKNOWN", [], ""

    joined = " | ".join(texts)
    lower = joined.lower()

    matched_block = [kw for kw in BLOCK_KEYWORDS if kw in lower]
    matched_err = [kw for kw in ERROR_KEYWORDS if kw in lower]

    snippet = joined[:240]
    if matched_block:
        return "BLOCKED", matched_block, snippet
    if matched_err:
        return "ERROR", matched_err, snippet
    return "ALLOWED", [], snippet


def navigate_chrome_urls(
    backend: AndroidBackend,
    urls: Sequence[str],
    output_dir: Path,
    private_dns: PrivateDNSStatus,
    page_wait: int = 6,
    input_method: str = "intent",
    add_banner: bool = True,
    save_ui_dumps: bool = True,
    logger: Optional[logging.Logger] = None,
) -> List[ChromeURLResult]:
    """Abre cada URL no Google Chrome do Android, confirma bloqueio/carregamento e captura printscreen."""
    log = logger or logging.getLogger(__name__)
    results: List[ChromeURLResult] = []

    for idx, url in enumerate(urls, start=1):
        t0 = time.monotonic()
        opened = False

        if input_method == "omnibox":
            backend.shell(["am", "start", "-n", f"{CHROME_PACKAGE}/{CHROME_ACTIVITY}"], timeout=8)
            time.sleep(2)
            nodes = parse_ui_nodes(backend.dump_ui_xml())
            url_bar = next(
                (n for n in nodes if "url_bar" in n.resource_id or "search_box_text" in n.resource_id),
                None,
            )
            if url_bar:
                backend.tap(*url_bar.center)
                time.sleep(0.8)
                backend.input_text(url)
                backend.keyevent("KEYCODE_ENTER")
                opened = True

        if not opened:
            res = backend.shell(
                [
                    "am",
                    "start",
                    "-a",
                    "android.intent.action.VIEW",
                    "-n",
                    f"{CHROME_PACKAGE}/{CHROME_ACTIVITY}",
                    "-d",
                    url,
                ],
                timeout=10,
            )
            opened = res.returncode == 0

        time.sleep(page_wait)

        xml = backend.dump_ui_xml()
        nodes = parse_ui_nodes(xml)
        ui_status, matched_kw, snippet = classify_chrome_screen_text(nodes)
        probe = probe_endpoint_connectivity(url)

        if ui_status in ("BLOCKED", "ERROR"):
            detected_status = ui_status
        elif probe.status == "BLOCKED":
            detected_status = "BLOCKED"
            matched_kw = matched_kw or probe.matched_keywords
        elif probe.status == "ERROR" and ui_status == "UNKNOWN":
            detected_status = "ERROR"
        elif ui_status == "ALLOWED" or probe.status == "LOADED":
            detected_status = "ALLOWED"
        else:
            detected_status = "UNKNOWN"

        safe_host = re.sub(r"[^a-zA-Z0-9.-]+", "_", url.replace("https://", "").replace("http://", ""))[:50]
        png_path = output_dir / "screenshots" / f"chrome_{idx:02d}_{safe_host}.png"
        has_png = backend.screencap(png_path)

        if has_png and add_banner:
            annotate_screenshot_with_banner(
                png_path,
                title=url,
                subtitle=f"Chrome Android | IPs: {', '.join(probe.resolved_ips) or '-'} | Keywords: {', '.join(matched_kw) or 'none'}",
                status=detected_status,
                bypass_risk=private_dns.bypass_risk,
            )
        elif not has_png:
            has_png = render_evidence_card(
                png_path,
                title=url,
                status=detected_status,
                bypass_risk=private_dns.bypass_risk,
                lines=[
                    f"Chrome Intent opened: {opened}",
                    f"IPs resolvidos: {', '.join(probe.resolved_ips) or '-'}",
                    f"HTTP status: {probe.http_status or '-'} | Final URL: {probe.final_url or '-'}",
                    f"Keywords: {', '.join(matched_kw) or 'none'}",
                    f"Erro: {probe.error or '-'}",
                ],
            )

        if save_ui_dumps and xml:
            dump_path = output_dir / "ui_dumps" / f"chrome_{idx:02d}_{safe_host}.xml"
            dump_path.parent.mkdir(parents=True, exist_ok=True)
            dump_path.write_text(xml, encoding="utf-8")

        duration_ms = int((time.monotonic() - t0) * 1000)
        log.info(
            "Chrome URL %s -> %s (http=%s, ips=%s, %dms, png=%s)",
            url,
            detected_status,
            probe.http_status,
            probe.resolved_ips,
            duration_ms,
            png_path.name if has_png else "FAILED",
        )

        results.append(
            ChromeURLResult(
                url=url,
                opened=opened,
                detected_status=detected_status,
                matched_keywords=matched_kw,
                resolved_ips=probe.resolved_ips,
                http_status=probe.http_status,
                page_snippet=snippet,
                duration_ms=duration_ms,
                screenshot_path=str(png_path) if has_png else "",
                bypass_risk=private_dns.bypass_risk,
                notes=probe.error,
            )
        )

    return results


# ==============================================================================
# RELATÓRIOS
# ==============================================================================


def write_reports(
    output_dir: Path,
    device: DeviceInfo,
    private_dns: PrivateDNSStatus,
    app_results: Sequence[AppTestResult],
    chrome_results: Sequence[ChromeURLResult],
) -> Tuple[Path, Path]:
    """Gera `report.json` e `report.csv` consolidados."""
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "report.json"
    payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device": asdict(device),
        "private_dns": asdict(private_dns),
        "apps": [asdict(a) for a in app_results],
        "chrome_urls": [asdict(c) for c in chrome_results],
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    csv_path = output_dir / "report.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "category",
                "target",
                "status",
                "bypass_risk",
                "duration_ms",
                "screenshot_path",
                "details",
            ]
        )
        writer.writerow(
            [
                "private_dns",
                f"android={private_dns.android_mode};chrome={private_dns.chrome_secure_dns_state}",
                private_dns.bypass_risk,
                private_dns.bypass_risk,
                0,
                private_dns.chrome_settings_screenshot or private_dns.android_settings_screenshot,
                private_dns.details,
            ]
        )
        for app in app_results:
            writer.writerow(
                [
                    "app",
                    f"{app.app_name} ({app.package})",
                    app.load_status,
                    private_dns.bypass_risk,
                    app.duration_ms,
                    app.screenshot_path,
                    app.notes,
                ]
            )
        for cr in chrome_results:
            writer.writerow(
                [
                    "chrome_url",
                    cr.url,
                    cr.detected_status,
                    cr.bypass_risk,
                    cr.duration_ms,
                    cr.screenshot_path,
                    ",".join(cr.matched_keywords) or cr.notes or cr.page_snippet[:120],
                ]
            )

    return json_path, csv_path


# ==============================================================================
# CLI / MAIN
# ==============================================================================


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validação de políticas DNS/Whalebone no Android (Termux nativo ou ADB)."
    )
    parser.add_argument("--env-file", help="Caminho para arquivo .env customizado (padrão: .env.android ou .env).")
    parser.add_argument("--backend", choices=["auto", "termux", "adb"], help="Backend de execução no Android.")
    parser.add_argument("--serial", help="Serial do dispositivo ADB (quando --backend adb).")
    parser.add_argument("--urls", nargs="+", help="URLs para testar no Chrome.")
    parser.add_argument(
        "--apps",
        nargs="+",
        help="Apps a testar (ex: reddit instagram netflix ou package names).",
    )
    parser.add_argument("--skip-apps", action="store_true", help="Não executa navegação nos aplicativos.")
    parser.add_argument("--skip-chrome", action="store_true", help="Não executa navegação nas URLs do Chrome.")
    parser.add_argument(
        "--skip-private-dns-ui",
        action="store_true",
        help="Verifica Private DNS apenas via settings/dumpsys/getprop sem navegar na UI.",
    )
    parser.add_argument("--page-wait", type=int, help="Tempo de espera (s) após abrir URL no Chrome.")
    parser.add_argument("--app-wait", type=int, help="Tempo de espera (s) após abrir cada aplicativo.")
    parser.add_argument(
        "--chrome-input-method",
        choices=["intent", "omnibox"],
        default="intent",
        help="Modo de abertura de URL no Chrome (intent VIEW ou digitação na omnibox).",
    )
    parser.add_argument("--no-scroll", action="store_true", help="Desativa scroll simulado dentro dos apps.")
    parser.add_argument("--no-banner", action="store_true", help="Não adiciona banner nos printscreens.")
    parser.add_argument("--output-dir", help="Diretório de saída dos resultados.")
    parser.add_argument("--run-tests", action="store_true", help="Executa toda a suíte de testes (`tests/`).")
    return parser.parse_args(argv)


def setup_logger(output_dir: Path) -> logging.Logger:
    output_dir.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("android_whalebone_check")
    log.setLevel(logging.INFO)
    log.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = logging.FileHandler(output_dir / "run.log", encoding="utf-8")
    fh.setFormatter(fmt)

    log.addHandler(sh)
    log.addHandler(fh)
    return log


def run_test_suite() -> int:
    tests_dir = Path(__file__).resolve().parent / "tests"
    suite = unittest.defaultTestLoader.discover(start_dir=str(tests_dir))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.run_tests:
        return run_test_suite()

    env_cfg = load_android_env(args.env_file)
    backend_mode = args.backend or env_cfg.backend
    app_tokens = args.apps or env_cfg.apps
    urls = args.urls or env_cfg.urls
    app_wait = args.app_wait if args.app_wait is not None else env_cfg.app_wait
    page_wait = args.page_wait if args.page_wait is not None else env_cfg.page_wait
    simulate_scroll = env_cfg.simulate_scroll and (not args.no_scroll)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_out = args.output_dir or env_cfg.output_dir
    output_dir = Path(raw_out).expanduser() if raw_out else Path(f"android_results_{ts}")
    log = setup_logger(output_dir)

    backend = create_backend(mode=backend_mode, serial=args.serial)
    if isinstance(backend, ADBClient):
        if not backend.is_available():
            log.error("Binário 'adb' não encontrado e modo Termux não selecionado.")
            return 1
        devices = backend.list_devices()
        if not devices:
            log.error("Nenhum dispositivo Android conectado/autorizado via ADB.")
            return 1
        if not backend.serial:
            backend.serial = devices[0]
    elif not backend.is_available():
        log.error("Ambiente Android/Termux não detetado.")
        return 1

    device = backend.get_device_info()
    log.info(
        "Dispositivo (%s): %s | Android %s (SDK %s)",
        device.execution_mode,
        device.model,
        device.android_version,
        device.sdk,
    )

    if env_cfg.check_private_dns:
        private_dns = check_android_private_dns(
            backend,
            output_dir=output_dir,
            check_ui=not args.skip_private_dns_ui,
            logger=log,
        )
    else:
        private_dns = PrivateDNSStatus(bypass_risk="UNKNOWN", details="Verificação desativada no .env")

    app_results: List[AppTestResult] = []
    if not args.skip_apps:
        apps = resolve_app_targets(app_tokens)
        app_results = navigate_apps(
            backend,
            apps=apps,
            output_dir=output_dir,
            private_dns=private_dns,
            wait_sec=app_wait,
            simulate_scroll=simulate_scroll,
            logger=log,
        )

    chrome_results: List[ChromeURLResult] = []
    if env_cfg.check_chrome and not args.skip_chrome:
        chrome_results = navigate_chrome_urls(
            backend,
            urls=urls,
            output_dir=output_dir,
            private_dns=private_dns,
            page_wait=page_wait,
            input_method=args.chrome_input_method,
            add_banner=not args.no_banner,
            logger=log,
        )

    json_path, csv_path = write_reports(output_dir, device, private_dns, app_results, chrome_results)
    log.info("Relatórios gerados: %s e %s", json_path, csv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
