#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "Pillow>=10.3.0",
# ]
# ///
"""
Kobiton Whalebone Check - Automação via Kobiton (Appium W3C WebDriver).

Executa no Kobiton todas as ações do `android_whalebone_check.py`, acrescidas do
fluxo de gestão de Dual SIM, Modo Avião e teste de conectividade DNS:
1. Verifica o estado inicial de SIM1 e SIM2 (e Modo Avião).
2. Garante que o SIM1 esteja ativo e o SIM2 desativado.
3. Ativa o Modo Avião e testa a conectividade para o(s) servidor(es) DNS destino.
4. Audita Private DNS (Android OS) e Secure DNS (Google Chrome).
5. Navega nos aplicativos configurados (Reddit, Instagram, Netflix, etc.) e nas
   URLs de teste no Chrome, capturando evidências e gerando relatórios.
6. Ao final (sempre, em bloco `finally`), restaura SIM1/SIM2 (e Modo Avião)
   ao estado inicial observado antes dos testes.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime
import html
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import android_whalebone_check as awc

# ==============================================================================
# CONSTANTES KOBITON / SIM / MODO AVIÃO
# ==============================================================================

DEFAULT_KOBITON_SERVER_URL = "https://api.kobiton.com/wd/hub"
DEFAULT_KOBITON_API_URL = "https://api.kobiton.com/v1"
DEFAULT_DNS_SERVERS: List[str] = ["10.36.41.114", "8.8.8.8"]
DEFAULT_BLOCK_IPS: List[str] = ["10.36.41.115"]
APN_CHECK_SCHEDULE_SECONDS: Tuple[int, ...] = (5, 15, 45, 120, 300)
PAGE_WAIT_SCHEDULE_SECONDS: Tuple[int, ...] = (5, 15, 30, 60, 120)

SIM_SETTINGS_ACTIONS = (
    "android.settings.SIM_SETTINGS",
    "android.settings.WIRELESS_SETTINGS",
    "android.settings.NETWORK_OPERATOR_SETTINGS",
    "android.settings.SETTINGS",
)

AIRPLANE_SETTINGS_ACTIONS = (
    "android.settings.AIRPLANE_MODE_SETTINGS",
    "android.settings.WIRELESS_SETTINGS",
    "android.settings.SETTINGS",
)

SIM_MENU_LABELS = (
    "sim manager",
    "gestor de sim",
    "gerenciador de sim",
    "gerenciador de cartões sim",
    "cartões sim e redes móveis",
    "cartoes sim e redes moveis",
    "sim cards",
    "cartões sim",
    "cartoes sim",
    "dual sim",
    "sims",
    "network & internet",
    "rede e internet",
    "connections",
    "conexões",
    "conexoes",
)

AIRPLANE_LABELS = (
    "airplane mode",
    "modo avião",
    "modo aviao",
    "modo de voo",
    "flight mode",
)

CONFIRM_POSITIVE_LABELS = (
    "turn on",
    "turn off",
    "ativar",
    "desativar",
    "ok",
    "confirm",
    "confirmar",
    "yes",
    "sim",
)

KEYCODE_MAP: Dict[str, int] = {
    "KEYCODE_HOME": 3,
    "KEYCODE_BACK": 4,
    "KEYCODE_ENTER": 66,
    "KEYCODE_DEL": 67,
    "KEYCODE_TAB": 61,
    "KEYCODE_SPACE": 62,
}


# ==============================================================================
# MODELOS DE DADOS
# ==============================================================================


@dataclass
class KobitonEnvConfig:
    username: str = ""
    api_key: str = ""
    server_url: str = DEFAULT_KOBITON_SERVER_URL
    api_url: str = DEFAULT_KOBITON_API_URL
    udid: str = ""
    udids: List[str] = field(default_factory=list)
    target_msisdn: str = ""
    device_name: str = ""
    platform_version: str = ""
    device_group: str = "KOBITON"
    session_name: str = "Whalebone DNS Check"
    session_description: str = "Automated DNS/Whalebone validation via Kobiton"
    group_id: Optional[int] = None
    dns_servers: List[str] = field(default_factory=lambda: list(DEFAULT_DNS_SERVERS))
    block_ips: List[str] = field(default_factory=lambda: list(DEFAULT_BLOCK_IPS))
    apps: List[str] = field(default_factory=lambda: list(awc.DEFAULT_APP_KEYS))
    urls: List[str] = field(default_factory=lambda: list(awc.DEFAULT_URLS))
    app_wait: int = 5
    page_wait: int = 6
    airplane_wait_on: int = 4
    airplane_wait_off: int = 10
    check_private_dns: bool = True
    check_chrome: bool = True
    simulate_scroll: bool = True
    disable_wifi_during_tests: bool = True
    set_android_dns: bool = False
    output_dir: str = ""
    insecure_ssl: bool = False


@dataclass
class SimInitialState:
    sim1_enabled: Optional[bool] = None
    sim2_enabled: Optional[bool] = None
    sim1_msisdn: str = ""
    sim2_msisdn: str = ""
    sim1_iccid: str = ""
    sim2_iccid: str = ""
    airplane_mode_enabled: Optional[bool] = None
    detection_method: str = "unknown"
    details: str = ""
    screenshot_path: str = ""


@dataclass
class SimActionResult:
    target_slot: int = 1
    sim1_changed: bool = False
    sim2_changed: bool = False
    sim1_final_before_tests: Optional[bool] = None
    sim2_final_before_tests: Optional[bool] = None
    airplane_mode_before_tests: Optional[bool] = None
    restored_successfully: bool = False
    sim1_after_restore: Optional[bool] = None
    sim2_after_restore: Optional[bool] = None
    airplane_after_restore: Optional[bool] = None
    notes: str = ""
    before_tests_screenshot: str = ""
    airplane_screenshot: str = ""
    restored_screenshot: str = ""


@dataclass
class DnsConnectivityResult:
    dns_server: str
    device_ping_ok: Optional[bool] = None
    device_ping_rtt_ms: Optional[float] = None
    device_tcp_53_ok: Optional[bool] = None
    device_dns_ok: Optional[bool] = None
    latency_ms: int = 0
    status: str = "UNKNOWN"
    details: str = ""
    screenshot_path: str = ""


@dataclass
class CellularApnTelemetry:
    sim1_operator: str = ""
    sim1_mcc_mnc: str = ""
    sim_state: str = ""
    network_type: str = ""
    apn_name: str = ""
    interface: str = ""
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    dns_addresses: List[str] = field(default_factory=list)
    dns_match_state: str = ""
    wifi_initially_enabled: Optional[bool] = None
    wifi_disabled_during_tests: bool = False
    wifi_restored: Optional[bool] = None
    raw_summary: str = ""


@dataclass
class TlsCertificateInfo:
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    sha256_fingerprint: str = ""
    verify_result: str = ""
    protocol: str = ""
    cipher: str = ""
    pem: str = ""
    pem_file: str = ""


@dataclass
class NetworkRequestItem:
    url: str
    resource_type: str = "document"
    method: str = "GET"
    status_code: Optional[int] = None
    size_bytes: int = 0
    start_offset_ms: int = 0
    dns_ms: Optional[int] = None
    tcp_ms: Optional[int] = None
    tls_ms: Optional[int] = None
    pretransfer_ms: Optional[int] = None
    redirect_ms: Optional[int] = None
    ttfb_ms: Optional[int] = None
    duration_ms: int = 0
    size_header_bytes: int = 0
    speed_download_bps: Optional[float] = None
    num_redirects: int = 0
    http_version: str = ""
    content_type: str = ""
    effective_url: str = ""
    remote_ip: str = ""
    error: str = ""


@dataclass
class WaterfallEntry:
    category: str
    target: str
    status: str = "UNKNOWN"
    dns_server_used: List[str] = field(default_factory=list)
    dns_rtt_ms: Optional[int] = None
    tcp_rtt_ms: Optional[int] = None
    tls_rtt_ms: Optional[int] = None
    ttfb_ms: Optional[int] = None
    device_ping_rtt_ms: Optional[float] = None
    total_load_ms: int = 0
    http_status: Optional[int] = None
    content_bytes: int = 0
    resolved_ips: List[str] = field(default_factory=list)
    tls_certificate: Optional[TlsCertificateInfo] = None
    network_requests: List[NetworkRequestItem] = field(default_factory=list)
    details: str = ""


# ==============================================================================
# CARREGAMENTO DE CONFIGURAÇÃO (.env.kobiton / .env)
# ==============================================================================


def _parse_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def load_kobiton_env(custom_env_path: Optional[str] = None) -> KobitonEnvConfig:
    """Carrega configurações do Kobiton a partir de `.env.kobiton`, `.env` e variáveis de ambiente."""
    cfg = KobitonEnvConfig()
    candidates: List[Path] = []
    if custom_env_path:
        candidates.append(Path(custom_env_path))
    else:
        candidates.extend([Path(".env.kobiton"), Path(".env.android"), Path(".env")])

    merged: Dict[str, str] = {}
    for p in reversed(candidates):
        merged.update(_parse_env_file(p))
    merged.update(os.environ)

    cfg.username = merged.get("KOBITON_USERNAME", "").strip()
    cfg.api_key = merged.get("KOBITON_API_KEY", "").strip()
    cfg.server_url = merged.get("KOBITON_SERVER_URL", DEFAULT_KOBITON_SERVER_URL).strip() or DEFAULT_KOBITON_SERVER_URL
    cfg.api_url = merged.get("KOBITON_API_URL", DEFAULT_KOBITON_API_URL).strip() or DEFAULT_KOBITON_API_URL
    raw_udid = merged.get("KOBITON_UDID", "").strip()
    raw_udids = merged.get("KOBITON_UDIDS") or merged.get("KOBITON_TARGET_UDIDS") or raw_udid
    if raw_udids.strip():
        cfg.udids = awc._split_list(raw_udids)
        cfg.udid = cfg.udids[0] if cfg.udids else ""
    else:
        cfg.udid = ""
    cfg.target_msisdn = merged.get("KOBITON_TARGET_MSISDN", "").strip()
    cfg.device_name = merged.get("KOBITON_DEVICE_NAME", "").strip()
    cfg.platform_version = merged.get("KOBITON_PLATFORM_VERSION", "").strip()
    cfg.device_group = merged.get("KOBITON_DEVICE_GROUP", "KOBITON").strip() or "KOBITON"
    cfg.session_name = merged.get("KOBITON_SESSION_NAME", "Whalebone DNS Check").strip() or "Whalebone DNS Check"
    cfg.session_description = merged.get("KOBITON_SESSION_DESCRIPTION", cfg.session_description).strip()
    if merged.get("KOBITON_GROUP_ID", "").strip().isdigit():
        cfg.group_id = int(merged["KOBITON_GROUP_ID"].strip())

    raw_dns = merged.get("KOBITON_DNS_SERVERS") or merged.get("DNS_SERVERS") or ""
    if raw_dns.strip():
        cfg.dns_servers = awc._split_list(raw_dns)

    raw_block_ips = merged.get("KOBITON_BLOCK_IPS") or ""
    if raw_block_ips.strip():
        cfg.block_ips = awc._split_list(raw_block_ips)

    raw_apps = merged.get("KOBITON_APPS") or merged.get("ANDROID_APPS") or ""
    if raw_apps.strip():
        cfg.apps = awc._split_list(raw_apps)

    raw_urls = merged.get("KOBITON_URLS") or merged.get("ANDROID_URLS") or merged.get("DOMAINS") or ""
    if raw_urls.strip():
        cfg.urls = awc._split_list(raw_urls)

    if merged.get("KOBITON_APP_WAIT") or merged.get("ANDROID_APP_WAIT"):
        try:
            cfg.app_wait = max(1, int(merged.get("KOBITON_APP_WAIT") or merged.get("ANDROID_APP_WAIT") or "5"))
        except ValueError:
            pass

    if merged.get("KOBITON_PAGE_WAIT") or merged.get("ANDROID_PAGE_WAIT"):
        try:
            cfg.page_wait = max(1, int(merged.get("KOBITON_PAGE_WAIT") or merged.get("ANDROID_PAGE_WAIT") or "6"))
        except ValueError:
            pass

    if merged.get("KOBITON_AIRPLANE_WAIT_ON"):
        try:
            cfg.airplane_wait_on = max(1, int(merged["KOBITON_AIRPLANE_WAIT_ON"]))
        except ValueError:
            pass
    if merged.get("KOBITON_AIRPLANE_WAIT_OFF"):
        try:
            cfg.airplane_wait_off = max(1, int(merged["KOBITON_AIRPLANE_WAIT_OFF"]))
        except ValueError:
            pass

    cfg.check_private_dns = awc._parse_bool(
        merged.get("KOBITON_CHECK_PRIVATE_DNS") or merged.get("ANDROID_CHECK_PRIVATE_DNS") or "true",
        True,
    )
    cfg.check_chrome = awc._parse_bool(
        merged.get("KOBITON_CHECK_CHROME") or merged.get("ANDROID_CHECK_CHROME") or "true",
        True,
    )
    cfg.simulate_scroll = awc._parse_bool(
        merged.get("KOBITON_SIMULATE_SCROLL") or merged.get("ANDROID_SIMULATE_SCROLL") or "true",
        True,
    )
    cfg.disable_wifi_during_tests = awc._parse_bool(merged.get("KOBITON_DISABLE_WIFI_DURING_TESTS", "true"), True)
    cfg.set_android_dns = awc._parse_bool(merged.get("KOBITON_SET_ANDROID_DNS", "false"), False)
    cfg.insecure_ssl = awc._parse_bool(merged.get("KOBITON_INSECURE_SSL", "false"), False)
    cfg.output_dir = (merged.get("KOBITON_OUTPUT_DIR") or merged.get("ANDROID_OUTPUT_DIR") or "").strip()
    return cfg


# ==============================================================================
# CLIENTE WEBDRIVER W3C / KOBITON (ZERO DEPENDÊNCIAS EXTERNAS)
# ==============================================================================


class KobitonWebDriverError(RuntimeError):
    """Erro retornado pela API Kobiton / Appium WebDriver."""


class KobitonClient:
    """Cliente HTTP W3C WebDriver + Kobiton REST API usando apenas stdlib."""

    def __init__(
        self,
        username: str,
        api_key: str,
        server_url: str = DEFAULT_KOBITON_SERVER_URL,
        api_url: str = DEFAULT_KOBITON_API_URL,
        insecure_ssl: bool = False,
        timeout: int = 90,
    ):
        self.username = username
        self.api_key = api_key
        self.server_url = server_url.rstrip("/")
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self.capabilities: Dict[str, Any] = {}

        self._ssl_ctx: Optional[ssl.SSLContext] = None
        if insecure_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._ssl_ctx = ctx

    def _auth_header(self) -> str:
        token = base64.b64encode(f"{self.username}:{self.api_key}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def _request(
        self,
        method: str,
        url: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": self._auth_header(),
        }
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout, context=self._ssl_ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise KobitonWebDriverError(f"HTTP {exc.code} em {method} {url}: {err_body[:400]}") from exc
        except urllib.error.URLError as exc:
            raise KobitonWebDriverError(f"Erro de conexão em {method} {url}: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise KobitonWebDriverError(f"Timeout/Erro de rede em {method} {url}: {exc}") from exc

    def list_devices(self) -> List[Dict[str, Any]]:
        """Lista dispositivos Android disponíveis via Kobiton REST API."""
        data = self._request("GET", f"{self.api_url}/devices")
        devices: List[Dict[str, Any]] = []
        for group_key in ("privateDevices", "favoriteDevices", "cloudDevices"):
            for d in data.get(group_key, []) or []:
                if str(d.get("platformName", "")).lower() == "android":
                    devices.append(d)
        return devices

    def create_session(self, desired_caps: Dict[str, Any]) -> str:
        """Cria uma nova sessão Appium/Kobiton (formato W3C `alwaysMatch`)."""
        payload = {"capabilities": {"alwaysMatch": desired_caps, "firstMatch": [{}]}}
        resp = self._request("POST", f"{self.server_url}/session", payload=payload, timeout=180)
        value = resp.get("value", resp)
        sid = value.get("sessionId") or resp.get("sessionId")
        if not sid:
            raise KobitonWebDriverError(f"Sessão criada sem sessionId: {resp}")
        self.session_id = str(sid)
        self.capabilities = value.get("capabilities") or value
        return self.session_id

    def delete_session(self) -> None:
        if not self.session_id:
            return
        try:
            self._request("DELETE", f"{self.server_url}/session/{self.session_id}", timeout=30)
        finally:
            self.session_id = None

    def _wd(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None) -> Any:
        if not self.session_id:
            raise KobitonWebDriverError("Sessão Kobiton não iniciada.")
        url = f"{self.server_url}/session/{self.session_id}{path}"
        resp = self._request(method, url, payload=payload, timeout=timeout)
        return resp.get("value")

    def execute_mobile(self, script: str, args: Optional[List[Dict[str, Any]]] = None, timeout: Optional[int] = None) -> Any:
        return self._wd("POST", "/execute/sync", {"script": script, "args": args or []}, timeout=timeout)

    def screenshot_png(self) -> bytes:
        b64_data = self._wd("GET", "/screenshot")
        if not isinstance(b64_data, str) or not b64_data:
            raise KobitonWebDriverError("Screenshot vazio retornado pelo Kobiton.")
        return base64.b64decode(b64_data)

    def page_source(self) -> str:
        src = self._wd("GET", "/source")
        return src if isinstance(src, str) else ""

    def tap(self, x: int, y: int) -> None:
        actions = {
            "actions": [
                {
                    "type": "pointer",
                    "id": "finger1",
                    "parameters": {"pointerType": "touch"},
                    "actions": [
                        {"type": "pointerMove", "duration": 0, "x": int(x), "y": int(y)},
                        {"type": "pointerDown", "button": 0},
                        {"type": "pause", "duration": 60},
                        {"type": "pointerUp", "button": 0},
                    ],
                }
            ]
        }
        self._wd("POST", "/actions", actions)

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 350) -> None:
        actions = {
            "actions": [
                {
                    "type": "pointer",
                    "id": "finger1",
                    "parameters": {"pointerType": "touch"},
                    "actions": [
                        {"type": "pointerMove", "duration": 0, "x": int(x1), "y": int(y1)},
                        {"type": "pointerDown", "button": 0},
                        {"type": "pointerMove", "duration": max(100, int(duration_ms)), "x": int(x2), "y": int(y2)},
                        {"type": "pointerUp", "button": 0},
                    ],
                }
            ]
        }
        self._wd("POST", "/actions", actions)

    def press_keycode(self, keycode: int) -> None:
        try:
            self._wd("POST", "/appium/device/press_keycode", {"keycode": int(keycode)})
        except KobitonWebDriverError:
            self.execute_mobile("mobile: pressKey", [{"keycode": int(keycode)}])

    def activate_app(self, package: str) -> None:
        try:
            self._wd("POST", "/appium/device/activate_app", {"appId": package})
        except KobitonWebDriverError:
            self.execute_mobile("mobile: activateApp", [{"appId": package}])

    def current_package(self) -> str:
        try:
            pkg = self._wd("GET", "/appium/device/current_package")
            return str(pkg or "")
        except KobitonWebDriverError:
            return ""

    def open_url(self, url: str) -> None:
        self._wd("POST", "/url", {"url": url})

    def send_keys_active(self, text: str) -> None:
        elem = self._wd("GET", "/element/active")
        elem_id = None
        if isinstance(elem, dict):
            elem_id = elem.get("ELEMENT") or next(iter(elem.values()), None)
        if not elem_id:
            raise KobitonWebDriverError("Nenhum elemento ativo para digitar texto.")
        self._wd("POST", f"/element/{elem_id}/value", {"text": text, "value": list(text)})


# ==============================================================================
# BACKEND KOBITON (COMPATÍVEL COM `android_whalebone_check.AndroidBackend`)
# ==============================================================================


class KobitonBackend(awc.AndroidBackend):
    """Backend `AndroidBackend` que delega para uma sessão Kobiton/Appium."""

    mode_name = "kobiton"

    def __init__(self, client: KobitonClient, logger: Optional[logging.Logger] = None):
        self.client = client
        self.log = logger or logging.getLogger(__name__)
        self.shell_supported: Optional[bool] = None

    def is_available(self) -> bool:
        return bool(self.client.session_id)

    def _try_mobile_shell(self, args: Sequence[str], timeout: int = 15) -> subprocess.CompletedProcess:
        if not args:
            return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="empty command")
        if self.shell_supported is False:
            return subprocess.CompletedProcess(args=list(args), returncode=1, stdout="", stderr="mobile: shell disabled")

        try:
            res = self.client.execute_mobile(
                "mobile: shell",
                [{"command": str(args[0]), "args": [str(a) for a in args[1:]]}],
                timeout=max(10, timeout + 5),
            )
            self.shell_supported = True
            stdout = res if isinstance(res, str) else json.dumps(res) if res is not None else ""
            return subprocess.CompletedProcess(args=list(args), returncode=0, stdout=stdout, stderr="")
        except KobitonWebDriverError as exc:
            msg = str(exc).lower()
            if any(
                hint in msg
                for hint in ("not allowed", "relaxed", "unknown command", "unsupported", "insecure", "adb_shell")
            ):
                self.shell_supported = False
                self.log.warning("`mobile: shell` indisponível nesta sessão Kobiton; usando fallback Appium/UI.")
            return subprocess.CompletedProcess(args=list(args), returncode=1, stdout="", stderr=str(exc))

    def _fallback_shell_via_appium(self, args: Sequence[str]) -> Optional[subprocess.CompletedProcess]:
        """Traduz comandos Android comuns para endpoints nativos do Appium quando `mobile: shell` está bloqueado."""
        if not args:
            return None
        cmd = args[0]

        if cmd == "pm" and len(args) >= 3 and args[1] == "list" and args[2] == "packages":
            # Retorna vazio para não bloquear o lançamento de apps em `navigate_apps`
            return subprocess.CompletedProcess(args=list(args), returncode=0, stdout="", stderr="")

        if cmd == "monkey" and "-p" in args:
            idx = list(args).index("-p")
            if idx + 1 < len(args):
                pkg = args[idx + 1]
                try:
                    self.client.activate_app(pkg)
                    return subprocess.CompletedProcess(args=list(args), returncode=0, stdout="OK", stderr="")
                except KobitonWebDriverError as exc:
                    return subprocess.CompletedProcess(args=list(args), returncode=1, stdout="", stderr=str(exc))

        if cmd == "am" and len(args) >= 2 and args[1] == "start":
            arg_list = list(args)
            if "-d" in arg_list:
                url = arg_list[arg_list.index("-d") + 1]
                pkg = ""
                if "-n" in arg_list:
                    pkg = arg_list[arg_list.index("-n") + 1].split("/")[0]
                try:
                    if pkg:
                        self.client.execute_mobile("mobile: deepLink", [{"url": url, "package": pkg}])
                    else:
                        self.client.open_url(url)
                    return subprocess.CompletedProcess(args=arg_list, returncode=0, stdout="OK", stderr="")
                except KobitonWebDriverError:
                    try:
                        self.client.open_url(url)
                        return subprocess.CompletedProcess(args=arg_list, returncode=0, stdout="OK", stderr="")
                    except KobitonWebDriverError as exc:
                        return subprocess.CompletedProcess(args=arg_list, returncode=1, stdout="", stderr=str(exc))

            if "-n" in arg_list:
                comp = arg_list[arg_list.index("-n") + 1]
                pkg, _, act = comp.partition("/")
                try:
                    self.client.execute_mobile("mobile: startActivity", [{"appPackage": pkg, "appActivity": act}])
                    return subprocess.CompletedProcess(args=arg_list, returncode=0, stdout="OK", stderr="")
                except KobitonWebDriverError:
                    try:
                        self.client.activate_app(pkg)
                        return subprocess.CompletedProcess(args=arg_list, returncode=0, stdout="OK", stderr="")
                    except KobitonWebDriverError as exc:
                        return subprocess.CompletedProcess(args=arg_list, returncode=1, stdout="", stderr=str(exc))

            if "-a" in arg_list:
                action = arg_list[arg_list.index("-a") + 1]
                try:
                    self.client.execute_mobile("mobile: startActivity", [{"intentAction": action}])
                    return subprocess.CompletedProcess(args=arg_list, returncode=0, stdout="OK", stderr="")
                except KobitonWebDriverError:
                    if "settings" in action.lower():
                        try:
                            self.client.activate_app("com.android.settings")
                            return subprocess.CompletedProcess(args=arg_list, returncode=0, stdout="OK", stderr="")
                        except KobitonWebDriverError as exc:
                            return subprocess.CompletedProcess(args=arg_list, returncode=1, stdout="", stderr=str(exc))

        if cmd == "dumpsys" and len(args) >= 3 and args[1] == "activity":
            pkg = self.client.current_package()
            if pkg:
                return subprocess.CompletedProcess(
                    args=list(args),
                    returncode=0,
                    stdout=f"mResumedActivity: ActivityRecord{{0 u0 {pkg}/.MainActivity}}",
                    stderr="",
                )

        return None

    def shell(self, args: Sequence[str], timeout: int = 15) -> subprocess.CompletedProcess:
        res = self._try_mobile_shell(args, timeout=timeout)
        if res.returncode == 0:
            return res
        fb = self._fallback_shell_via_appium(args)
        return fb if fb is not None else res

    def get_device_info(self) -> awc.DeviceInfo:
        caps = self.client.capabilities
        serial = str(caps.get("deviceUDID") or caps.get("udid") or self.client.session_id or "kobiton")
        model = str(caps.get("deviceModel") or caps.get("deviceName") or "Unknown")
        version = str(caps.get("platformVersion") or "Unknown")
        sdk = str(caps.get("deviceApiLevel") or "Unknown")

        if self.shell_supported is not False:
            m_res = self._try_mobile_shell(["getprop", "ro.product.model"], timeout=5)
            if m_res.returncode == 0 and m_res.stdout.strip():
                model = m_res.stdout.strip()
            v_res = self._try_mobile_shell(["getprop", "ro.build.version.release"], timeout=5)
            if v_res.returncode == 0 and v_res.stdout.strip():
                version = v_res.stdout.strip()
            s_res = self._try_mobile_shell(["getprop", "ro.build.version.sdk"], timeout=5)
            if s_res.returncode == 0 and s_res.stdout.strip():
                sdk = s_res.stdout.strip()

        return awc.DeviceInfo(
            serial=serial,
            model=model,
            android_version=version,
            sdk=sdk,
            execution_mode=self.mode_name,
        )

    def screencap(self, output_png: Path, timeout: int = 15) -> bool:
        try:
            png_bytes = self.client.screenshot_png()
            output_png.parent.mkdir(parents=True, exist_ok=True)
            output_png.write_bytes(png_bytes)
            return True
        except KobitonWebDriverError as exc:
            self.log.warning("Falha ao capturar screenshot no Kobiton: %s", exc)
            return False

    def dump_ui_xml(self, remote_path: str = "/sdcard/whalebone_ui_dump.xml") -> str:
        try:
            src = self.client.page_source()
            if "<hierarchy" in src or "<android." in src:
                return src
        except KobitonWebDriverError as exc:
            self.log.debug("Falha em page_source(): %s", exc)
        return super().dump_ui_xml(remote_path=remote_path)

    def tap(self, x: int, y: int) -> None:
        try:
            self.client.tap(x, y)
        except KobitonWebDriverError:
            super().tap(x, y)

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 350) -> None:
        try:
            self.client.swipe(x1, y1, x2, y2, duration_ms=duration_ms)
        except KobitonWebDriverError:
            super().swipe(x1, y1, x2, y2, duration_ms=duration_ms)

    def keyevent(self, keycode: str) -> None:
        code = KEYCODE_MAP.get(keycode.upper())
        if code is None and keycode.isdigit():
            code = int(keycode)
        if code is not None:
            try:
                self.client.press_keycode(code)
                return
            except KobitonWebDriverError:
                pass
        super().keyevent(keycode)

    def input_text(self, text: str) -> None:
        try:
            self.client.send_keys_active(text)
        except KobitonWebDriverError:
            super().input_text(text)


# ==============================================================================
# GESTÃO DE DUAL SIM (SIM1 / SIM2) E MODO AVIÃO
# ==============================================================================


def _normalize_msisdn(raw: str) -> str:
    return re.sub(r"\D+", "", raw or "")


def msisdn_matches(candidate: str, target: str) -> bool:
    """Compara dois MSISDNs ignorando '+'/espaços e aceitando correspondência exata ou pelos últimos 9 dígitos."""
    c_digits = _normalize_msisdn(candidate)
    t_digits = _normalize_msisdn(target)
    if not c_digits or not t_digits:
        return False
    if c_digits == t_digits:
        return True
    if len(c_digits) >= 9 and len(t_digits) >= 9:
        return c_digits[-9:] == t_digits[-9:]
    return False


def _looks_like_iccid(val: str) -> bool:
    digits = _normalize_msisdn(val)
    return len(digits) >= 15 and digits.startswith("89")


def _is_valid_unmasked_msisdn(val: str) -> bool:
    """Retorna True apenas se o valor não estiver mascarado (ex: `+3519[****`) e tiver >= 7 dígitos."""
    if not val:
        return False
    low = val.lower()
    if low in ("null", "none", "unknown", '""', "''") or "*" in val or "[" in val:
        return False
    return len(_normalize_msisdn(val)) >= 7 and not _looks_like_iccid(val)


def parse_service_call_parcel_string(parcel_output: str) -> str:
    """Decodifica uma string retornada por `service call iphonesubinfo <id>` (formato Parcel UTF-16), ignorando ICCID."""
    if not parcel_output or "Parcel(" not in parcel_output:
        return ""
    # Extrai trechos entre aspas simples: '....+.3.5.1.9.3.0.9.9.2.7.8.5...'
    ascii_parts = re.findall(r"'([^']*)'", parcel_output)
    if not ascii_parts:
        return ""
    joined = "".join(ascii_parts).replace(".", "")
    m = re.search(r"(\+?\d{7,15})", joined)
    if not m:
        return ""
    candidate = m.group(1)
    if _looks_like_iccid(candidate):
        return ""
    return candidate


def parse_sim_msisdns_from_content_siminfo(output: str) -> Tuple[str, str]:
    """Extrai MSISDN de `content query --uri content://telephony/siminfo`."""
    sim1_msisdn = ""
    sim2_msisdn = ""
    for line in (output or "").splitlines():
        if "Row:" not in line:
            continue
        m_slot = re.search(r"\bsim_id=(-?\d+)", line)
        m_num = re.search(r"\bnumber=([^,\r\n]+)", line)
        if not m_slot or not m_num:
            continue
        slot = int(m_slot.group(1))
        val = m_num.group(1).strip()
        if not _is_valid_unmasked_msisdn(val):
            continue
        if slot == 0 and not sim1_msisdn:
            sim1_msisdn = val
        elif slot == 1 and not sim2_msisdn:
            sim2_msisdn = val
    return sim1_msisdn, sim2_msisdn


def parse_sim_msisdns_from_ui(nodes: Sequence[awc.UINode]) -> Tuple[str, str]:
    """Extrai os números de telefone próximos a SIM 1 e SIM 2 na UI do Gestor SIM (lista vertical ou cards lado a lado)."""
    sim1_msisdn = ""
    sim2_msisdn = ""
    phone_re = re.compile(r"(\+?\d[\d\s\-\.\(\)]{6,25}\d)")

    anchor1 = awc.find_node_by_labels(nodes, ("sim 1", "sim1"))
    anchor2 = awc.find_node_by_labels(nodes, ("sim 2", "sim2"))
    anchors = [(1, anchor1), (2, anchor2)]
    anchors = [(s, a) for s, a in anchors if a is not None]
    if not anchors:
        return "", ""

    best_score: Dict[int, Tuple[int, float]] = {1: (0, float("inf")), 2: (0, float("inf"))}
    for n in nodes:
        if not n.label:
            continue
        for m in phone_re.finditer(n.label):
            num = re.sub(r"[\s\-\.\(\)]+", "", m.group(1))
            digits = re.sub(r"\D+", "", num)
            if len(digits) < 9 or _looks_like_iccid(num):
                continue
            nx, ny = n.center
            best_slot = None
            min_d = float("inf")
            for slot, anch in anchors:
                ax, ay = anch.center
                _, ay1, _, ay2 = anch.bounds
                if ny < ay1 - 100 or ny > ay2 + 450:
                    continue
                d = ((nx - ax) ** 2 + (ny - ay) ** 2) ** 0.5
                if d < min_d:
                    min_d = d
                    best_slot = slot
            if best_slot is not None:
                # Prioriza MSISDN completo (com DDI/mais dígitos) e menor distância
                prev_len, prev_dist = best_score[best_slot]
                if len(digits) > prev_len or (len(digits) == prev_len and min_d < prev_dist):
                    best_score[best_slot] = (len(digits), min_d)
                    if best_slot == 1:
                        sim1_msisdn = num
                    else:
                        sim2_msisdn = num

    return sim1_msisdn, sim2_msisdn


def parse_sim_msisdns_from_shell(
    dumpsys_isub: str = "",
    dumpsys_iphonesubinfo: str = "",
) -> Tuple[str, str]:
    """Extrai os MSISDNs de SIM1 (slot 0) e SIM2 (slot 1) a partir de saídas shell do Android."""
    sim1_msisdn = ""
    sim2_msisdn = ""

    if dumpsys_isub:
        for slot_idx in (0, 1):
            pattern = rf"simSlotIndex={slot_idx}\b[^\n]*?\b(?:number|msisdn)=([^\s,\]}}]+)"
            m = re.search(pattern, dumpsys_isub, re.IGNORECASE)
            if not m:
                pattern_multiline = rf"simSlotIndex={slot_idx}\b.*?\b(?:number|msisdn)=([^\s,\]}}]+)"
                m = re.search(pattern_multiline, dumpsys_isub, re.IGNORECASE | re.DOTALL)
            if m:
                val = m.group(1).strip().strip('"').strip("'")
                if _is_valid_unmasked_msisdn(val):
                    if slot_idx == 0 and not sim1_msisdn:
                        sim1_msisdn = val
                    elif slot_idx == 1 and not sim2_msisdn:
                        sim2_msisdn = val

    if dumpsys_iphonesubinfo:
        for slot_idx in (0, 1):
            if (slot_idx == 0 and sim1_msisdn) or (slot_idx == 1 and sim2_msisdn):
                continue
            m = re.search(
                rf"(?:Phone ID\s*=\s*{slot_idx}|subId\s*=\s*\d+).*?Line\s*1\s*number\s*=\s*([^\r\n]+)",
                dumpsys_iphonesubinfo,
                re.IGNORECASE | re.DOTALL,
            )
            if m:
                val = m.group(1).strip()
                if _is_valid_unmasked_msisdn(val):
                    if slot_idx == 0:
                        sim1_msisdn = val
                    else:
                        sim2_msisdn = val

    return sim1_msisdn, sim2_msisdn


def parse_sim_iccids_from_isub(dumpsys_isub: str = "") -> Tuple[str, str]:
    """Extrai o ICCID de SIM1 (slot 0) e SIM2 (slot 1) a partir de `dumpsys isub`."""
    sim1_iccid = ""
    sim2_iccid = ""
    for slot_idx in (0, 1):
        m = re.search(rf"simSlotIndex={slot_idx}\b[^\n]*?\biccId=([^\s,\]}}]+)", dumpsys_isub or "", re.IGNORECASE)
        if not m:
            m = re.search(rf"simSlotIndex={slot_idx}\b.*?\biccId=([^\s,\]}}]+)", dumpsys_isub or "", re.IGNORECASE | re.DOTALL)
        if m:
            val = m.group(1).strip().strip('"').strip("'")
            if val and val.lower() not in ("null", "none", "unknown"):
                if slot_idx == 0 and not sim1_iccid:
                    sim1_iccid = val
                elif slot_idx == 1 and not sim2_iccid:
                    sim2_iccid = val
    return sim1_iccid, sim2_iccid


def extract_kobiton_device_msisdns(device: Dict[str, Any]) -> str:
    """Extrai MSISDN/telefone de um objeto de dispositivo da API REST do Kobiton."""
    found: List[str] = []
    for key in ("msisdn", "phoneNumber", "simNumber", "sim1Number", "sim2Number"):
        val = str(device.get(key) or "").strip()
        if val and val not in found:
            found.append(f"{key}={val}")
    for list_key in ("sims", "simNumbers"):
        items = device.get(list_key)
        if isinstance(items, list):
            for idx, item in enumerate(items, start=1):
                if isinstance(item, dict):
                    num = str(item.get("msisdn") or item.get("phoneNumber") or item.get("number") or "").strip()
                    if num:
                        found.append(f"SIM{idx}={num}")
                elif item:
                    found.append(f"SIM{idx}={item}")
    return ", ".join(found) if found else "-"


def parse_sim_states_from_shell(
    gsm_sim_state: str = "",
    dumpsys_isub: str = "",
    phone1_on: str = "",
    phone2_on: str = "",
) -> Tuple[Optional[bool], Optional[bool]]:
    """Extrai estado booleano aproximado de SIM1 e SIM2 a partir de saídas shell do Android."""
    sim1: Optional[bool] = None
    sim2: Optional[bool] = None

    if phone1_on.strip() in ("0", "1"):
        sim1 = phone1_on.strip() == "1"
    if phone2_on.strip() in ("0", "1"):
        sim2 = phone2_on.strip() == "1"

    if dumpsys_isub:
        for slot_idx in (0, 1):
            pattern = rf"simSlotIndex={slot_idx}.*?areUiccApplicationsEnabled=(true|false)"
            m = re.search(pattern, dumpsys_isub, re.IGNORECASE | re.DOTALL)
            if m:
                val = m.group(1).lower() == "true"
                if slot_idx == 0 and sim1 is None:
                    sim1 = val
                elif slot_idx == 1 and sim2 is None:
                    sim2 = val

    if gsm_sim_state.strip():
        parts = [p.strip().upper() for p in gsm_sim_state.strip().split(",")]
        if len(parts) >= 1 and sim1 is None and parts[0]:
            sim1 = parts[0] in ("READY", "LOADED", "PIN_REQUIRED", "PUK_REQUIRED", "NETWORK_LOCKED")
        if len(parts) >= 2 and sim2 is None and parts[1]:
            sim2 = parts[1] in ("READY", "LOADED", "PIN_REQUIRED", "PUK_REQUIRED", "NETWORK_LOCKED")

    return sim1, sim2


def find_switch_near_label(
    nodes: Sequence[awc.UINode],
    label_keywords: Sequence[str],
) -> Optional[Tuple[awc.UINode, Optional[awc.UINode]]]:
    """Encontra o nó de texto correspondente ao rótulo e o Switch/CheckBox mais próximo na mesma linha."""
    target = awc.find_node_by_labels(nodes, label_keywords)
    if not target:
        return None

    _, ty1, _, ty2 = target.bounds
    ty_center = (ty1 + ty2) // 2

    best_switch: Optional[awc.UINode] = None
    best_dist = 10**9
    for n in nodes:
        cls_lower = n.class_name.lower()
        rid_lower = n.resource_id.lower()
        is_toggle = ("switch" in cls_lower) or ("checkbox" in cls_lower) or ("switch" in rid_lower)
        if not is_toggle:
            continue
        _, sy1, _, sy2 = n.bounds
        sy_center = (sy1 + sy2) // 2
        dist = abs(sy_center - ty_center)
        if dist <= 160 and dist < best_dist:
            best_dist = dist
            best_switch = n

    return target, best_switch


def _confirm_dialog_if_present(backend: KobitonBackend) -> None:
    time.sleep(1.0)
    nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
    btn = awc.find_node_by_labels(nodes, CONFIRM_POSITIVE_LABELS)
    if btn and btn.clickable:
        backend.tap(*btn.center)
        time.sleep(1.5)


def _open_sim_settings_ui(backend: KobitonBackend) -> List[awc.UINode]:
    for action in SIM_SETTINGS_ACTIONS:
        backend.shell(["am", "start", "-a", action], timeout=8)
        time.sleep(2.0)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        if find_switch_near_label(nodes, ["sim 1", "sim1"]) or find_switch_near_label(nodes, ["sim 2", "sim2"]):
            return nodes
        menu = awc.find_node_by_labels(nodes, SIM_MENU_LABELS)
        if menu:
            backend.tap(*menu.center)
            time.sleep(2.0)
            nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
            if find_switch_near_label(nodes, ["sim 1", "sim1"]) or find_switch_near_label(nodes, ["sim 2", "sim2"]):
                return nodes
    return awc.parse_ui_nodes(backend.dump_ui_xml())


def _set_sim_slot_via_ui(
    backend: KobitonBackend,
    slot: int,
    desired_enabled: bool,
    log: logging.Logger,
) -> Optional[bool]:
    labels = ["sim 1", "sim1"] if slot == 1 else ["sim 2", "sim2"]
    nodes = _open_sim_settings_ui(backend)
    found = find_switch_near_label(nodes, labels)
    if not found:
        log.warning("SIM %d não encontrado na UI de Configurações.", slot)
        return None

    label_node, switch_node = found
    if switch_node is None:
        # Alguns aparelhos abrem uma tela de detalhe ao tocar no SIM
        backend.tap(*label_node.center)
        time.sleep(1.5)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        switch_node = next(
            (n for n in nodes if "switch" in n.class_name.lower() or "switch" in n.resource_id.lower()),
            None,
        )
        if switch_node is None:
            log.warning("Switch do SIM %d não localizado após abrir detalhe.", slot)
            return None

    current = switch_node.checked
    if current != desired_enabled:
        log.info("Alterando SIM %d via UI: %s -> %s", slot, current, desired_enabled)
        backend.tap(*switch_node.center)
        _confirm_dialog_if_present(backend)
        time.sleep(2.0)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        recheck = find_switch_near_label(nodes, labels)
        if recheck and recheck[1] is not None:
            return recheck[1].checked
        return desired_enabled
    return current


def _set_sim_slot_state(
    backend: KobitonBackend,
    slot: int,
    desired_enabled: bool,
    log: logging.Logger,
) -> Optional[bool]:
    """Tenta alterar o estado do SIM1/SIM2 via shell (quando permitido) e valida/fallback via UI."""
    if backend.shell_supported is not False:
        prop_key = f"phone{slot}_on"
        backend.shell(["settings", "put", "global", prop_key, "1" if desired_enabled else "0"], timeout=6)
        state_val = "1" if desired_enabled else "0"
        backend.shell(["cmd", "phone", "set-sim-power", str(slot - 1), state_val], timeout=6)

    return _set_sim_slot_via_ui(backend, slot=slot, desired_enabled=desired_enabled, log=log)


def detect_initial_sim_and_airplane_state(
    backend: KobitonBackend,
    output_dir: Path,
    log: logging.Logger,
) -> SimInitialState:
    """Detecta o estado inicial de SIM1, SIM2, seus MSISDNs e Modo Avião antes de qualquer alteração."""
    sim1: Optional[bool] = None
    sim2: Optional[bool] = None
    sim1_msisdn = ""
    sim2_msisdn = ""
    sim1_iccid = ""
    sim2_iccid = ""
    airplane: Optional[bool] = None
    method = "ui"

    if backend.shell_supported is not False:
        gsm = backend.shell(["getprop", "gsm.sim.state"], timeout=5).stdout
        isub = backend.shell(["dumpsys", "isub"], timeout=8).stdout
        iph = backend.shell(["dumpsys", "iphonesubinfo"], timeout=6).stdout
        p1 = backend.shell(["settings", "get", "global", "phone1_on"], timeout=5).stdout
        p2 = backend.shell(["settings", "get", "global", "phone2_on"], timeout=5).stdout
        air = backend.shell(["settings", "get", "global", "airplane_mode_on"], timeout=5).stdout.strip()
        if air in ("0", "1"):
            airplane = air == "1"
        sim1, sim2 = parse_sim_states_from_shell(gsm, isub, p1, p2)
        sim1_msisdn, sim2_msisdn = parse_sim_msisdns_from_shell(isub, iph)
        sim1_iccid, sim2_iccid = parse_sim_iccids_from_isub(isub)

        if not sim1_msisdn and not sim2_msisdn:
            siminfo = backend.shell(["content", "query", "--uri", "content://telephony/siminfo"], timeout=6).stdout
            sim1_msisdn, sim2_msisdn = parse_sim_msisdns_from_content_siminfo(siminfo)

        if not sim1_msisdn:
            for tx_id in ("13", "15", "16", "17", "18"):
                parcel_out = backend.shell(["service", "call", "iphonesubinfo", tx_id], timeout=4).stdout
                candidate = parse_service_call_parcel_string(parcel_out)
                if candidate:
                    sim1_msisdn = candidate
                    break

        if sim1 is not None or sim2 is not None:
            method = "shell"

    nodes = _open_sim_settings_ui(backend)
    if sim1 is None:
        f1 = find_switch_near_label(nodes, ["sim 1", "sim1"])
        if f1 and f1[1] is not None:
            sim1 = f1[1].checked
    if sim2 is None:
        f2 = find_switch_near_label(nodes, ["sim 2", "sim2"])
        if f2 and f2[1] is not None:
            sim2 = f2[1].checked
    if not sim1_msisdn or not sim2_msisdn:
        ui_s1, ui_s2 = parse_sim_msisdns_from_ui(nodes)
        sim1_msisdn = sim1_msisdn or ui_s1
        sim2_msisdn = sim2_msisdn or ui_s2

    log.info(
        "Estado inicial detectado (%s): SIM1=%s (MSISDN=%s, ICCID=%s) | SIM2=%s (MSISDN=%s, ICCID=%s) | Modo Avião=%s",
        method,
        sim1,
        sim1_msisdn or "-",
        sim1_iccid or "-",
        sim2,
        sim2_msisdn or "-",
        sim2_iccid or "-",
        airplane,
    )
    return SimInitialState(
        sim1_enabled=sim1,
        sim2_enabled=sim2,
        sim1_msisdn=sim1_msisdn,
        sim2_msisdn=sim2_msisdn,
        sim1_iccid=sim1_iccid,
        sim2_iccid=sim2_iccid,
        airplane_mode_enabled=airplane,
        detection_method=method,
        details=(
            f"SIM1={sim1} (MSISDN={sim1_msisdn or '-'}, ICCID={sim1_iccid or '-'}), "
            f"SIM2={sim2} (MSISDN={sim2_msisdn or '-'}, ICCID={sim2_iccid or '-'}), airplane={airplane}"
        ),
        screenshot_path="",
    )


def select_target_sim_slot(
    initial: SimInitialState,
    target_msisdn: str = "",
    log: Optional[logging.Logger] = None,
) -> int:
    """Determina qual slot SIM (1 ou 2) deve ficar ativo com base no MSISDN (ou ICCID) informado."""
    if not target_msisdn.strip():
        return 1
    if msisdn_matches(initial.sim1_msisdn, target_msisdn) or msisdn_matches(initial.sim1_iccid, target_msisdn):
        return 1
    if msisdn_matches(initial.sim2_msisdn, target_msisdn) or msisdn_matches(initial.sim2_iccid, target_msisdn):
        return 2
    if not initial.sim1_msisdn and not initial.sim2_msisdn:
        if log:
            log.warning(
                "Não foi possível ler o MSISDN de SIM1/SIM2 no Android (ocultado pelo SO/operadora; "
                "SIM1 ICCID=%s, SIM2 ICCID=%s). Prosseguindo com SIM1 como padrão.",
                initial.sim1_iccid or "-",
                initial.sim2_iccid or "-",
            )
        return 1
    raise ValueError(
        f"MSISDN alvo '{target_msisdn}' não corresponde ao SIM1 ({initial.sim1_msisdn or '-'}) "
        f"nem ao SIM2 ({initial.sim2_msisdn or '-'})."
    )


def ensure_target_sim_active(
    backend: KobitonBackend,
    initial: SimInitialState,
    sim_action: SimActionResult,
    target_slot: int,
    output_dir: Path,
    log: logging.Logger,
) -> Tuple[Optional[bool], Optional[bool], str]:
    """Garante que o SIM alvo (`target_slot`: 1 ou 2) esteja ativo e o outro slot desativado."""
    sim1 = initial.sim1_enabled
    sim2 = initial.sim2_enabled
    sim_action.target_slot = target_slot
    want_sim1 = target_slot == 1
    want_sim2 = target_slot == 2

    if sim1 is not want_sim1:
        log.info("Alterando SIM1 (atual=%s -> %s)...", sim1, want_sim1)
        sim1 = _set_sim_slot_state(backend, slot=1, desired_enabled=want_sim1, log=log)
        sim_action.sim1_changed = True
    else:
        log.info("SIM1 já está %s.", "ativo" if want_sim1 else "desativado")

    if sim2 is not want_sim2:
        log.info("Alterando SIM2 (atual=%s -> %s)...", sim2, want_sim2)
        sim2 = _set_sim_slot_state(backend, slot=2, desired_enabled=want_sim2, log=log)
        sim_action.sim2_changed = True
    else:
        log.info("SIM2 já está %s.", "ativo" if want_sim2 else "desativado")

    return sim1, sim2, ""


def ensure_sim1_active_sim2_inactive(
    backend: KobitonBackend,
    initial: SimInitialState,
    sim_action: SimActionResult,
    output_dir: Path,
    log: logging.Logger,
) -> Tuple[Optional[bool], Optional[bool], str]:
    """Garante que SIM1 esteja ativo e SIM2 desativado, registrando o que foi alterado."""
    return ensure_target_sim_active(backend, initial, sim_action, target_slot=1, output_dir=output_dir, log=log)


def set_airplane_mode(
    backend: KobitonBackend,
    enabled: bool,
    keep_wifi: bool,
    output_dir: Optional[Path],
    screenshot_name: str,
    log: logging.Logger,
) -> Tuple[Optional[bool], str]:
    """Ativa ou desativa o Modo Avião no Android (via shell e/ou UI)."""
    if backend.shell_supported is not False:
        cmd_word = "enable" if enabled else "disable"
        res = backend.shell(["cmd", "connectivity", "airplane-mode", cmd_word], timeout=8)
        if res.returncode != 0:
            val = "1" if enabled else "0"
            state_bool = "true" if enabled else "false"
            backend.shell(["settings", "put", "global", "airplane_mode_on", val], timeout=6)
            backend.shell(
                ["am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE", "--ez", "state", state_bool],
                timeout=6,
            )
        if enabled and keep_wifi:
            time.sleep(1.5)
            backend.shell(["svc", "wifi", "enable"], timeout=6)

    # Confirma/aplica via UI de Configurações
    final_state: Optional[bool] = None
    for action in AIRPLANE_SETTINGS_ACTIONS:
        backend.shell(["am", "start", "-a", action], timeout=8)
        time.sleep(2.0)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        found = find_switch_near_label(nodes, AIRPLANE_LABELS)
        if found and found[1] is not None:
            sw = found[1]
            if sw.checked != enabled:
                log.info("Alterando Modo Avião via UI: %s -> %s", sw.checked, enabled)
                backend.tap(*sw.center)
                _confirm_dialog_if_present(backend)
                time.sleep(2.0)
                nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
                recheck = find_switch_near_label(nodes, AIRPLANE_LABELS)
                final_state = recheck[1].checked if (recheck and recheck[1]) else enabled
            else:
                final_state = sw.checked
            break

    if final_state is None and backend.shell_supported is not False:
        air = backend.shell(["settings", "get", "global", "airplane_mode_on"], timeout=5).stdout.strip()
        if air in ("0", "1"):
            final_state = air == "1"

    saved_png = ""
    if output_dir is not None:
        png_path = output_dir / "screenshots" / screenshot_name
        if backend.screencap(png_path):
            saved_png = str(png_path)

    log.info("Modo Avião definido para %s (estado observado=%s)", enabled, final_state)
    return final_state, saved_png


def toggle_airplane_mode_reregister(
    backend: KobitonBackend,
    wait_on_sec: int,
    wait_off_sec: int,
    output_dir: Path,
    log: logging.Logger,
) -> Tuple[Optional[bool], str]:
    """
    Liga e desliga o Modo Avião para forçar o deregistro e novo registro do SIM1 na rede,
    garantindo que os testes sejam executados com o Modo Avião DESATIVADO.
    """
    log.info("Ativando Modo Avião por %ds para deregistrar SIM1...", wait_on_sec)
    set_airplane_mode(
        backend,
        enabled=True,
        keep_wifi=False,
        output_dir=None,
        screenshot_name="",
        log=log,
    )
    time.sleep(max(1, wait_on_sec))

    log.info("Desativando Modo Avião e aguardando %ds para novo registro do SIM1...", wait_off_sec)
    final_state, off_png = set_airplane_mode(
        backend,
        enabled=False,
        keep_wifi=False,
        output_dir=None,
        screenshot_name="",
        log=log,
    )
    time.sleep(max(1, wait_off_sec))
    return final_state, off_png


def restore_sim_and_airplane_state(
    backend: KobitonBackend,
    initial: SimInitialState,
    sim_action: SimActionResult,
    output_dir: Path,
    log: logging.Logger,
) -> None:
    """Restaura SIM1, SIM2 e Modo Avião ao estado inicial apenas se tiverem sido alterados."""
    log.info(
        "Restaurando estado inicial: SIM1=%s (alterado=%s), SIM2=%s (alterado=%s), Modo Avião=%s",
        initial.sim1_enabled,
        sim_action.sim1_changed,
        initial.sim2_enabled,
        sim_action.sim2_changed,
        initial.airplane_mode_enabled,
    )
    try:
        if initial.airplane_mode_enabled is True:
            air_restored, _ = set_airplane_mode(
                backend,
                enabled=True,
                keep_wifi=False,
                output_dir=None,
                screenshot_name="",
                log=log,
            )
            sim_action.airplane_after_restore = air_restored
        else:
            sim_action.airplane_after_restore = False

        # Se o SIM1 estava desativado inicialmente (e foi alterado), desativa SIM1
        if sim_action.sim1_changed and initial.sim1_enabled is not None:
            sim_action.sim1_after_restore = _set_sim_slot_state(
                backend, slot=1, desired_enabled=initial.sim1_enabled, log=log
            )
        else:
            sim_action.sim1_after_restore = initial.sim1_enabled

        # Se o SIM2 estava ativo inicialmente (e foi alterado), reativa SIM2
        if sim_action.sim2_changed and initial.sim2_enabled is not None:
            sim_action.sim2_after_restore = _set_sim_slot_state(
                backend, slot=2, desired_enabled=initial.sim2_enabled, log=log
            )
        else:
            sim_action.sim2_after_restore = initial.sim2_enabled

        if sim_action.sim1_changed or sim_action.sim2_changed or initial.airplane_mode_enabled is True:
            png_path = output_dir / "screenshots" / "99_sim_restored_state.png"
            if backend.screencap(png_path):
                sim_action.restored_screenshot = str(png_path)
        sim_action.restored_successfully = True
        sim_action.notes = "Estado inicial de SIM/Modo Avião restaurado."
    except Exception as exc:
        sim_action.restored_successfully = False
        sim_action.notes = f"Falha ao restaurar estado inicial: {exc}"
        log.error(sim_action.notes)


# ==============================================================================
# TESTE DE CONECTIVIDADE PARA O SERVIDOR DE DNS DESTINO
# ==============================================================================


def _parse_device_curl_metrics(stdout: str) -> Dict[str, str]:
    metrics: Dict[str, str] = {}
    for part in stdout.strip().split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            metrics[k.strip()] = v.strip()
    return metrics


def _sec_str_to_ms(val: Optional[str]) -> Optional[int]:
    if not val:
        return None
    try:
        return max(0, int(float(val) * 1000))
    except ValueError:
        return None


def _collect_device_tls_cert(
    backend: KobitonBackend,
    host: str,
    target_ip: str,
    port: int = 443,
    output_dir: Optional[Path] = None,
) -> Optional[TlsCertificateInfo]:
    """Coleta o certificado entregue no handshake TLS diretamente no dispositivo Android (`openssl` ou `curl -vvI`)."""
    if backend.shell_supported is False or not host:
        return None
    connect_target = f"{target_ip or host}:{port}"
    info = TlsCertificateInfo()

    res = backend.shell(
        [
            "sh",
            "-c",
            (
                f"OUT=$(echo | openssl s_client -showcerts -connect {connect_target} -servername {host} 2>&1); "
                f"echo \"$OUT\"; "
                f"echo \"$OUT\" | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>/dev/null"
            ),
        ],
        timeout=10,
    )
    if res.returncode == 0 and res.stdout:
        pem_match = re.search(
            r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
            res.stdout,
            re.DOTALL,
        )
        if pem_match:
            info.pem = pem_match.group(1).strip()
        for line in res.stdout.splitlines():
            line_s = line.strip()
            low = line_s.lower()
            if low.startswith("subject="):
                info.subject = line_s.split("=", 1)[1].strip()
            elif low.startswith("issuer="):
                info.issuer = line_s.split("=", 1)[1].strip()
            elif low.startswith("notafter="):
                info.not_after = line_s.split("=", 1)[1].strip()
            elif "fingerprint=" in low:
                info.sha256_fingerprint = line_s.split("=", 1)[1].strip()
            elif "verify return code:" in low:
                info.verify_result = line_s.split(":", 1)[1].strip()
            elif low.startswith("protocol"):
                info.protocol = line_s.split(":", 1)[-1].strip()
            elif low.startswith("cipher"):
                info.cipher = line_s.split(":", 1)[-1].strip()

    # Fallback via `curl -vvI -k` no Android caso `openssl` não esteja instalado no aparelho
    if not (info.subject or info.issuer or info.pem):
        curl_cert = backend.shell(
            ["curl", "-vvI", "-k", "--max-time", "6", f"https://{host}:{port}/"],
            timeout=9,
        )
        combined = f"{curl_cert.stdout}\n{curl_cert.stderr}"
        for line in combined.splitlines():
            line_s = line.strip()
            low = line_s.lower()
            if "subject:" in low:
                info.subject = line_s.split("subject:", 1)[1].strip()
            elif "issuer:" in low:
                info.issuer = line_s.split("issuer:", 1)[1].strip()
            elif "expire date:" in low:
                info.not_after = line_s.split("expire date:", 1)[1].strip()
            elif "ssl certificate verify" in low:
                info.verify_result = line_s

    if not (info.subject or info.issuer or info.sha256_fingerprint or info.pem):
        return None

    return info


def _extract_subresource_urls(html_body: str, base_url: str, limit: int = 12) -> List[Tuple[str, str]]:
    """Extrai sub-recursos (script, stylesheet, img) do HTML para compor a timeline de requests."""
    if not html_body:
        return []
    found: List[Tuple[str, str]] = []
    seen = {base_url}
    patterns = (
        ("script", re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)),
        ("stylesheet", re.compile(r'<link[^>]+rel=["\'][^"\']*stylesheet[^"\']*["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)),
        ("image", re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)),
    )
    for rtype, pat in patterns:
        for m in pat.finditer(html_body):
            raw = m.group(1).strip()
            if not raw or raw.startswith("data:") or raw.startswith("javascript:"):
                continue
            abs_url = urllib.parse.urljoin(base_url, raw)
            if abs_url not in seen:
                seen.add(abs_url)
                found.append((rtype, abs_url))
            if len(found) >= limit:
                return found
    return found


def measure_url_waterfall(
    url: str,
    dns_servers: Sequence[str],
    block_ips: Sequence[str],
    backend: Optional[KobitonBackend] = None,
    timeout: int = 6,
    active_dns_servers: Sequence[str] = (),
    output_dir: Optional[Path] = None,
) -> Tuple[awc.EndpointProbeResult, WaterfallEntry]:
    """
    Sonda o endpoint EXCLUSIVAMENTE a partir do dispositivo Android (via `mobile: shell`),
    medindo RTT, timeline DevTools (requests, HTTP status, size, DNS/TCP/TLS/TTFB),
    certificado TLS e confirmando bloqueio pelo IP (`block_ips`).
    """
    t_total_start = time.monotonic()
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    block_set = set(block_ips) | awc.SINKHOLE_IPS

    dns_used: List[str] = list(active_dns_servers)
    resolved_ips: List[str] = []
    dns_rtt_ms: Optional[int] = None
    tcp_rtt_ms: Optional[int] = None
    tls_rtt_ms: Optional[int] = None
    ttfb_ms: Optional[int] = None
    device_ping_rtt_ms: Optional[float] = None
    http_status: Optional[int] = None
    content_bytes = 0
    tls_cert: Optional[TlsCertificateInfo] = None
    network_requests: List[NetworkRequestItem] = []
    notes: List[str] = []

    if backend is not None and backend.shell_supported is not False and host:
        if not dns_used:
            for prop in ("net.dns1", "net.dns2"):
                d_ip = (backend.shell(["getprop", prop], timeout=4).stdout or "").strip()
                if d_ip and d_ip not in dns_used:
                    dns_used.append(d_ip)

        # 1. Ping no dispositivo Android: resolve via DNS do Android (APN SIM1) e mede RTT
        t_ping = time.monotonic()
        ping_res = backend.shell(["ping", "-c", "1", "-W", "8", host], timeout=11)
        ping_wall_ms = int((time.monotonic() - t_ping) * 1000)
        if ping_res.stdout:
            m_ip = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", ping_res.stdout)
            if m_ip and m_ip.group(1) not in resolved_ips:
                resolved_ips.append(m_ip.group(1))
            m_rtt = re.search(r"time[=<]\s*([\d.]+)\s*ms", ping_res.stdout)
            if m_rtt:
                device_ping_rtt_ms = float(m_rtt.group(1))
        if dns_rtt_ms is None:
            dns_rtt_ms = ping_wall_ms

        # 2. Curl --write-out no dispositivo Android para coletar todas as métricas de performance
        curl_fmt = (
            "\n__CURL_METRICS__http=%{http_code}\nhttp_ver=%{http_version}\ndns=%{time_namelookup}\n"
            "tcp=%{time_connect}\ntls=%{time_appconnect}\npretransfer=%{time_pretransfer}\n"
            "redirect=%{time_redirect}\nttfb=%{time_starttransfer}\ntotal=%{time_total}\n"
            "bytes=%{size_download}\nhdr_bytes=%{size_header}\nspeed=%{speed_download}\n"
            "redirects=%{num_redirects}\nconnects=%{num_connects}\nip=%{remote_ip}\n"
            "port=%{remote_port}\neff_url=%{url_effective}\nctype=%{content_type}\n"
            "ssl_verify=%{ssl_verify_result}"
        )
        curl_res = backend.shell(
            ["curl", "-sS", "-L", "-k", "--write-out", curl_fmt, "--max-time", str(timeout), url],
            timeout=timeout + 4,
        )
        html_body = ""
        if curl_res.returncode == 0 and "__CURL_METRICS__" in curl_res.stdout:
            html_body, metrics_raw = curl_res.stdout.rsplit("__CURL_METRICS__", 1)
            m = _parse_device_curl_metrics(metrics_raw)
            if m.get("http", "").isdigit():
                code = int(m["http"])
                if code > 0:
                    http_status = code
            dns_rtt_ms = _sec_str_to_ms(m.get("dns")) or dns_rtt_ms
            tcp_rtt_ms = _sec_str_to_ms(m.get("tcp"))
            tls_rtt_ms = _sec_str_to_ms(m.get("tls"))
            pretransfer_ms = _sec_str_to_ms(m.get("pretransfer"))
            redirect_ms = _sec_str_to_ms(m.get("redirect"))
            ttfb_ms = _sec_str_to_ms(m.get("ttfb"))
            doc_total_ms = _sec_str_to_ms(m.get("total")) or int((time.monotonic() - t_total_start) * 1000)
            if m.get("bytes", "").isdigit():
                content_bytes = int(m["bytes"])
            hdr_bytes = int(m["hdr_bytes"]) if m.get("hdr_bytes", "").isdigit() else 0
            try:
                speed_bps = float(m["speed"]) if m.get("speed") else None
            except ValueError:
                speed_bps = None
            num_redirects = int(m["redirects"]) if m.get("redirects", "").isdigit() else 0
            remote_ip = m.get("ip", "").strip()
            if remote_ip and remote_ip not in resolved_ips:
                resolved_ips.insert(0, remote_ip)

            network_requests.append(
                NetworkRequestItem(
                    url=url,
                    resource_type="document",
                    method="GET",
                    status_code=http_status,
                    size_bytes=content_bytes,
                    start_offset_ms=0,
                    dns_ms=dns_rtt_ms,
                    tcp_ms=tcp_rtt_ms,
                    tls_ms=tls_rtt_ms,
                    pretransfer_ms=pretransfer_ms,
                    redirect_ms=redirect_ms,
                    ttfb_ms=ttfb_ms,
                    duration_ms=doc_total_ms,
                    size_header_bytes=hdr_bytes,
                    speed_download_bps=speed_bps,
                    num_redirects=num_redirects,
                    http_version=m.get("http_ver", ""),
                    content_type=m.get("ctype", ""),
                    effective_url=m.get("eff_url", ""),
                    remote_ip=remote_ip,
                )
            )
        else:
            # Fallback no dispositivo Android: `toybox nc` para testar conectividade TCP na porta (e HTTP/80)
            t_tcp = time.monotonic()
            nc_res = backend.shell(["toybox", "nc", "-z", "-w", "4", host, str(port)], timeout=7)
            if nc_res.returncode == 0:
                tcp_rtt_ms = int((time.monotonic() - t_tcp) * 1000)
            elif "not found" not in (nc_res.stderr or "").lower():
                notes.append(f"device_tcp_closed:{port}")

            if parsed.scheme == "http" and (resolved_ips or host):
                target_h = resolved_ips[0] if resolved_ips else host
                http_res = backend.shell(
                    ["sh", "-c", f'printf "HEAD / HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n" | toybox nc -w 4 {target_h} {port}'],
                    timeout=7,
                )
                if http_res.stdout:
                    m_st = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", http_res.stdout)
                    if m_st:
                        http_status = int(m_st.group(1))

            network_requests.append(
                NetworkRequestItem(
                    url=url,
                    resource_type="document",
                    method="GET",
                    status_code=http_status,
                    size_bytes=content_bytes,
                    start_offset_ms=0,
                    dns_ms=dns_rtt_ms,
                    tcp_ms=tcp_rtt_ms,
                    tls_ms=tls_rtt_ms,
                    ttfb_ms=ttfb_ms,
                    duration_ms=int((time.monotonic() - t_total_start) * 1000),
                    remote_ip=resolved_ips[0] if resolved_ips else "",
                )
            )

        # 3. Certificado TLS entregue no handshake a partir do dispositivo
        if parsed.scheme == "https":
            tls_cert = _collect_device_tls_cert(
                backend, host, resolved_ips[0] if resolved_ips else "", port=port, output_dir=output_dir
            )
    else:
        notes.append("device_shell_unavailable")

    matched_block_ips = [ip for ip in resolved_ips if ip in block_set]
    if matched_block_ips:
        status = "BLOCKED"
        matched_kw = [f"block_ip:{ip}" for ip in matched_block_ips]
        notes.append(f"Bloqueio confirmado pelo IP DNS no dispositivo: {', '.join(matched_block_ips)}")
    elif http_status is not None and 200 <= http_status < 400:
        status = "LOADED"
        matched_kw = []
    elif http_status is not None and http_status >= 400:
        status = "BLOCKED"
        matched_kw = [f"http_{http_status}"]
    elif resolved_ips and (tcp_rtt_ms is not None or device_ping_rtt_ms is not None):
        status = "LOADED"
        matched_kw = []
    else:
        # Deixa a classificação da UI do Chrome/App no dispositivo decidir se não houve resposta de rede
        status = "UNKNOWN"
        matched_kw = []

    total_ms = int((time.monotonic() - t_total_start) * 1000)
    probe = awc.EndpointProbeResult(
        url=url,
        resolved_ips=resolved_ips,
        http_status=http_status,
        status=status,
        matched_keywords=matched_kw,
        error="; ".join(notes),
    )
    wf = WaterfallEntry(
        category="probe",
        target=url,
        status=status,
        dns_server_used=dns_used,
        dns_rtt_ms=dns_rtt_ms,
        tcp_rtt_ms=tcp_rtt_ms,
        tls_rtt_ms=tls_rtt_ms,
        ttfb_ms=ttfb_ms,
        device_ping_rtt_ms=device_ping_rtt_ms,
        total_load_ms=total_ms,
        http_status=http_status,
        content_bytes=content_bytes,
        resolved_ips=resolved_ips,
        tls_certificate=tls_cert,
        network_requests=network_requests,
        details="; ".join(notes) or "OK",
    )
    return probe, wf


class WifiStateManager:
    """Detecta e desativa o Wi-Fi no Android durante os testes, restaurando o estado original ao final."""

    def __init__(self, backend: KobitonBackend, log: logging.Logger):
        self.backend = backend
        self.log = log
        self.initial_enabled: Optional[bool] = None
        self.disabled_by_script = False

    def detect(self) -> Optional[bool]:
        if self.backend.shell_supported is not False:
            res = self.backend.shell(["settings", "get", "global", "wifi_on"], timeout=5)
            val = (res.stdout or "").strip()
            if val in ("0", "1", "2", "3"):
                # Em Android, 1 ou 2 indica Wi-Fi ativado; 0 indica desativado
                self.initial_enabled = val != "0"
                return self.initial_enabled
        return None

    def disable_for_tests(self) -> Optional[bool]:
        self.detect()
        if self.initial_enabled is False:
            self.log.info("Wi-Fi do Android já está desativado.")
            return False

        self.log.info("Desativando Wi-Fi no Android para garantir uso da rede móvel (SIM1)...")
        if self.backend.shell_supported is not False:
            self.backend.shell(["svc", "wifi", "disable"], timeout=6)
            self.backend.shell(["cmd", "wifi", "set-wifi-enabled", "disabled"], timeout=6)
            time.sleep(2.0)
            self.disabled_by_script = True
            val = (self.backend.shell(["settings", "get", "global", "wifi_on"], timeout=5).stdout or "").strip()
            is_on = val != "0" if val in ("0", "1", "2", "3") else False
            self.log.info("Wi-Fi do Android desativado (wifi_on=%s).", val or "-")
            return is_on
        return None

    def restore(self) -> Optional[bool]:
        if not self.disabled_by_script or self.initial_enabled is not True:
            return self.initial_enabled
        if self.backend.shell_supported is not False:
            self.log.info("Restaurando Wi-Fi do Android para o estado original (ativado)...")
            self.backend.shell(["svc", "wifi", "enable"], timeout=6)
            self.backend.shell(["cmd", "wifi", "set-wifi-enabled", "enabled"], timeout=6)
            time.sleep(2.0)
            val = (self.backend.shell(["settings", "get", "global", "wifi_on"], timeout=5).stdout or "").strip()
            return val != "0" if val in ("0", "1", "2", "3") else True
        return None


class AndroidDnsManager:
    """Altera temporariamente o DNS no Android (quando solicitado) e restaura ao final."""

    def __init__(self, backend: KobitonBackend, log: logging.Logger):
        self.backend = backend
        self.log = log
        self.orig_private_dns_mode: Optional[str] = None
        self.orig_private_dns_specifier: Optional[str] = None
        self.changed = False

    def apply(self, dns_servers: Sequence[str]) -> bool:
        if self.backend.shell_supported is False:
            return False
        mode_res = self.backend.shell(["settings", "get", "global", "private_dns_mode"], timeout=5)
        spec_res = self.backend.shell(["settings", "get", "global", "private_dns_specifier"], timeout=5)
        self.orig_private_dns_mode = (mode_res.stdout or "").strip()
        self.orig_private_dns_specifier = (spec_res.stdout or "").strip()

        # Desativa Private DNS (DoT) para garantir que o Android use o DNS IPv4/IPv6 da APN/configurado
        r1 = self.backend.shell(["settings", "put", "global", "private_dns_mode", "off"], timeout=5)
        if dns_servers:
            self.backend.shell(["setprop", "net.dns1", dns_servers[0]], timeout=5)
            if len(dns_servers) > 1:
                self.backend.shell(["setprop", "net.dns2", dns_servers[1]], timeout=5)
        if r1.returncode == 0:
            self.changed = True
            self.log.info(
                "Android Private DNS ajustado para 'off' (original: mode=%s, specifier=%s) para uso do DNS alvo %s.",
                self.orig_private_dns_mode or "-",
                self.orig_private_dns_specifier or "-",
                list(dns_servers),
            )
            return True
        return False

    def restore(self) -> None:
        if not self.changed or self.backend.shell_supported is False:
            return
        try:
            if self.orig_private_dns_mode in ("null", "None", ""):
                self.backend.shell(["settings", "delete", "global", "private_dns_mode"], timeout=5)
            elif self.orig_private_dns_mode is not None:
                self.backend.shell(
                    ["settings", "put", "global", "private_dns_mode", self.orig_private_dns_mode], timeout=5
                )
            if self.orig_private_dns_specifier and self.orig_private_dns_specifier not in ("null", "None"):
                self.backend.shell(
                    ["settings", "put", "global", "private_dns_specifier", self.orig_private_dns_specifier], timeout=5
                )
            self.log.info("Configuração de Private DNS do Android restaurada (mode=%s).", self.orig_private_dns_mode)
        finally:
            self.changed = False


def parse_cellular_apn_from_dumpsys(dumpsys_output: str) -> CellularApnTelemetry:
    """Extrai APN registrada, interface, IPv4, IPv6 e DNS da rede móvel em `dumpsys connectivity`."""
    tel = CellularApnTelemetry()
    if not dumpsys_output:
        return tel

    # Procura bloco NetworkAgentInfo da rede MOBILE / CELLULAR conectada
    for line in dumpsys_output.splitlines():
        if "NetworkAgentInfo{" not in line:
            continue
        if "MOBILE" not in line and "CELLULAR" not in line:
            continue

        m_type = re.search(r"MOBILE\[([^\]]+)\]", line)
        if m_type:
            tel.network_type = m_type.group(1).strip()

        m_apn = re.search(r"extra:\s*([^,}]+)", line)
        if m_apn:
            tel.apn_name = m_apn.group(1).strip()

        m_iface = re.search(r"InterfaceName:\s*(\S+)", line)
        if m_iface:
            tel.interface = m_iface.group(1).strip()

        m_links = re.search(r"LinkAddresses:\s*\[([^\]]*)\]", line)
        if m_links:
            for addr in m_links.group(1).split(","):
                ip = addr.strip().split("/")[0].strip()
                if not ip:
                    continue
                if ":" in ip and ip not in tel.ipv6_addresses:
                    tel.ipv6_addresses.append(ip)
                elif "." in ip and ip not in tel.ipv4_addresses:
                    tel.ipv4_addresses.append(ip)

        m_dns = re.search(r"DnsAddresses:\s*\[([^\]]*)\]", line)
        if m_dns:
            for d in m_dns.group(1).split(","):
                ip = d.strip().lstrip("/").strip()
                if ip and ip not in tel.dns_addresses:
                    tel.dns_addresses.append(ip)

        if tel.apn_name or tel.ipv4_addresses or tel.dns_addresses:
            break

    return tel


def collect_cellular_apn_telemetry(
    backend: KobitonBackend,
    wifi_mgr: Optional[WifiStateManager],
    log: logging.Logger,
    expected_dns_servers: Sequence[str] = (),
) -> CellularApnTelemetry:
    """Coleta telemetria completa do SIM1, APN registrada, IPv4, IPv6 e DNS recebidos da APN."""
    tel = CellularApnTelemetry()
    if backend.shell_supported is False:
        return tel

    conn_out = backend.shell(["dumpsys", "connectivity"], timeout=10).stdout
    tel = parse_cellular_apn_from_dumpsys(conn_out)
    tel.sim1_operator = (backend.shell(["getprop", "gsm.sim.operator.alpha"], timeout=4).stdout or "").strip()
    tel.sim1_mcc_mnc = (backend.shell(["getprop", "gsm.sim.operator.numeric"], timeout=4).stdout or "").strip()
    tel.sim_state = (backend.shell(["getprop", "gsm.sim.state"], timeout=4).stdout or "").strip()
    if not tel.network_type:
        tel.network_type = (backend.shell(["getprop", "gsm.network.type"], timeout=4).stdout or "").strip()
    roaming = (backend.shell(["getprop", "gsm.operator.isroaming"], timeout=4).stdout or "").strip()

    for prop in ("net.dns1", "net.dns2", "net.dns3"):
        ip = (backend.shell(["getprop", prop], timeout=4).stdout or "").strip()
        if ip and ip not in tel.dns_addresses:
            tel.dns_addresses.append(ip)

    if wifi_mgr is not None:
        tel.wifi_initially_enabled = wifi_mgr.initial_enabled
        tel.wifi_disabled_during_tests = wifi_mgr.disabled_by_script

    if expected_dns_servers:
        tel.dns_match_state = "SUCCESSFUL" if any(d in tel.dns_addresses for d in expected_dns_servers) else "MISMATCH"
    state_label = "SUCCESSFUL" if tel.dns_match_state == "SUCCESSFUL" else (tel.sim_state or "-")

    tel.raw_summary = (
        f"SIM={tel.sim1_operator or '-'} ({tel.sim1_mcc_mnc or '-'}) | "
        f"State={state_label} | Net={tel.network_type or '-'} | Roaming={roaming or '-'} | "
        f"APN={tel.apn_name or '-'} | Iface={tel.interface or '-'} | "
        f"IPv4={tel.ipv4_addresses} | IPv6={tel.ipv6_addresses} | DNS_APN={tel.dns_addresses}"
    )
    log.info("Telemetria SIM1/APN: %s", tel.raw_summary)
    return tel


class ApnRegistrationError(RuntimeError):
    """Erro lançado quando o SIM1 não registra na APN dentro do tempo máximo."""


def is_apn_registered(tel: CellularApnTelemetry) -> bool:
    """Retorna True se o SIM1 estiver registrado em uma APN com endereço IPv4 ou IPv6."""
    return bool(tel.apn_name) and (bool(tel.ipv4_addresses) or bool(tel.ipv6_addresses))


def check_device_internet_connectivity(backend: KobitonBackend, log: logging.Logger) -> bool:
    """Verifica se o dispositivo Android já navega na internet pela rede móvel (DNS + TCP/ICMP)."""
    if backend.shell_supported is False:
        return True

    ping_res = backend.shell(["ping", "-c", "1", "-W", "4", "www.google.com"], timeout=8)
    if ping_res.returncode == 0 and ("ttl=" in ping_res.stdout.lower() or "1 received" in ping_res.stdout.lower()):
        log.info("Conectividade Internet (SIM1) confirmada via ping www.google.com.")
        return True

    nc_res = backend.shell(["toybox", "nc", "-z", "-w", "4", "www.google.com", "443"], timeout=8)
    if nc_res.returncode == 0:
        log.info("Conectividade Internet (SIM1) confirmada via TCP/443 www.google.com.")
        return True

    nc_dns = backend.shell(["toybox", "nc", "-z", "-w", "4", "8.8.8.8", "53"], timeout=8)
    if nc_dns.returncode == 0:
        log.info("Conectividade Internet (SIM1) confirmada via TCP/53 8.8.8.8.")
        return True

    return False


def wait_for_sim1_apn_registration(
    backend: KobitonBackend,
    wifi_mgr: Optional[WifiStateManager],
    output_dir: Path,
    log: logging.Logger,
    schedule: Sequence[int] = APN_CHECK_SCHEDULE_SECONDS,
    expected_dns_servers: Sequence[str] = (),
) -> CellularApnTelemetry:
    """
    Confirma que o SIM1 está registrado na APN e navegando na internet antes de prosseguir.
    Se não estiver pronto, verifica nos marcos 5s, 15s, 45s, 2m (120s) e 5m (300s).
    Caso não registre/conecte até 5m, gera evidência de erro e aborta o teste.
    """
    tel = collect_cellular_apn_telemetry(backend, wifi_mgr, log, expected_dns_servers=expected_dns_servers)
    if is_apn_registered(tel) and check_device_internet_connectivity(backend, log):
        log.info(
            "SIM1 registrado na APN com internet ativa. Prosseguindo. [%s]",
            tel.raw_summary,
        )
        return tel

    log.warning("SIM1 ainda sem APN/internet ativa. Iniciando verificações (5s, 15s, 45s, 2m, 5m)...")
    elapsed = 0
    for checkpoint in schedule:
        delta = max(0, checkpoint - elapsed)
        if delta > 0:
            time.sleep(delta)
        elapsed = checkpoint
        label = f"{checkpoint}s" if checkpoint < 60 else f"{checkpoint // 60}m"
        tel = collect_cellular_apn_telemetry(backend, wifi_mgr, log, expected_dns_servers=expected_dns_servers)
        if is_apn_registered(tel) and check_device_internet_connectivity(backend, log):
            log.info(
                "SIM1 registrado na APN com internet ativa após %s. [%s]",
                label,
                tel.raw_summary,
            )
            return tel
        log.warning("SIM1 ainda sem APN/internet ativa no marco %s (%s).", label, tel.raw_summary)

    png_path = output_dir / "screenshots" / "03c_apn_registration_failed.png"
    awc.render_evidence_card(
        png_path,
        title="SIM1 APN Registration Failed",
        status="ABORTED",
        bypass_risk="N/A",
        lines=[
            "SIM1 nao registrou na APN dentro de 5 minutos (5s, 15s, 45s, 2m, 5m).",
            f"Operadora: {tel.sim1_operator or '-'} ({tel.sim1_mcc_mnc or '-'})",
            f"SIM State: {tel.sim_state or '-'} | Rede: {tel.network_type or '-'}",
            f"APN: {tel.apn_name or '-'} | IPv4: {tel.ipv4_addresses} | IPv6: {tel.ipv6_addresses}",
        ],
    )
    msg = (
        f"ABORTADO: SIM1 não registrou na APN após 5 minutos "
        f"(APN={tel.apn_name or '-'}, IPv4={tel.ipv4_addresses}, IPv6={tel.ipv6_addresses})."
    )
    log.error(msg)
    raise ApnRegistrationError(msg)


def clear_browser_cache(backend: KobitonBackend, log: logging.Logger) -> bool:
    """Limpa o cache do navegador (Google Chrome) no Android antes de iniciar os testes."""
    if backend.shell_supported is False:
        log.warning("Limpeza de cache do navegador ignorada: `mobile: shell` indisponível.")
        return False

    log.info("Limpando cache do navegador Google Chrome no Android antes dos testes...")
    backend.shell(["am", "force-stop", awc.CHROME_PACKAGE], timeout=6)
    backend.shell(["rm", "-rf", f"/sdcard/Android/data/{awc.CHROME_PACKAGE}/cache"], timeout=6)
    backend.shell(["pm", "trim-caches", "100G"], timeout=8)
    log.info("Cache do navegador limpo com sucesso.")
    return True


TERMUX_PACKAGE = "com.termux"
TERMUX_ACTIVITY = "com.termux.app.TermuxActivity"


def _run_termux_dns_and_curl_probe(
    backend: KobitonBackend,
    dns_ip: str,
    png_path: Path,
    log: logging.Logger,
) -> Tuple[bool, Optional[bool], str]:
    """
    Abre o Termux no Android, executa `dig @<dns_ip>` e `curl --write-out`
    (instalando `dnsutils` e `curl` via `pkg install -y` caso não existam) e
    tira o screenshot `04_dns_connectivity_*.png` diretamente da tela do shell.
    """
    if backend.shell_supported is False:
        return False, None, ""

    backend.shell(["logcat", "-c"], timeout=5)
    launch = backend.shell(["am", "start", "-n", f"{TERMUX_PACKAGE}/{TERMUX_ACTIVITY}"], timeout=8)
    if launch.returncode != 0:
        launch = backend.shell(
            ["monkey", "-p", TERMUX_PACKAGE, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout=8,
        )
    if launch.returncode != 0:
        return False, None, ""

    time.sleep(2.5)
    xml_init = backend.dump_ui_xml()
    if xml_init:
        init_nodes = awc.parse_ui_nodes(xml_init)
        perm_btn = awc.find_node_by_labels(
            init_nodes,
            ("permitir", "allow", "permission_allow_button", "while using the app"),
        )
        if perm_btn is not None:
            cx, cy = perm_btn.center
            backend.tap(cx, cy)
            time.sleep(1.0)
            xml_init = backend.dump_ui_xml()
            init_nodes = awc.parse_ui_nodes(xml_init)
        term_node = awc.find_node_by_labels(init_nodes, ("terminal_view",))
        if term_node is not None:
            x1, y1, x2, y2 = term_node.bounds
            backend.tap((x1 + x2) // 2, min(max(220, y1 + 180), max(220, y2 - 100)))
            time.sleep(0.4)

    fg = awc.get_foreground_package(backend)
    if fg and TERMUX_PACKAGE not in fg:
        return False, None, ""

    def _termux_type_line(cmd_line: str, wait_s: float = 2.0, chunk_size: int = 16) -> None:
        # `TerminalView` do Termux não é `EditText`, portanto `send_keys_active` (setText) é ignorado.
        # Digitamos sempre via `input text` no shell do dispositivo em blocos curtos para não perder caracteres.
        for i in range(0, len(cmd_line), chunk_size):
            piece = cmd_line[i : i + chunk_size].replace(" ", "%s")
            backend.shell(["input", "text", piece], timeout=8)
            time.sleep(0.18)
        enter_res = backend.shell(["input", "keyevent", "66"], timeout=6)
        if enter_res.returncode != 0:
            backend.keyevent("KEYCODE_ENTER")
        time.sleep(wait_s)

    dig_cmd = f"dig @{dns_ip} malware.test.attacker.online +noall +comments +question +answer +stats +time=4 +tries=1"
    curl_cmd = (
        "curl -sS -k -m 6 -o /dev/null --write-out "
        "HTTP_Status:%{http_code}\\\\\\\\n"
        "Remote_IP:%{remote_ip}:%{remote_port}\\\\\\\\n"
        "DNS_Lookup:%{time_namelookup}s\\\\\\\\n"
        "TCP_Connect:%{time_connect}s\\\\\\\\n"
        "TLS_Handshake:%{time_appconnect}s\\\\\\\\n"
        "TTFB:%{time_starttransfer}s\\\\\\\\n"
        "Total_Time:%{time_total}s\\\\\\\\n"
        "Size_Bytes:%{size_download}B\\\\\\\\n "
        "https://malware.test.attacker.online"
    )

    # Verifica silenciosamente via `run-as` (sem poluir o terminal do Termux) se `dig` e `curl` já existem
    chk_tools = backend.shell(
        [
            "run-as",
            TERMUX_PACKAGE,
            "sh",
            "-c",
            "test -x /data/data/com.termux/files/usr/bin/dig && test -x /data/data/com.termux/files/usr/bin/curl",
        ],
        timeout=5,
    )
    chk_err = (chk_tools.stderr or "").lower()
    if chk_tools.returncode != 0 and "not debuggable" not in chk_err and "permission" not in chk_err and "unknown package" not in chk_err:
        log.info("Comandos `dig`/`curl` ausentes no Termux; instalando via `pkg install -y dnsutils curl`...")
        _termux_type_line("yes | pkg install -y dnsutils curl", wait_s=25.0)

    _termux_type_line("clear", wait_s=1.0)
    _termux_type_line(dig_cmd, wait_s=4.5)
    _termux_type_line(curl_cmd, wait_s=5.0)

    xml = backend.dump_ui_xml()
    screen_low = xml.lower()
    if any(
        err in screen_low
        for err in ("no command dig", "no command curl", "dig: not found", "curl: not found", "command not found")
    ):
        log.info("Comandos `dig`/`curl` ausentes no Termux; instalando via `pkg install -y dnsutils curl`...")
        _termux_type_line("yes | pkg install -y dnsutils curl", wait_s=25.0)
        _termux_type_line("clear", wait_s=1.0)
        _termux_type_line(dig_cmd, wait_s=4.5)
        _termux_type_line(curl_cmd, wait_s=5.0)
        xml = backend.dump_ui_xml()
        screen_low = xml.lower()

    dig_ok: Optional[bool] = None
    if "status: noerror" in screen_low or "query time:" in screen_low or "answer section" in screen_low:
        dig_ok = True
    elif "connection timed out" in screen_low or "no servers could be reached" in screen_low:
        dig_ok = False

    has_shot = backend.screencap(png_path)
    return has_shot, dig_ok, "termux_dig_curl_shell"


def test_dns_server_connectivity(
    backend: KobitonBackend,
    dns_servers: Sequence[str],
    output_dir: Path,
    log: logging.Logger,
    timeout: int = 4,
) -> List[DnsConnectivityResult]:
    """Testa conectividade EXCLUSIVAMENTE a partir do dispositivo Android para cada DNS destino."""
    results: List[DnsConnectivityResult] = []

    for idx, dns_ip in enumerate(dns_servers, start=1):
        t0 = time.monotonic()
        device_ping_ok: Optional[bool] = None
        device_ping_rtt_ms: Optional[float] = None
        device_tcp_53_ok: Optional[bool] = None
        device_dns_ok: Optional[bool] = None
        notes: List[str] = []

        if backend.shell_supported is not False:
            ping_res = backend.shell(["ping", "-c", "2", "-W", str(timeout), dns_ip], timeout=timeout * 3)
            if ping_res.returncode == 0 and (
                "ttl=" in ping_res.stdout.lower()
                or "1 received" in ping_res.stdout.lower()
                or "2 received" in ping_res.stdout.lower()
            ):
                device_ping_ok = True
                m_rtt = re.search(r"time[=<]\s*([\d.]+)\s*ms", ping_res.stdout)
                if m_rtt:
                    device_ping_rtt_ms = float(m_rtt.group(1))
            elif backend.shell_supported:
                device_ping_ok = False
                notes.append("device_ping_failed")

            nc_res = backend.shell(["toybox", "nc", "-z", "-w", str(timeout), dns_ip, "53"], timeout=timeout + 3)
            if nc_res.returncode == 0:
                device_tcp_53_ok = True
            elif "not found" not in (nc_res.stderr or "").lower():
                device_tcp_53_ok = False

            ns_res = backend.shell(["nslookup", "www.google.com", dns_ip], timeout=timeout + 3)
            if ns_res.returncode == 0 and "address" in ns_res.stdout.lower():
                device_dns_ok = True
            elif backend.shell_supported and "not found" not in (ns_res.stderr or "").lower():
                device_dns_ok = False
        else:
            notes.append("device_shell_unavailable")

        safe_ip = re.sub(r"[^a-zA-Z0-9._-]+", "_", dns_ip)
        png_path = output_dir / "screenshots" / f"04_dns_connectivity_{idx:02d}_{safe_ip}.png"
        termux_shot, termux_dig_ok, termux_note = _run_termux_dns_and_curl_probe(backend, dns_ip, png_path, log)
        if termux_dig_ok is not None:
            device_dns_ok = termux_dig_ok
        if termux_note:
            notes.append(termux_note)

        latency_ms = int((time.monotonic() - t0) * 1000)
        if device_ping_ok or device_tcp_53_ok or device_dns_ok:
            status = "REACHABLE"
        else:
            status = "UNREACHABLE"

        if termux_shot and png_path.is_file():
            awc.annotate_screenshot_with_banner(
                png_path,
                title=f"Termux DNS & Curl Probe: @{dns_ip}",
                subtitle=f"dig @{dns_ip} + curl --write-out | Ping: {device_ping_ok} ({device_ping_rtt_ms}ms) | TCP/53: {device_tcp_53_ok}",
                status=status,
                bypass_risk="N/A",
            )
        else:
            awc.render_evidence_card(
                png_path,
                title=f"Device DNS Connectivity: {dns_ip}",
                status=status,
                bypass_risk="N/A",
                lines=[
                    f"Servidor DNS destino: {dns_ip}:53 (testado no Android)",
                    f"Device ping: {device_ping_ok} (RTT: {device_ping_rtt_ms} ms)",
                    f"Device TCP/53: {device_tcp_53_ok} | Device DNS/dig: {device_dns_ok}",
                    f"Latencia total: {latency_ms} ms",
                    f"Detalhes: {'; '.join(notes) or 'OK'}",
                ],
            )

        log.info(
            "Conectividade DNS (Android) %s -> %s (ping=%s rtt=%sms, tcp53=%s, nslookup=%s, %dms)",
            dns_ip,
            status,
            device_ping_ok,
            device_ping_rtt_ms,
            device_tcp_53_ok,
            device_dns_ok,
            latency_ms,
        )
        results.append(
            DnsConnectivityResult(
                dns_server=dns_ip,
                device_ping_ok=device_ping_ok,
                device_ping_rtt_ms=device_ping_rtt_ms,
                device_tcp_53_ok=device_tcp_53_ok,
                device_dns_ok=device_dns_ok,
                latency_ms=latency_ms,
                status=status,
                details="; ".join(notes) or "OK",
                screenshot_path=str(png_path) if png_path.is_file() else "",
            )
        )

    return results


DISMISS_POPUP_LABELS = (
    "agora não",
    "agora nao",
    "not now",
    "no thanks",
    "não, obrigado",
    "nao, obrigado",
    "continuar sem conta",
    "continuar sem iniciar sessão",
    "use without an account",
    "aceitar e continuar",
    "accept & continue",
    "dispensar",
    "dismiss",
    "entendi",
    "got it",
)

SECURITY_ERROR_HINTS = (
    "your connection is not private",
    "a sua ligação não é privada",
    "sua conexão não é particular",
    "err_cert_",
    "err_ssl",
    "avançadas",
    "advanced",
    "back to safety",
    "voltar à segurança",
)


def dismiss_popups_if_present(backend: KobitonBackend, log: logging.Logger, max_attempts: int = 2) -> bool:
    """Dispensa diálogos modais (ex.: 'Desbloqueie as suas palavras-passe... Agora não', onboarding do Chrome)."""
    dismissed = False
    for _ in range(max_attempts):
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        btn = awc.find_node_by_labels(nodes, DISMISS_POPUP_LABELS)
        if not btn:
            break
        log.info("Dispensando diálogo na tela: '%s'", btn.label)
        backend.tap(*btn.center)
        time.sleep(1.5)
        dismissed = True
    return dismissed


def navigate_apps_kobiton(
    backend: KobitonBackend,
    apps: Sequence[Dict[str, object]],
    output_dir: Path,
    private_dns: awc.PrivateDNSStatus,
    wait_sec: int,
    simulate_scroll: bool,
    log: logging.Logger,
) -> List[awc.AppTestResult]:
    """Lança cada aplicativo, dispensa popups de sistema (ex. palavras-passe no Netflix) e captura evidência."""
    installed_pkgs = awc.get_installed_packages(backend)
    results: List[awc.AppTestResult] = []
    bypass_risk = private_dns.bypass_risk if private_dns else "UNKNOWN"

    for idx, app in enumerate(apps, start=1):
        name = str(app.get("name", app["package"]))
        pkg = str(app["package"])
        probe_urls = list(app.get("probe_urls") or [])
        t0 = time.monotonic()

        probe = awc.probe_endpoint_connectivity(probe_urls[0]) if probe_urls else awc.EndpointProbeResult(url="")
        known_missing = bool(installed_pkgs) and (pkg not in installed_pkgs)
        if known_missing:
            log.warning("App não instalado: %s (%s) | Probe rede: %s", name, pkg, probe.status)
            safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", name.lower()).strip("_")
            png_path = output_dir / "screenshots" / f"app_{idx:02d}_{safe_name}.png"
            awc.render_evidence_card(
                png_path,
                title=f"App {name} ({pkg})",
                status="NOT_INSTALLED",
                bypass_risk=bypass_risk,
                lines=[
                    f"Pacote: {pkg} (nao instalado no aparelho)",
                    f"Sondagem de dominio: {probe.url or '-'} -> {probe.status}",
                    f"IPs resolvidos: {', '.join(probe.resolved_ips) or '-'}",
                ],
            )
            results.append(
                awc.AppTestResult(
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
        time.sleep(1.0)
        launch_res = backend.shell(
            ["monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout=10,
        )
        launched = launch_res.returncode == 0
        time.sleep(wait_sec)

        # Dispensa diálogo de palavras-passe / autofill (ex.: Netflix) antes de capturar evidência
        dismiss_popups_if_present(backend, log)

        if simulate_scroll:
            backend.swipe(540, 1450, 540, 750, 400)
            time.sleep(1.5)

        fg_pkg = awc.get_foreground_package(backend)
        fg_ok = fg_pkg == pkg
        ui_nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        ui_status, ui_kw, _ = awc.classify_chrome_screen_text(ui_nodes)

        if probe.status == "BLOCKED" or ui_status == "BLOCKED":
            load_status = "BLOCKED"
        elif probe.status == "ERROR" or ui_status == "ERROR":
            load_status = "ERROR"
        elif probe.status == "LOADED" or launched:
            load_status = "LOADED"
        else:
            load_status = "ERROR"

        safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", name.lower()).strip("_")
        png_path = output_dir / "screenshots" / f"app_{idx:02d}_{safe_name}.png"
        has_png = backend.screencap(png_path)
        if has_png:
            awc.annotate_screenshot_with_banner(
                png_path,
                title=f"App: {name} ({pkg})",
                subtitle=f"IPs: {', '.join(probe.resolved_ips) or '-'} | HTTP: {probe.http_status or '-'}",
                status=load_status,
                bypass_risk=bypass_risk,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        log.info(
            "App %s (%s): status=%s launched=%s fg=%s ips=%s png=%s",
            name,
            pkg,
            load_status,
            launched,
            fg_ok,
            probe.resolved_ips,
            png_path.name if has_png else "FAILED",
        )
        results.append(
            awc.AppTestResult(
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


CERT_ADVANCED_LABELS = ("avançadas", "avancadas", "advanced", "detalhes", "details")
CERT_PROCEED_LABELS = (
    "avançar para",
    "avancar para",
    "ir para",
    "prosseguir para",
    "continuar para",
    "proceed to",
    "visit this website",
    "visitar este website",
    "unsafe",
    "não seguro",
    "nao seguro",
)


def _classify_kobiton_screen_text(nodes: Sequence[awc.UINode]) -> Tuple[str, List[str], str]:
    """
    Classifica o conteúdo do ecrã do Chrome evitando falso positivo de 'blocked'
    quando o servidor de sinkhole Whalebone exibe 'This site is not blocked'.
    """
    texts = [n.label for n in nodes if n.label]
    if not texts:
        return "UNKNOWN", [], ""
    joined = " | ".join(texts)
    lower = joined.lower()
    snippet = joined[:240]

    if "this site is not blocked" in lower or "nothing is blocked for you" in lower:
        return "SINKHOLE_NOT_BLOCKED_MSG", ["sinkhole_unblocked_msg"], snippet

    return awc.classify_chrome_screen_text(nodes)


def _capture_chrome_certificate_viewer_screenshot(
    backend: KobitonBackend,
    cert_details_png: Path,
    log: logging.Logger,
) -> bool:
    """
    Abre o Visualizador de Certificados do próprio Chrome (ícone de status na barra de URL ->
    A ligação não é segura -> Informações do certificado) e tira o screenshot do certificado de sinkhole.
    """
    nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
    status_icon = next(
        (
            n
            for n in nodes
            if any(
                rid in n.resource_id
                for rid in ("location_bar_status_icon", "location_bar_status", "security_button")
            )
            or any(
                lbl in (n.label or "").lower()
                for lbl in (
                    "ver informações do site",
                    "view site information",
                    "informações do site",
                    "site information",
                    "não seguro",
                    "not secure",
                )
            )
        ),
        None,
    )
    if not status_icon:
        return False

    log.info("Abrindo informações do site/certificado no Chrome...")
    backend.tap(*status_icon.center)
    time.sleep(1.2)
    nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
    steps = 1

    conn_row = awc.find_node_by_labels(
        nodes,
        (
            "a ligação não é segura",
            "sua conexão não é segura",
            "connection is not secure",
            "ligação",
            "conexão",
            "connection",
        ),
    )
    if conn_row:
        backend.tap(*conn_row.center)
        time.sleep(1.2)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        steps += 1

    cert_row = awc.find_node_by_labels(
        nodes,
        (
            "informações do certificado",
            "informacoes do certificado",
            "detalhes do certificado",
            "certificate information",
            "certificate details",
            "certificate viewer",
            "certificado",
            "certificate",
        ),
    )
    if cert_row:
        backend.tap(*cert_row.center)
        time.sleep(1.2)
        steps += 1

    captured = backend.screencap(cert_details_png)
    for _ in range(steps):
        backend.keyevent("KEYCODE_BACK")
        time.sleep(0.6)
    return captured


def _proceed_past_chrome_cert_warning(
    backend: KobitonBackend,
    log: logging.Logger,
    cert_details_png: Optional[Path] = None,
) -> bool:
    """
    Na tela de erro de certificado do Chrome, clica em Avançadas, tira print dos
    detalhes do certificado de sinkhole no próprio browser e clica em Avançar para o site.
    """
    nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
    adv_btn = awc.find_node_by_labels(nodes, CERT_ADVANCED_LABELS)
    if adv_btn:
        log.info("Erro de certificado detectado: clicando em '%s'...", adv_btn.label)
        backend.tap(*adv_btn.center)
        time.sleep(1.5)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())

    # Tira screenshot do certificado de sinkhole diretamente no browser (detalhes expandidos ou viewer)
    if cert_details_png is not None:
        err_node = next((n for n in nodes if "err_cert_" in (n.label or "").lower()), None)
        if err_node and err_node.clickable:
            backend.tap(*err_node.center)
            time.sleep(1.2)
            nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        backend.screencap(cert_details_png)

    proceed_btn = awc.find_node_by_labels(nodes, CERT_PROCEED_LABELS)
    if not proceed_btn:
        backend.swipe(540, 1400, 540, 700, 350)
        time.sleep(1.2)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        if cert_details_png is not None and not cert_details_png.is_file():
            backend.screencap(cert_details_png)
        proceed_btn = awc.find_node_by_labels(nodes, CERT_PROCEED_LABELS)

    if proceed_btn:
        log.info("Clicando para abrir página apesar do erro de certificado: '%s'...", proceed_btn.label)
        backend.tap(*proceed_btn.center)
        return True

    log.warning("Botão para prosseguir na página de erro de certificado não encontrado.")
    return False


def _close_chrome_tab(backend: KobitonBackend, log: logging.Logger) -> None:
    """Fecha a aba atual do Chrome via seletor de abas ou força encerramento se necessário."""
    nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
    tab_btn = next(
        (
            n
            for n in nodes
            if "tab_switcher" in n.resource_id
            or any(
                k in (n.label or "").lower()
                for k in ("switch or close tabs", "trocar ou fechar separadores", "alternar ou fechar guias")
            )
        ),
        None,
    )
    if tab_btn:
        backend.tap(*tab_btn.center)
        time.sleep(1.0)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        close_btn = next(
            (
                n
                for n in nodes
                if "close_tab_button" in n.resource_id
                or "action_button" in n.resource_id
                or any(k in (n.label or "").lower() for k in ("fechar separador", "close tab", "fechar guia"))
            ),
            None,
        )
        if close_btn:
            backend.tap(*close_btn.center)
            time.sleep(0.8)
            return
    # Fallback: encerra a instância do Chrome para não acumular abas abertas
    backend.shell(["am", "force-stop", awc.CHROME_PACKAGE], timeout=6)
    log.debug("Página do Chrome encerrada via force-stop.")


def _close_all_chrome_tabs(backend: KobitonBackend, log: logging.Logger) -> None:
    """Fecha todas as abas abertas no Chrome antes de encerrar o aplicativo."""
    try:
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        tab_btn = next(
            (
                n
                for n in nodes
                if "tab_switcher" in n.resource_id
                or any(
                    k in (n.label or "").lower()
                    for k in ("switch or close tabs", "trocar ou fechar separadores", "alternar ou fechar guias")
                )
            ),
            None,
        )
        if tab_btn:
            backend.tap(*tab_btn.center)
            time.sleep(1.2)
            nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
            menu_btn = awc.find_node_by_labels(nodes, ("more options", "mais opções", "mais opcoes"))
            if menu_btn:
                backend.tap(*menu_btn.center)
                time.sleep(1.0)
                nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
                close_all = awc.find_node_by_labels(
                    nodes, ("close all tabs", "fechar todos os separadores", "fechar todas as guias")
                )
                if close_all:
                    backend.tap(*close_all.center)
                    time.sleep(1.0)
                    nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
                    confirm = awc.find_node_by_labels(
                        nodes, ("close all", "fechar tudo", "fechar todos", "ok")
                    )
                    if confirm and confirm.clickable:
                        backend.tap(*confirm.center)
                        time.sleep(1.0)
    finally:
        backend.shell(["am", "force-stop", awc.CHROME_PACKAGE], timeout=6)
        log.info("Abas fechadas e navegador Chrome encerrado ao término dos testes.")


def _reload_chrome_page(backend: KobitonBackend, url: str, host: str, log: logging.Logger) -> None:
    """Força nova resolução DNS no aparelho e recarrega a página atual no Chrome."""
    if host and backend.shell_supported is not False:
        backend.shell(["ping", "-c", "1", "-W", "4", host], timeout=6)
    nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
    reload_btn = next(
        (
            n
            for n in nodes
            if "refresh_button" in n.resource_id
            or "reload" in n.resource_id
            or any(k in (n.label or "").lower() for k in ("reload", "recarregar", "atualizar"))
        ),
        None,
    )
    if reload_btn:
        backend.tap(*reload_btn.center)
        return
    menu_btn = awc.find_node_by_labels(nodes, ("more options", "mais opções", "mais opcoes"))
    if menu_btn:
        backend.tap(*menu_btn.center)
        time.sleep(1.0)
        nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
        reload_item = next(
            (
                n
                for n in nodes
                if "reload" in n.resource_id
                or any(k in (n.label or "").lower() for k in ("reload", "recarregar", "atualizar"))
            ),
            None,
        )
        if reload_item:
            backend.tap(*reload_item.center)
            return
    backend.shell(["am", "start", "-a", "android.intent.action.VIEW", "-p", awc.CHROME_PACKAGE, "-d", url], timeout=10)


CHROME_TOOLBAR_IGNORES = (
    "home",
    "início",
    "inicio",
    "more options",
    "mais opções",
    "mais opcoes",
    "switch or close tabs",
    "trocar ou fechar separadores",
    "alternar ou fechar guias",
    "share",
    "partilhar",
    "compartilhar",
    "bookmark",
    "favorito",
    "voice search",
    "pesquisa por voz",
    "nova guia",
    "new tab",
    "novo separador",
)


def _is_chrome_page_ready(nodes: Sequence[awc.UINode], host: str = "") -> bool:
    """Verifica se o Chrome concluiu o carregamento (sem progress_bar/stop_loading e com view/conteúdo ativo)."""
    if not nodes:
        return False
    has_progress = any(
        "progress" in n.resource_id.lower()
        or "progressbar" in n.class_name.lower()
        or any(
            k in (n.label or "").lower()
            for k in ("stop page loading", "parar carregamento", "interromper carregamento")
        )
        for n in nodes
    )
    if has_progress:
        return False

    non_bar_texts = [
        n.label
        for n in nodes
        if n.label
        and "url_bar" not in n.resource_id
        and "search_box" not in n.resource_id
        and "tab_switcher" not in n.resource_id
        and "menu_button" not in n.resource_id
        and "home_button" not in n.resource_id
        and n.label.strip().lower() not in CHROME_TOOLBAR_IGNORES
    ]
    joined = " ".join(non_bar_texts).lower()
    if any(h in joined for h in SECURITY_ERROR_HINTS):
        return True
    if any(kw in joined for kw in awc.BLOCK_KEYWORDS) or any(kw in joined for kw in awc.ERROR_KEYWORDS):
        return True
    if len(non_bar_texts) >= 1:
        return True

    # Mesmo quando o WebView do Chrome não expõe nós de texto HTML ao uiautomator,
    # a ausência de barra de progresso com WebView/compositor/url_bar presente indica carregamento concluído
    has_chrome_surface = any(
        "webview" in n.class_name.lower()
        or any(
            rid in n.resource_id.lower()
            for rid in ("compositor_view_holder", "content", "url_bar", "coordinator")
        )
        for n in nodes
    )
    return has_chrome_surface


def _is_png_mostly_blank(png_path: Path) -> bool:
    """Verifica via Pillow se a imagem capturada está praticamente toda em branco/preto."""
    if not awc.HAS_PILLOW or not png_path.is_file():
        return False
    try:
        with awc.Image.open(png_path) as img:
            rgb = img.convert("RGB")
            w, h = rgb.size
            crop = rgb.crop((0, int(h * 0.18), w, int(h * 0.90)))
            extrema = crop.getextrema()
            return all((hi - lo) < 8 for lo, hi in extrema)
    except Exception:
        return False


def navigate_chrome_urls_kobiton(
    backend: KobitonBackend,
    urls: Sequence[str],
    output_dir: Path,
    private_dns: awc.PrivateDNSStatus,
    page_wait: int,
    add_banner: bool,
    log: logging.Logger,
    wait_schedule: Sequence[int] = PAGE_WAIT_SCHEDULE_SECONDS,
) -> List[awc.ChromeURLResult]:
    """
    Abre cada URL no Chrome, aguarda conclusão nos marcos (5s, 15s, 30s, 1m, 2m),
    trata erro de certificado tirando print antes e depois, e fecha a página aberta ao final.
    """
    results: List[awc.ChromeURLResult] = []

    # Prepara o Chrome dispensando diálogos iniciais
    backend.shell(["am", "start", "-n", f"{awc.CHROME_PACKAGE}/{awc.CHROME_ACTIVITY}"], timeout=10)
    time.sleep(2.5)
    dismiss_popups_if_present(backend, log)

    try:
        for idx, url in enumerate(urls, start=1):
            t0 = time.monotonic()
            host = (urllib.parse.urlparse(url).hostname or "").lower()

            res = backend.shell(
                [
                    "am",
                    "start",
                    "-a",
                    "android.intent.action.VIEW",
                    "-p",
                    awc.CHROME_PACKAGE,
                    "-d",
                    url,
                ],
                timeout=10,
            )
            opened = res.returncode == 0
            time.sleep(2.0)
            dismiss_popups_if_present(backend, log, max_attempts=1)

            # Verifica se a barra de URL realmente navegou para o host; se não, digita na omnibox
            nodes = awc.parse_ui_nodes(backend.dump_ui_xml())
            url_bar = next(
                (n for n in nodes if "url_bar" in n.resource_id or "search_box_text" in n.resource_id),
                None,
            )
            if url_bar and host and host not in (url_bar.label or "").lower():
                log.info("Navegando via omnibox do Chrome para %s...", url)
                backend.tap(*url_bar.center)
                time.sleep(0.8)
                backend.input_text(url)
                backend.keyevent("KEYCODE_ENTER")
                opened = True

            # Regra de espera progressiva por site: 5s, 15s, 30s, 1m (60s), 2m (120s)
            xml = ""
            ui_status = "UNKNOWN"
            matched_kw: List[str] = []
            snippet = ""
            probe = awc.EndpointProbeResult(url=url, status="UNKNOWN")
            detected_status = "UNKNOWN"
            is_sec_error = False

            elapsed = 0
            safe_host = re.sub(r"[^a-zA-Z0-9.-]+", "_", url.replace("https://", "").replace("http://", ""))[:50]
            png_path = output_dir / "screenshots" / f"chrome_{idx:02d}_{safe_host}.png"
            has_png = False
            for cp_idx, checkpoint in enumerate(wait_schedule):
                delta = max(0, checkpoint - elapsed)
                if delta > 0:
                    time.sleep(delta)
                elapsed = checkpoint
                label = f"{checkpoint}s" if checkpoint < 60 else f"{checkpoint // 60}m"
                is_last_cp = cp_idx == (len(wait_schedule) - 1)

                xml = backend.dump_ui_xml()
                nodes = awc.parse_ui_nodes(xml)
                ui_status, matched_kw, snippet = _classify_kobiton_screen_text(nodes)
                lower_snip = snippet.lower()
                is_sec_error = any(h in lower_snip for h in SECURITY_ERROR_HINTS)
                ui_ready = is_sec_error or ui_status in ("BLOCKED", "ERROR") or _is_chrome_page_ready(nodes, host)

                if ui_status == "BLOCKED":
                    detected_status = "BLOCKED"
                elif is_sec_error or ui_status == "ERROR":
                    detected_status = "ERROR"
                    if is_sec_error and "security_error" not in matched_kw:
                        matched_kw.append("security_error")
                elif ui_ready:
                    detected_status = "ALLOWED"
                else:
                    detected_status = "UNKNOWN"

                # Assim que a página ficar pronta (ui_ready=True e não estiver em branco), prossegue imediatamente
                if ui_ready or is_last_cp:
                    has_png = backend.screencap(png_path)
                    if has_png and _is_png_mostly_blank(png_path) and not is_last_cp:
                        log.info("Viewport ainda em branco para %s no marco %s; aguardando próximo marco...", url, label)
                        continue
                    break
                log.info(
                    "Site %s aguardando carregamento completo no marco %s (status=%s, ui_ready=%s)...",
                    url,
                    label,
                    detected_status,
                    ui_ready,
                )

            if not has_png:
                has_png = backend.screencap(png_path)
            if has_png and _is_png_mostly_blank(png_path):
                log.info("Screenshot em branco detectado para %s; aguardando 3s e recapturando...", url)
                time.sleep(3.0)
                has_png = backend.screencap(png_path)

            extra_notes = ""
            # Se houver erro de certificado/segurança, tira o print do erro e do certificado no browser,
            # clica para abrir a página, aguarda o carregamento e tira um novo print confirmando o bloqueio.
            if is_sec_error:
                cert_png_path = output_dir / "screenshots" / f"chrome_{idx:02d}_{safe_host}_01_cert_error.png"
                cert_details_png = output_dir / "screenshots" / f"chrome_{idx:02d}_{safe_host}_02_sinkhole_cert.png"
                if has_png and png_path.is_file():
                    cert_png_path.write_bytes(png_path.read_bytes())

                if _proceed_past_chrome_cert_warning(backend, log, cert_details_png=cert_details_png):
                    # Aguarda o carregamento completo da página após avançar pelo erro de certificado
                    for _ in range(10):
                        time.sleep(2.0)
                        xml_after = backend.dump_ui_xml()
                        if xml_after:
                            xml = xml_after
                        nodes_after = awc.parse_ui_nodes(xml)
                        if _is_chrome_page_ready(nodes_after, host):
                            break
                    nodes_after = awc.parse_ui_nodes(xml)
                    ui_status_after, kw_after, snippet_after = _classify_kobiton_screen_text(nodes_after)
                    if ui_status_after != "BLOCKED":
                        log.info("Atualizando lookup DNS e recarregando página de bloqueio para %s...", url)
                        time.sleep(3.0)
                        _reload_chrome_page(backend, url, host, log)
                        for _ in range(6):
                            time.sleep(2.0)
                            xml_reload = backend.dump_ui_xml()
                            if xml_reload:
                                xml = xml_reload
                            nodes_after = awc.parse_ui_nodes(xml)
                            if _is_chrome_page_ready(nodes_after, host):
                                break
                        ui_status_after, kw_after, snippet_after = _classify_kobiton_screen_text(nodes_after)
                    if snippet_after:
                        snippet = snippet_after
                    if kw_after:
                        matched_kw = list(dict.fromkeys(matched_kw + kw_after))
                    if ui_status_after == "BLOCKED":
                        detected_status = "BLOCKED"
                    elif ui_status_after == "ALLOWED":
                        detected_status = "ALLOWED"

            # Sonda o endpoint no dispositivo APÓS a navegação no Chrome para não consumir o evento de bloqueio antes do browser
            probe = awc.probe_endpoint_connectivity(url)
            if probe.error:
                extra_notes = probe.error
            if probe.status == "BLOCKED":
                detected_status = "BLOCKED"
                matched_kw = list(dict.fromkeys(matched_kw + probe.matched_keywords))
            elif detected_status == "UNKNOWN" and probe.status == "LOADED":
                detected_status = "ALLOWED"

            if is_sec_error:
                after_png_path = output_dir / "screenshots" / f"chrome_{idx:02d}_{safe_host}_02_after_cert_proceed.png"
                has_after_png = backend.screencap(after_png_path)
                # Tenta capturar o Visualizador de Certificados do Chrome após carregar a página
                _capture_chrome_certificate_viewer_screenshot(backend, cert_details_png, log)

                if add_banner and cert_png_path.is_file():
                    awc.annotate_screenshot_with_banner(
                        cert_png_path,
                        title=f"{url} (Cert Warning)",
                        subtitle=f"Chrome Android | IPs: {', '.join(probe.resolved_ips) or '-'} | Keywords: {', '.join(matched_kw) or 'none'}",
                        status=detected_status,
                        bypass_risk=private_dns.bypass_risk,
                    )
                if add_banner and cert_details_png.is_file():
                    awc.annotate_screenshot_with_banner(
                        cert_details_png,
                        title=f"{url} (Sinkhole Certificate)",
                        subtitle=f"Chrome Android | IPs: {', '.join(probe.resolved_ips) or '-'} | Keywords: {', '.join(matched_kw) or 'none'}",
                        status=detected_status,
                        bypass_risk=private_dns.bypass_risk,
                    )
                if has_after_png and add_banner:
                    awc.annotate_screenshot_with_banner(
                        after_png_path,
                        title=f"{url} (After Cert Proceed)",
                        subtitle=f"Chrome Android | IPs: {', '.join(probe.resolved_ips) or '-'} | Keywords: {', '.join(matched_kw) or 'none'}",
                        status=detected_status,
                        bypass_risk=private_dns.bypass_risk,
                    )
                if has_after_png:
                    png_path = after_png_path
                    has_png = True
                    extra_notes = f"{extra_notes}; cert_error_png={cert_png_path.name}; cert_details_png={cert_details_png.name}".strip("; ")
            elif has_png and add_banner:
                awc.annotate_screenshot_with_banner(
                    png_path,
                    title=url,
                    subtitle=f"Chrome Android | IPs: {', '.join(probe.resolved_ips) or '-'} | Keywords: {', '.join(matched_kw) or 'none'}",
                    status=detected_status,
                    bypass_risk=private_dns.bypass_risk,
                )

            if xml:
                dump_path = output_dir / "ui_dumps" / f"chrome_{idx:02d}_{safe_host}.xml"
                dump_path.parent.mkdir(parents=True, exist_ok=True)
                dump_path.write_text(xml, encoding="utf-8")

            # Encerra a página aberta no browser após concluir o teste da URL
            _close_chrome_tab(backend, log)

            duration_ms = int((time.monotonic() - t0) * 1000)
            log.info(
                "Chrome URL %s -> %s (ips=%s, kw=%s, %dms, png=%s)",
                url,
                detected_status,
                probe.resolved_ips,
                matched_kw or "none",
                duration_ms,
                png_path.name if has_png else "FAILED",
            )
            results.append(
                awc.ChromeURLResult(
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
                    notes=extra_notes,
                )
            )
    finally:
        # Fecha todas as abas abertas e encerra o navegador Chrome ao término dos testes
        _close_all_chrome_tabs(backend, log)
    return results


# ==============================================================================
# RELATÓRIO CONSOLIDADO
# ==============================================================================


def generate_waterfall_html(
    output_dir: Path,
    waterfalls: Sequence[WaterfallEntry],
    cellular_telemetry: Optional[CellularApnTelemetry] = None,
    private_dns: Optional[awc.PrivateDNSStatus] = None,
) -> Path:
    """Gera `waterfall.html` com timeline estilo DevTools (Inspecionar Elemento) dos requests, DNS, HTTP e TLS."""
    html_path = output_dir / "waterfall.html"
    rows_html: List[str] = []
    for wf in waterfalls:
        max_total = max([wf.total_load_ms, 1] + [r.start_offset_ms + r.duration_ms for r in wf.network_requests])
        cert_txt = "-"
        if wf.tls_certificate:
            cert_txt = (
                f"Subject: {wf.tls_certificate.subject or '-'} | "
                f"Issuer: {wf.tls_certificate.issuer or '-'} | "
                f"Expires: {wf.tls_certificate.not_after or '-'}"
            )
        reqs = wf.network_requests or [
            NetworkRequestItem(
                url=wf.target,
                resource_type="document",
                status_code=wf.http_status,
                size_bytes=wf.content_bytes,
                dns_ms=wf.dns_rtt_ms,
                tcp_ms=wf.tcp_rtt_ms,
                tls_ms=wf.tls_rtt_ms,
                ttfb_ms=wf.ttfb_ms,
                duration_ms=wf.total_load_ms,
                remote_ip=", ".join(wf.resolved_ips),
            )
        ]
        req_rows: List[str] = []
        for req in reqs:
            left_pct = min(95.0, (req.start_offset_ms / max_total) * 100.0)
            dur = max(req.duration_ms, (req.dns_ms or 0) + (req.tcp_ms or 0) + (req.tls_ms or 0) + (req.ttfb_ms or 0), 1)
            width_pct = max(2.0, min(100.0 - left_pct, (dur / max_total) * 100.0))
            req_rows.append(
                f"<tr>"
                f"<td class='url'>{html.escape(req.url)}</td>"
                f"<td>{html.escape(req.resource_type)}</td>"
                f"<td>{req.status_code or '-'}</td>"
                f"<td>{req.size_bytes} B</td>"
                f"<td>{req.dns_ms if req.dns_ms is not None else '-'} ms</td>"
                f"<td>{req.tcp_ms if req.tcp_ms is not None else '-'} ms</td>"
                f"<td>{req.tls_ms if req.tls_ms is not None else '-'} ms</td>"
                f"<td>{req.ttfb_ms if req.ttfb_ms is not None else '-'} ms</td>"
                f"<td>{dur} ms</td>"
                f"<td class='tl'><div class='bar-wrap'><div class='bar' style='left:{left_pct:.1f}%;width:{width_pct:.1f}%'></div></div></td>"
                f"</tr>"
            )
        rows_html.append(
            f"<section class='card'>"
            f"<h3>{html.escape(wf.target)} <span class='badge {html.escape(wf.status)}'>{html.escape(wf.status)}</span></h3>"
            f"<p class='meta'><b>DNS Browser/Android:</b> {html.escape(', '.join(wf.dns_server_used) or '-')} | "
            f"<b>Resolução:</b> {html.escape(', '.join(wf.resolved_ips) or '-')} ({wf.dns_rtt_ms or '-'} ms) | "
            f"<b>HTTP:</b> {wf.http_status or '-'} | <b>Ping RTT:</b> {wf.device_ping_rtt_ms or '-'} ms</p>"
            f"<p class='meta'><b>Certificado TLS:</b> {html.escape(cert_txt)}</p>"
            f"<table><thead><tr><th>Request</th><th>Tipo</th><th>HTTP</th><th>Size</th><th>DNS</th><th>TCP</th><th>TLS</th><th>TTFB</th><th>Total</th><th>Timeline</th></tr></thead>"
            f"<tbody>{''.join(req_rows)}</tbody></table>"
            f"</section>"
        )

    apn_info = html.escape(cellular_telemetry.raw_summary if cellular_telemetry else "-")
    pdns_info = (
        f"Android={private_dns.android_mode} | Chrome={private_dns.chrome_secure_dns_state}"
        if private_dns
        else "-"
    )
    doc = (
        "<!doctype html><html lang='pt'><head><meta charset='utf-8'>"
        "<title>Kobiton Network Waterfall</title>"
        "<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:24px}"
        ".card{background:#1e293b;border-radius:10px;padding:16px;margin-bottom:18px}"
        ".meta{font-size:13px;color:#cbd5e1;margin:4px 0}.badge{padding:2px 8px;border-radius:6px;font-size:12px}"
        ".BLOCKED{background:#dc2626}.LOADED,.ALLOWED{background:#16a34a}.UNKNOWN,.ERROR{background:#d97706}"
        "table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}"
        "th,td{border-bottom:1px solid #334155;padding:6px;text-align:left}"
        ".url{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
        ".tl{width:220px}.bar-wrap{position:relative;height:12px;background:#0f172a;border-radius:4px}"
        ".bar{position:absolute;top:2px;height:8px;background:#38bdf8;border-radius:3px}</style></head><body>"
        f"<h1>Network Waterfall — Kobiton Android</h1>"
        f"<p class='meta'><b>Telemetria APN:</b> {apn_info} | <b>Private DNS:</b> {html.escape(pdns_info)}</p>"
        f"{''.join(rows_html)}</body></html>"
    )
    html_path.write_text(doc, encoding="utf-8")
    return html_path


def write_kobiton_reports(
    output_dir: Path,
    device: awc.DeviceInfo,
    sim_initial: SimInitialState,
    sim_actions: SimActionResult,
    dns_connectivity: Sequence[DnsConnectivityResult],
    private_dns: awc.PrivateDNSStatus,
    app_results: Sequence[awc.AppTestResult],
    chrome_results: Sequence[awc.ChromeURLResult],
    cellular_telemetry: Optional[CellularApnTelemetry] = None,
    waterfalls: Sequence[WaterfallEntry] = (),
) -> Tuple[Path, Path]:
    """Gera `report.json` e `report.csv` consolidados incluindo SIM/Modo Avião/DNS/Telemetria."""
    json_path, csv_path = awc.write_reports(output_dir, device, private_dns, app_results, chrome_results)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    payload["sim_initial"] = asdict(sim_initial)
    payload["sim_actions"] = asdict(sim_actions)
    payload["dns_connectivity"] = [asdict(d) for d in dns_connectivity]
    payload["telemetry"] = {
        "cellular_apn": asdict(cellular_telemetry) if cellular_telemetry else {},
        "waterfalls": [asdict(w) for w in waterfalls],
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    with csv_path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "sim_management",
                f"init(sim1={sim_initial.sim1_enabled},sim2={sim_initial.sim2_enabled})",
                "RESTORED" if sim_actions.restored_successfully else "RESTORE_FAILED",
                "N/A",
                0,
                sim_actions.restored_screenshot or sim_actions.before_tests_screenshot,
                sim_actions.notes,
            ]
        )
        if cellular_telemetry is not None:
            writer.writerow(
                [
                    "cellular_apn",
                    f"APN={cellular_telemetry.apn_name or '-'} ({cellular_telemetry.network_type or '-'})",
                    "COLLECTED",
                    "N/A",
                    0,
                    "",
                    cellular_telemetry.raw_summary,
                ]
            )
        for dc in dns_connectivity:
            writer.writerow(
                [
                    "dns_connectivity",
                    dc.dns_server,
                    dc.status,
                    "N/A",
                    dc.latency_ms,
                    dc.screenshot_path,
                    dc.details,
                ]
            )
        for wf in waterfalls:
            writer.writerow(
                [
                    "waterfall",
                    wf.target,
                    wf.status,
                    "N/A",
                    wf.total_load_ms,
                    "",
                    (
                        f"dns_rtt={wf.dns_rtt_ms}ms tcp_rtt={wf.tcp_rtt_ms}ms "
                        f"tls_rtt={wf.tls_rtt_ms}ms ttfb={wf.ttfb_ms}ms "
                        f"ping_rtt={wf.device_ping_rtt_ms}ms ips={wf.resolved_ips}"
                    ),
                ]
            )

    return json_path, csv_path


# ==============================================================================
# CLI / MAIN
# ==============================================================================


def build_kobiton_capabilities(
    cfg: KobitonEnvConfig,
    args: argparse.Namespace,
    udid_override: Optional[str] = None,
) -> Dict[str, Any]:
    caps: Dict[str, Any] = {
        "platformName": "Android",
        "appium:automationName": "UiAutomator2",
        "appium:noReset": True,
        "appium:newCommandTimeout": 300,
        "kobiton:options": {
            "sessionName": cfg.session_name,
            "sessionDescription": cfg.session_description,
            "deviceGroup": cfg.device_group,
            "captureScreenshots": True,
        },
    }
    if cfg.group_id is not None:
        caps["kobiton:options"]["groupId"] = cfg.group_id
    udid = udid_override or args.udid or cfg.udid
    device_name = args.device_name or cfg.device_name
    platform_version = args.platform_version or cfg.platform_version
    if udid:
        caps["appium:udid"] = udid
    if device_name:
        caps["appium:deviceName"] = device_name
    else:
        caps["appium:deviceName"] = "*"
    if platform_version:
        caps["appium:platformVersion"] = platform_version
    return caps


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validação de políticas DNS/Whalebone via Kobiton (SIM1/SIM2, Modo Avião, DNS, Apps e Chrome)."
    )
    parser.add_argument("--env-file", help="Caminho para arquivo .env customizado (padrão: .env.kobiton).")
    parser.add_argument("--username", help="Usuário Kobiton (sobrescreve KOBITON_USERNAME).")
    parser.add_argument("--api-key", help="API Key Kobiton (sobrescreve KOBITON_API_KEY).")
    parser.add_argument("--server-url", help="URL do hub WebDriver Kobiton.")
    parser.add_argument("--udid", help="UDID do dispositivo Android no Kobiton.")
    parser.add_argument("--udids", nargs="+", help="Lista de UDIDs alvo no Kobiton.")
    parser.add_argument(
        "--target-msisdn",
        help="MSISDN do SIM que deve ficar ativo (seleciona SIM1 ou SIM2 automaticamente).",
    )
    parser.add_argument("--device-name", help="Nome do dispositivo Android no Kobiton.")
    parser.add_argument("--platform-version", help="Versão do Android no Kobiton.")
    parser.add_argument("--list-devices", action="store_true", help="Lista dispositivos Android e MSISDNs no Kobiton e sai.")
    parser.add_argument(
        "--probe-msisdn",
        action="store_true",
        help="Usado com --list-devices para consultar SIM1/SIM2 MSISDN diretamente nos aparelhos online.",
    )
    parser.add_argument("--dns-servers", nargs="+", help="Servidores DNS destino para teste de conectividade.")
    parser.add_argument(
        "--block-ips",
        nargs="+",
        help="IPs de resposta DNS que confirmam bloqueio (padrão: 212.113.177.247).",
    )
    parser.add_argument(
        "--set-android-dns",
        action="store_true",
        help="Altera temporariamente o DNS/Private DNS no Android para os testes e restaura ao final.",
    )
    parser.add_argument("--keep-wifi", action="store_true", help="Não desativa o Wi-Fi no Android durante os testes.")
    parser.add_argument("--urls", nargs="+", help="URLs para testar no Chrome.")
    parser.add_argument("--apps", nargs="+", help="Apps a testar (ex: reddit instagram netflix).")
    parser.add_argument("--skip-sim-setup", action="store_true", help="Pula gestão de SIM1/SIM2.")
    parser.add_argument(
        "--skip-airplane-mode",
        action="store_true",
        help="Pula o ciclo liga/desliga do Modo Avião para re-registro do SIM1.",
    )
    parser.add_argument("--skip-apn-check", action="store_true", help="Pula verificação de registro na APN.")
    parser.add_argument("--skip-clear-cache", action="store_true", help="Pula limpeza de cache do navegador.")
    parser.add_argument("--skip-apps", action="store_true", help="Não executa navegação nos aplicativos.")
    parser.add_argument("--skip-chrome", action="store_true", help="Não executa navegação nas URLs do Chrome.")
    parser.add_argument("--skip-private-dns-ui", action="store_true", help="Audita Private DNS sem navegar na UI.")
    parser.add_argument("--page-wait", type=int, help="Tempo de espera (s) após abrir URL no Chrome.")
    parser.add_argument("--app-wait", type=int, help="Tempo de espera (s) após abrir cada aplicativo.")
    parser.add_argument("--no-scroll", action="store_true", help="Desativa scroll simulado dentro dos apps.")
    parser.add_argument("--no-banner", action="store_true", help="Não adiciona banner nos printscreens.")
    parser.add_argument("--output-dir", help="Diretório de saída dos resultados.")
    parser.add_argument("--run-tests", action="store_true", help="Executa a suíte de testes unitários.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.run_tests:
        tests_dir = Path(__file__).resolve().parent / "tests"
        suite = unittest.defaultTestLoader.discover(start_dir=str(tests_dir))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    cfg = load_kobiton_env(args.env_file)
    if args.username:
        cfg.username = args.username
    if args.api_key:
        cfg.api_key = args.api_key
    if args.server_url:
        cfg.server_url = args.server_url

    if not cfg.username or not cfg.api_key:
        print("ERRO: KOBITON_USERNAME e KOBITON_API_KEY são obrigatórios.", file=sys.stderr)
        return 1

    client = KobitonClient(
        username=cfg.username,
        api_key=cfg.api_key,
        server_url=cfg.server_url,
        api_url=cfg.api_url,
        insecure_ssl=cfg.insecure_ssl,
    )

def _probe_device_msisdns_via_session(
    client: KobitonClient,
    cfg: KobitonEnvConfig,
    args: argparse.Namespace,
    udid: str,
) -> str:
    """Abre uma sessão rápida no dispositivo online para ler os MSISDNs de SIM1 e SIM2 via `dumpsys isub`."""
    caps = build_kobiton_capabilities(cfg, args, udid_override=udid)
    caps["kobiton:options"]["sessionName"] = "MSISDN Discovery"
    try:
        client.create_session(caps)
        backend = KobitonBackend(client)
        isub = backend.shell(["dumpsys", "isub"], timeout=8).stdout
        iph = backend.shell(["dumpsys", "iphonesubinfo"], timeout=6).stdout
        s1, s2 = parse_sim_msisdns_from_shell(isub, iph)
        if not s1 and not s2:
            siminfo = backend.shell(["content", "query", "--uri", "content://telephony/siminfo"], timeout=6).stdout
            s1, s2 = parse_sim_msisdns_from_content_siminfo(siminfo)
        if not s1:
            for tx_id in ("13", "15", "16", "17", "18"):
                candidate = parse_service_call_parcel_string(
                    backend.shell(["service", "call", "iphonesubinfo", tx_id], timeout=4).stdout
                )
                if candidate:
                    s1 = candidate
                    break
        return f"SIM1={s1 or '-'}, SIM2={s2 or '-'}"
    except Exception as exc:
        return f"probe_err={exc}"
    finally:
        client.delete_session()


def _move_screenshots_to_msisdn_dir(
    output_dir: Path,
    msisdn_label: str,
    sim_initial: SimInitialState,
    sim_actions: SimActionResult,
    dns_connectivity: Sequence[DnsConnectivityResult],
    private_dns: awc.PrivateDNSStatus,
    app_results: Sequence[awc.AppTestResult],
    chrome_results: Sequence[awc.ChromeURLResult],
) -> Path:
    """Move os screenshots gerados para `output_dir/screenshots/<MSISDN>/` e atualiza os caminhos."""
    safe_folder = re.sub(r"[^0-9A-Za-z+_-]+", "_", msisdn_label or "unknown").strip("_") or "unknown"
    src_dir = output_dir / "screenshots"
    dst_dir = src_dir / safe_folder
    dst_dir.mkdir(parents=True, exist_ok=True)

    def _relocate(path_str: str) -> str:
        if not path_str:
            return ""
        p = Path(path_str)
        target = dst_dir / p.name
        if p.parent == src_dir:
            if p.is_file():
                p.replace(target)
                return str(target)
            if target.is_file():
                return str(target)
        return path_str

    if src_dir.is_dir():
        for png in list(src_dir.glob("*.png")):
            png.replace(dst_dir / png.name)

    sim_initial.screenshot_path = _relocate(sim_initial.screenshot_path)
    sim_actions.before_tests_screenshot = _relocate(sim_actions.before_tests_screenshot)
    sim_actions.airplane_screenshot = _relocate(sim_actions.airplane_screenshot)
    sim_actions.restored_screenshot = _relocate(sim_actions.restored_screenshot)
    private_dns.android_settings_screenshot = _relocate(private_dns.android_settings_screenshot)
    private_dns.chrome_settings_screenshot = _relocate(private_dns.chrome_settings_screenshot)
    for dc in dns_connectivity:
        dc.screenshot_path = _relocate(dc.screenshot_path)
    for ar in app_results:
        ar.screenshot_path = _relocate(ar.screenshot_path)
    for cr in chrome_results:
        cr.screenshot_path = _relocate(cr.screenshot_path)
    return dst_dir


def _run_device_session(
    client: KobitonClient,
    cfg: KobitonEnvConfig,
    args: argparse.Namespace,
    udid: str,
    target_msisdn: str,
    output_dir: Path,
) -> int:
    log = awc.setup_logger(output_dir)

    dns_servers = args.dns_servers or cfg.dns_servers
    block_ips = args.block_ips or cfg.block_ips
    app_tokens = args.apps or cfg.apps
    urls = args.urls or cfg.urls
    app_wait = args.app_wait if args.app_wait is not None else cfg.app_wait
    page_wait = args.page_wait if args.page_wait is not None else cfg.page_wait
    simulate_scroll = cfg.simulate_scroll and (not args.no_scroll)

    caps = build_kobiton_capabilities(cfg, args, udid_override=udid or None)
    log.info("Iniciando sessão no Kobiton (%s) | UDID=%s...", cfg.server_url, udid or "auto")
    try:
        sid = client.create_session(caps)
    except KobitonWebDriverError as exc:
        msg_lower = str(exc).lower()
        if any(tok in msg_lower for tok in ("currently in use", "in use", "booked", "retain")):
            reason = f"Dispositivo UDID={udid or 'auto'} está em uso ou retido por outro utilizador no Kobiton."
        else:
            reason = f"Não foi possível iniciar sessão no Kobiton para UDID={udid or 'auto'}: {exc}"
        log.error(reason)
        dev_stub = awc.DeviceInfo(
            serial=udid or "kobiton",
            model="Unknown",
            android_version="Unknown",
            sdk="Unknown",
            execution_mode="kobiton",
        )
        json_path, csv_path = write_kobiton_reports(
            output_dir=output_dir,
            device=dev_stub,
            sim_initial=SimInitialState(),
            sim_actions=SimActionResult(notes=reason),
            dns_connectivity=[],
            private_dns=awc.PrivateDNSStatus(bypass_risk="UNKNOWN"),
            app_results=[],
            chrome_results=[],
        )
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        payload["status"] = "DEVICE_UNAVAILABLE"
        payload["error"] = str(exc)
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Relatório de indisponibilidade salvo em %s e %s", json_path, csv_path)
        return 1
    log.info("Sessão Kobiton criada: %s", sid)

    backend = KobitonBackend(client, logger=log)
    wifi_mgr = WifiStateManager(backend, log)
    android_dns_mgr = AndroidDnsManager(backend, log)
    sim_initial = SimInitialState()
    sim_actions = SimActionResult()
    dns_connectivity: List[DnsConnectivityResult] = []
    cellular_telemetry = CellularApnTelemetry()
    waterfalls: List[WaterfallEntry] = []
    private_dns = awc.PrivateDNSStatus(bypass_risk="UNKNOWN")
    app_results: List[awc.AppTestResult] = []
    chrome_results: List[awc.ChromeURLResult] = []
    abort_error: Optional[str] = None
    device = awc.DeviceInfo(serial=udid or "kobiton", model="Unknown", android_version="Unknown", sdk="Unknown", execution_mode="kobiton")

    orig_probe = awc.probe_endpoint_connectivity

    def _kobiton_probe(url: str, timeout: int = 10) -> awc.EndpointProbeResult:
        active_dns = private_dns.active_dns_servers or cellular_telemetry.dns_addresses
        probe, wf = measure_url_waterfall(
            url,
            dns_servers=dns_servers,
            block_ips=block_ips,
            backend=backend,
            timeout=timeout,
            active_dns_servers=active_dns,
            output_dir=output_dir,
        )
        waterfalls.append(wf)
        cert_summary = ""
        if wf.tls_certificate:
            cert_summary = (
                f" | TLS_Cert(subject={wf.tls_certificate.subject or '-'}, "
                f"issuer={wf.tls_certificate.issuer or '-'}, "
                f"verify={wf.tls_certificate.verify_result or '-'})"
            )
        log.info(
            "Probe %s -> %s (http=%s, ips=%s, ping_rtt=%sms%s)",
            url,
            wf.status,
            wf.http_status,
            wf.resolved_ips,
            wf.device_ping_rtt_ms,
            cert_summary,
        )
        return probe

    try:
        device = backend.get_device_info()
        log.info(
            "Dispositivo Kobiton: %s | Android %s (SDK %s) | UDID=%s",
            device.model,
            device.android_version,
            device.sdk,
            device.serial,
        )

        # 0. Desativar Wi-Fi no Android durante os testes (restaurando ao final)
        if cfg.disable_wifi_during_tests and not args.keep_wifi:
            wifi_mgr.disable_for_tests()

        # 0b. Alterar DNS no Android (quando solicitado), restaurando ao final
        if cfg.set_android_dns or args.set_android_dns:
            android_dns_mgr.apply(dns_servers)

        # 1 & 2. Detectar estado inicial de SIM1/SIM2 + MSISDNs e ativar o SIM alvo (por MSISDN ou padrão SIM1)
        target_slot = 1
        if not args.skip_sim_setup:
            sim_initial = detect_initial_sim_and_airplane_state(backend, output_dir, log)
            target_slot = select_target_sim_slot(sim_initial, target_msisdn, log=log)
            log.info(
                "Slot alvo selecionado: SIM%d (target_msisdn=%s)",
                target_slot,
                target_msisdn or "padrão SIM1",
            )
            s1, s2, before_png = ensure_target_sim_active(
                backend, sim_initial, sim_actions, target_slot, output_dir, log
            )
            sim_actions.sim1_final_before_tests = s1
            sim_actions.sim2_final_before_tests = s2
            sim_actions.before_tests_screenshot = before_png

        # 3. Alternar Modo Avião (ON -> aguarda -> OFF -> aguarda) para deregistro e novo registro do SIM ativo
        if not args.skip_airplane_mode:
            air_state, air_png = toggle_airplane_mode_reregister(
                backend,
                wait_on_sec=cfg.airplane_wait_on,
                wait_off_sec=cfg.airplane_wait_off,
                output_dir=output_dir,
                log=log,
            )
            sim_actions.airplane_mode_before_tests = air_state
            sim_actions.airplane_screenshot = air_png

        # 3b. Confirmar que o SIM registrou na APN (aguardando 5s, 15s, 45s, 2m, 5m se necessário)
        if not args.skip_apn_check:
            cellular_telemetry = wait_for_sim1_apn_registration(
                backend, wifi_mgr, output_dir, log, expected_dns_servers=dns_servers
            )
        else:
            cellular_telemetry = collect_cellular_apn_telemetry(
                backend, wifi_mgr, log, expected_dns_servers=dns_servers
            )

        # 3c. Limpar cache do navegador antes de iniciar os testes
        if not args.skip_clear_cache:
            clear_browser_cache(backend, log)

        dns_connectivity = test_dns_server_connectivity(backend, dns_servers, output_dir, log)

        # 4. Auditar Private DNS (Android + Chrome) via settings/dumpsys sem screenshots 00_*
        if cfg.check_private_dns:
            private_dns = awc.check_android_private_dns(
                backend,
                output_dir=output_dir,
                check_ui=False,
                logger=log,
            )

        # 5. Navegar nos aplicativos e nas URLs do Chrome com waterfall + confirmação pelo IP de bloqueio
        awc.probe_endpoint_connectivity = _kobiton_probe
        if not args.skip_apps:
            apps = awc.resolve_app_targets(app_tokens)
            app_results = navigate_apps_kobiton(
                backend,
                apps=apps,
                output_dir=output_dir,
                private_dns=private_dns,
                wait_sec=app_wait,
                simulate_scroll=simulate_scroll,
                log=log,
            )

        if cfg.check_chrome and not args.skip_chrome:
            chrome_results = navigate_chrome_urls_kobiton(
                backend,
                urls=urls,
                output_dir=output_dir,
                private_dns=private_dns,
                page_wait=page_wait,
                add_banner=not args.no_banner,
                log=log,
            )
    except KeyboardInterrupt:
        abort_error = "Execução interrompida pelo utilizador (KeyboardInterrupt)."
        log.warning(abort_error)
        interrupted = True
    except (ApnRegistrationError, ValueError) as exc:
        abort_error = str(exc)
        interrupted = False
        log.error("Execução abortada: %s", abort_error)
    else:
        interrupted = False
    finally:
        awc.probe_endpoint_connectivity = orig_probe
        # 6. Sempre restaurar SIM1/SIM2, Modo Avião, DNS no Android e Wi-Fi ao estado inicial e encerrar sessão
        if not args.skip_sim_setup:
            restore_sim_and_airplane_state(backend, sim_initial, sim_actions, output_dir, log)
        android_dns_mgr.restore()
        cellular_telemetry.wifi_restored = wifi_mgr.restore()
        client.delete_session()
        log.info("Sessão Kobiton encerrada.")

    detected_active_msisdn = (
        (sim_initial.sim2_msisdn if sim_actions.target_slot == 2 else sim_initial.sim1_msisdn)
        or sim_initial.sim1_msisdn
        or sim_initial.sim2_msisdn
    )
    if (
        target_msisdn
        and detected_active_msisdn
        and msisdn_matches(detected_active_msisdn, target_msisdn)
        and len(_normalize_msisdn(target_msisdn)) > len(_normalize_msisdn(detected_active_msisdn))
    ):
        active_msisdn = target_msisdn
    else:
        active_msisdn = detected_active_msisdn or target_msisdn or udid or "unknown"
    msisdn_shots_dir = _move_screenshots_to_msisdn_dir(
        output_dir=output_dir,
        msisdn_label=active_msisdn,
        sim_initial=sim_initial,
        sim_actions=sim_actions,
        dns_connectivity=dns_connectivity,
        private_dns=private_dns,
        app_results=app_results,
        chrome_results=chrome_results,
    )
    log.info("Screenshots salvos no diretório MSISDN: %s", msisdn_shots_dir)

    json_path, csv_path = write_kobiton_reports(
        output_dir=output_dir,
        device=device,
        sim_initial=sim_initial,
        sim_actions=sim_actions,
        dns_connectivity=dns_connectivity,
        private_dns=private_dns,
        app_results=app_results,
        chrome_results=chrome_results,
        cellular_telemetry=cellular_telemetry,
        waterfalls=waterfalls,
    )
    if abort_error:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        payload["status"] = "INTERRUPTED" if interrupted else "ABORTED"
        payload["error"] = abort_error
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        log.warning("Relatórios parciais salvos em %s e %s", json_path, csv_path)
        return 130 if interrupted else 1
    log.info("Relatórios gerados: %s e %s", json_path, csv_path)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.run_tests:
        tests_dir = Path(__file__).resolve().parent / "tests"
        suite = unittest.defaultTestLoader.discover(start_dir=str(tests_dir))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    cfg = load_kobiton_env(args.env_file)
    if args.username:
        cfg.username = args.username
    if args.api_key:
        cfg.api_key = args.api_key
    if args.server_url:
        cfg.server_url = args.server_url

    if not cfg.username or not cfg.api_key:
        print("ERRO: KOBITON_USERNAME e KOBITON_API_KEY são obrigatórios.", file=sys.stderr)
        return 1

    client = KobitonClient(
        username=cfg.username,
        api_key=cfg.api_key,
        server_url=cfg.server_url,
        api_url=cfg.api_url,
        insecure_ssl=cfg.insecure_ssl,
    )

    if args.list_devices:
        devices = client.list_devices()
        for d in devices:
            udid = str(d.get("udid") or "")
            msisdn_info = extract_kobiton_device_msisdns(d)
            if args.probe_msisdn and d.get("isOnline") and not d.get("isBooked") and udid:
                msisdn_info = _probe_device_msisdns_via_session(client, cfg, args, udid)
            print(
                f"udid={udid} | name={d.get('deviceName')} | "
                f"android={d.get('platformVersion')} | online={d.get('isOnline')} | "
                f"booked={d.get('isBooked')} | msisdn={msisdn_info}"
            )
        return 0

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_out = args.output_dir or cfg.output_dir
    base_out = Path(raw_out).expanduser() if raw_out else Path(f"kobiton_results_{ts}")
    target_msisdn = (args.target_msisdn or cfg.target_msisdn).strip()

    target_udids: List[str] = []
    if args.udids:
        for token in args.udids:
            target_udids.extend(awc._split_list(token))
    elif args.udid:
        target_udids = awc._split_list(args.udid)
    elif cfg.udids:
        target_udids = list(cfg.udids)
    else:
        target_udids = [""]

    exit_code = 0
    try:
        for target_udid in target_udids:
            dev_out = base_out / target_udid if (len(target_udids) > 1 and target_udid) else base_out
            rc = _run_device_session(client, cfg, args, target_udid, target_msisdn, dev_out)
            if rc != 0:
                exit_code = rc
            if rc == 130:
                break
    except KeyboardInterrupt:
        print("\nExecução interrompida pelo utilizador (Ctrl+C).", file=sys.stderr)
        return 130
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
