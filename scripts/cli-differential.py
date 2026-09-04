#!/usr/bin/env python3
"""Strict executable Go↔Rust differential coverage for the non-MCP CLI.

The fake box binds to every interface on a fixed high port.  The subprocesses
connect through this machine's private RFC1918 address, which exercises the
same explicit host:port origins used by a real local box while avoiding the
Go client's intentional public/loopback discovery restrictions.  Every route,
SOAP action, argument, SID, digest challenge, and mutation sequence is
allow-listed; an unexpected request is a failure, never a generic 200.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import ipaddress
import json
import os
import re
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

PORT = 49000
RFC1918 = tuple(ipaddress.ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
USER = "admin"
PASSWORD = "test-password"
SID = "1234567890abcdef"
CHALLENGE = "fixed-challenge"
REALM = "symfritz-test"
NONCE = "fixed-test-nonce"
MAC = "AA:BB:CC:DD:EE:FF"
IP = "192.168.1.20"
AIN = "16-000000000000"

TRAFFIC_XML = b'''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:X_AVM-DE_GetOnlineMonitorResponse xmlns:u="urn:dslforum-org:service:WANCommonInterfaceConfig:1">
<Newds_current_bps>1500000,1200000</Newds_current_bps><Newmc_current_bps>500000</Newmc_current_bps><Newds_guest_bps>0</Newds_guest_bps>
<Newprio_realtime_bps>100000</Newprio_realtime_bps><Newprio_high_bps>200000</Newprio_high_bps><Newprio_default_bps>800000</Newprio_default_bps><Newprio_low_bps>50000</Newprio_low_bps><Newus_guest_bps>0</Newus_guest_bps>
</u:X_AVM-DE_GetOnlineMonitorResponse></s:Body></s:Envelope>'''
DESC_XML = b'''<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device><serviceList>
<service><serviceType>urn:dslforum-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/upnp/control/wancommonifconfig1</controlURL></service>
<service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service>
</serviceList></device></root>'''
HOSTS_XML = b'''<?xml version="1.0"?><List><Item><IPAddress>192.168.1.20</IPAddress><MACAddress>AA:BB:CC:DD:EE:FF</MACAddress><Active>1</Active><HostName>laptop</HostName><InterfaceType>Ethernet</InterfaceType><AddressSource>DHCP</AddressSource><LeaseTimeRemaining>3600</LeaseTimeRemaining></Item></List>'''
MESH_JSON = b'''{"schema_version":"1","nodes":[{"uid":"node-1","device_name":"fritz.box","device_model":"FRITZ!Box","is_meshed":true,"mesh_role":"master","node_interfaces":[]}]}'''
LOG_XML = b'''<?xml version="1.0"?><Logs><Log><Time>01.01.26 12:00</Time><Message>Started</Message><Group>sys</Group></Log></Logs>'''
CALLS_XML = b'''<?xml version="1.0"?><CallList><Call><Type>1</Type><Caller>123</Caller><Called>456</Called><Name>Alice</Name><Date>01.01.26 12:00</Date><Duration>00:01</Duration></Call></CallList>'''
AHA_XML = f'''<devicelist><device identifier="{AIN}" id="id-1"><name>Desk</name><present>1</present><switch><state>1</state></switch><temperature><celsius>210</celsius></temperature><hkr><tist>40</tist><tsoll>42</tsoll><batterylow>0</batterylow><battery>100</battery><windowopenactiv>0</windowopenactiv><errorcode>0</errorcode><nextchange><end></end><start></start><tchange>0</tchange></nextchange></hkr><powermeter><power>1250</power><energy>12</energy></powermeter></device></devicelist>'''.encode()

EXPECTED_ACTIONS = {
    "/upnp/control/deviceinfo": {"GetInfo", "X_AVM-DE_GetDeviceLogPath"},
    "/upnp/control/userif": {"GetInfo"},
    "/upnp/control/wanipconnection1": {"GetInfo", "GetExternalIPAddress"},
    "/upnp/control/wanpppconn1": {"GetInfo", "GetExternalIPAddress"},
    "/upnp/control/wancommonifconfig1": {"X_AVM-DE_GetOnlineMonitor", "GetCommonLinkProperties", "GetAddonInfos"},
    "/igdupnp/control/WANCommonIFC1": {"GetCommonLinkProperties", "GetAddonInfos"},
    "/upnp/control/wandslifconfig1": {"X_AVM-DE_GetDSLLinkInfo", "GetInfo"},
    "/upnp/control/hosts": {"X_AVM-DE_GetHostListPath", "X_AVM-DE_GetMeshListPath", "X_AVM-DE_GetDeviceLogPath", "GetHostNumberOfEntries", "GetGenericHostEntry", "GetSpecificHostEntry", "X_AVM-DE_GetSpecificHostEntryByIP", "X_AVM-DE_WakeOnLANByMACAddress"},
    "/upnp/control/x_voip": {"X_AVM-DE_Dial", "X_AVM-DE_DialNumber", "X_AVM-DE_DialHangup"},
    "/upnp/control/x_contact": {"X_AVM-DE_GetCallList", "GetCallList"},
    "/upnp/control/x_homeauto": {"GetGenericDeviceInfos", "SetSwitch"},
    "/upnp/control/wlanconfig1": {"GetInfo", "GetTotalAssociations", "GetGenericAssociatedDeviceInfo"},
    "/upnp/control/wlanconfig2": {"GetInfo", "GetTotalAssociations", "GetGenericAssociatedDeviceInfo"},
    "/upnp/control/wlanconfig3": {"GetInfo", "GetTotalAssociations", "GetGenericAssociatedDeviceInfo", "SetEnable"},
    "/upnp/control/deviceconfig": {"Reboot"},
}
EXPECTED_SERVICES = {
    "/upnp/control/deviceinfo": "DeviceInfo:1", "/upnp/control/userif": "UserInterface:1",
    "/upnp/control/wanipconnection1": "WANIPConnection:1", "/upnp/control/wanpppconn1": "WANPPPConnection:1",
    "/upnp/control/wancommonifconfig1": "WANCommonInterfaceConfig:1", "/igdupnp/control/WANCommonIFC1": "WANCommonInterfaceConfig:1", "/upnp/control/wandslifconfig1": "WANDSLInterfaceConfig:1",
    "/upnp/control/hosts": "Hosts:1", "/upnp/control/x_voip": "X_VoIP:1", "/upnp/control/x_contact": "X_AVM-DE_OnTel:1",
    "/upnp/control/x_homeauto": "X_AVM-DE_Homeauto:1", "/upnp/control/wlanconfig1": "WLANConfiguration:1",
    "/upnp/control/wlanconfig2": "WLANConfiguration:2", "/upnp/control/wlanconfig3": "WLANConfiguration:3",
    "/upnp/control/deviceconfig": "DeviceConfig:1",
}


def md5(value: str) -> str:
    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()


def legacy_response(challenge: str, password: str) -> str:
    clear = (challenge + "-" + password).encode("utf-16le")
    return challenge + "-" + hashlib.md5(clear, usedforsecurity=False).hexdigest()


class StrictFakeBox(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], private_ip: str) -> None:
        super().__init__(address, StrictHandler)
        self.private_ip = private_ip
        self.requests: list[tuple[str, str, str, bytes, int]] = []
        self.accepted: list[tuple[str, str, str, bytes]] = []
        self.failures: list[str] = []
        self.authenticated: set[tuple[str, str]] = set()

    def reset(self) -> None:
        self.requests.clear()
        self.accepted.clear()
        self.failures.clear()
        self.authenticated.clear()


class StrictHandler(http.server.BaseHTTPRequestHandler):
    server: StrictFakeBox  # type: ignore[reportIncompatibleVariableOverride]

    def record(self, method: str, action: str, body: bytes, status: int) -> None:
        self.server.requests.append((method, self.path, action, body, status))

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        if path == "/login_sid.lua":
            supplied = query.get("response", [""])[0]
            if supplied and supplied != legacy_response(CHALLENGE, PASSWORD):
                self.server.failures.append("login response did not authenticate test credential")
                self.reply(b"<SessionInfo><SID>0000000000000000</SID></SessionInfo>", "text/xml")
                return
            body = (f"<SessionInfo><SID>{SID if supplied else '0000000000000000'}</SID><Challenge>{CHALLENGE}</Challenge><BlockTime>0</BlockTime></SessionInfo>").encode()
            self.record("GET", "", b"", 200)
            self.server.accepted.append(("GET", path, "", b""))
            self.reply(body, "text/xml")
            return
        if path.startswith("/webservices/homeautoswitch.lua"):
            if query.get("sid", [""])[0] != SID:
                self.server.failures.append("AHA request omitted valid SID")
                self.reply(b"", "text/plain", status=401)
                return
            command = query.get("switchcmd", [""])[0]
            ain = query.get("ain", [""])[0]
            if command == "getdevicelistinfos":
                body = AHA_XML
            elif command in {"setswitchon", "setswitchoff"} and ain == AIN:
                body = b"1"
            elif command == "sethkrtsoll" and ain == AIN and query.get("param", [""])[0] == "41":
                body = b"1"
            else:
                self.server.failures.append(f"unexpected AHA command/args {command!r} {query!r}")
                self.reply(b"", "text/plain", status=400)
                return
            self.record("GET", command, b"", 200)
            self.server.accepted.append(("GET", path, command, b""))
            self.reply(body, "text/plain")
            return
        if path == "/query.lua":
            if query.get("sid", [""])[0] != SID:
                self.server.failures.append("query.lua omitted valid SID")
                self.reply(b"", "application/json", status=403)
                return
            body = b'{"CPUTEMP":"42"}'
            self.record("GET", "", b"", 200)
            self.server.accepted.append(("GET", path, "", b""))
            self.reply(body, "application/json")
            return
        bodies = {"/tr64desc.xml": (DESC_XML, "text/xml"), "/hosts.xml": (HOSTS_XML, "text/xml"), "/mesh.json": (MESH_JSON, "application/json"), "/log.xml": (LOG_XML, "text/xml"), "/calls.xml": (CALLS_XML, "text/xml")}
        if path not in bodies:
            self.server.failures.append(f"GET unexpected path {self.path!r}")
            self.reply(b"", "text/plain", status=404)
            return
        body, content_type = bodies[path]
        self.record("GET", "", b"", 200)
        self.server.accepted.append(("GET", path, "", b""))
        self.reply(body, content_type)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 0 or length > 1024 * 1024:
            self.server.failures.append("POST missing or oversized Content-Length")
            self.reply(b"", "text/plain", status=400)
            return
        body = self.rfile.read(length)
        if urlsplit(self.path).path == "/data.lua":
            fields = parse_qs(body.decode("utf-8", "replace"))
            if fields.get("page", [""])[0] != "netDev" or fields.get("sid", [""])[0] != SID:
                self.server.failures.append(f"data.lua carried wrong fields {fields!r}")
                self.reply(b"", "application/json", status=401)
                return
            self.record("POST", "", body, 200)
            self.server.accepted.append(("POST", "/data.lua", "", body))
            self.reply(b'{"ok":true,"page":"netDev"}', "application/json")
            return
        path = urlsplit(self.path).path
        soap_action = self.headers.get("SOAPAction", "")
        action = soap_action.strip('"').rsplit("#", 1)[-1]
        self.record("POST", action, body, 200)
        if path not in EXPECTED_ACTIONS or action not in EXPECTED_ACTIONS[path]:
            self.server.failures.append(f"POST unexpected route/action {path!r} {soap_action!r}")
            self.reply(b"", "text/plain", status=404)
            return
        normalized = soap_action.strip('"')
        if not normalized.startswith("urn:") or f":{EXPECTED_SERVICES[path]}#" not in normalized:
            self.server.failures.append(f"SOAPAction used wrong service: {soap_action!r}")
            self.reply(b"", "text/plain", status=400)
            return
        text = body.decode("utf-8", "replace")
        if action not in text:
            self.server.failures.append(f"SOAP body omitted action {action!r}")
            self.reply(b"", "text/plain", status=400)
            return
        required = {
            "X_AVM-DE_GetOnlineMonitor": b"<NewSyncGroupIndex>0</NewSyncGroupIndex>",
            "X_AVM-DE_DialNumber": b"<NewX_AVM-DE_PhoneNumber>123</NewX_AVM-DE_PhoneNumber>",
            "X_AVM-DE_WakeOnLANByMACAddress": f"<NewMACAddress>{MAC}</NewMACAddress>".encode(),
            "GetGenericHostEntry": b"<NewIndex>0</NewIndex>", "GetSpecificHostEntry": f"<NewMACAddress>{MAC}</NewMACAddress>".encode(),
            "X_AVM-DE_GetSpecificHostEntryByIP": f"<NewIPAddress>{IP}</NewIPAddress>".encode(), "SetEnable": b"<NewEnable>1</NewEnable>",
        }
        if action == "X_AVM-DE_GetSpecificHostEntryByIP" and not any(f"<NewIPAddress>{value}</NewIPAddress>".encode() in body for value in (IP, self.server.private_ip)):
            self.server.failures.append(f"{action} carried wrong arguments: {body!r}")
            self.reply(b"", "text/plain", status=400)
            return
        if action == "SetEnable" and not any(f"<NewEnable>{value}</NewEnable>".encode() in body for value in ("0", "1")):
            self.server.failures.append("guest SetEnable carried wrong argument")
            self.reply(b"", "text/plain", status=400)
            return
        if action in required and action not in {"X_AVM-DE_GetSpecificHostEntryByIP", "SetEnable"} and required[action] not in body:
            self.server.failures.append(f"{action} carried wrong arguments: {body!r}")
            self.reply(b"", "text/plain", status=400)
            return
        if action == "SetSwitch" and (f"<NewAIN>{AIN}</NewAIN>".encode() not in body or b"<NewSwitchState>ON</NewSwitchState>" not in body):
            self.server.failures.append("SetSwitch carried wrong arguments")
            self.reply(b"", "text/plain", status=400)
            return
        key = (path, action)
        authorization = self.headers.get("Authorization", "")
        if key not in self.server.authenticated:
            if not authorization or not self.valid_digest(authorization, action):
                self.reply(b"", "text/xml", status=401, extra={"WWW-Authenticate": f'Digest realm="{REALM}", nonce="{NONCE}", qop="auth", algorithm=MD5'})
                return
            self.server.authenticated.add(key)
        elif not authorization or not self.valid_digest(authorization, action):
            self.server.failures.append("retry SOAP request omitted valid Digest authorization")
            self.reply(b"", "text/xml", status=401)
            return
        # Homeauto enumeration terminates on the first expected out-of-range fault.
        if action == "GetGenericDeviceInfos" and b"<NewIndex>1</NewIndex>" in body:
            fault = b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>ArrayIndexError</faultstring></s:Fault></s:Body></s:Envelope>'
            self.reply(fault, "text/xml", status=500)
            return
        values: dict[str, str] = {}
        if action == "GetInfo" and path == "/upnp/control/deviceinfo": values = {"NewModelName": "FRITZ!Box 7590", "NewSoftwareVersion": "8.0", "NewUpTime": "42"}
        elif action == "GetInfo" and path.startswith("/upnp/control/wan"): values = {"NewConnectionStatus": "Connected", "NewExternalIPAddress": "198.51.100.10"}
        elif action == "GetInfo" and path.startswith("/upnp/control/wlanconfig"):
            idx = path.rsplit("wlanconfig", 1)[1]; values = {"NewSSID": f"Test-{idx}", "NewEnable": "1", "NewChannel": idx, "NewStandard": "802.11ax", "NewStatus": "Up"}
        elif action == "GetInfo" and path == "/upnp/control/userif": values = {"NewUpgradeAvailable": "0"}
        elif action == "GetCommonLinkProperties": values = {"NewLayer1UpstreamMaxBitRate": "1000000", "NewLayer1DownstreamMaxBitRate": "10000000"}
        elif action in {"X_AVM-DE_GetDSLLinkInfo", "GetInfo"} and path == "/upnp/control/wandslifconfig1": values = {"NewUpstreamNoiseMargin": "100", "NewDownstreamNoiseMargin": "120", "NewUpstreamAttenuation": "50", "NewDownstreamAttenuation": "60"}
        elif action == "X_AVM-DE_GetHostListPath": values = {"NewX_AVM-DE_HostListPath": "/hosts.xml"}
        elif action == "X_AVM-DE_GetMeshListPath": values = {"NewX_AVM-DE_MeshListPath": "/mesh.json"}
        elif action == "X_AVM-DE_GetDeviceLogPath": values = {"NewX_AVM-DE_DeviceLogPath": "/log.xml"}
        elif action in {"GetCallList", "X_AVM-DE_GetCallList"}: values = {"NewCallListURL": f"http://{self.server.private_ip}:{PORT}/calls.xml"}
        elif action == "GetHostNumberOfEntries": values = {"NewHostNumberOfEntries": "1"}
        elif action in {"GetGenericHostEntry", "GetSpecificHostEntry", "X_AVM-DE_GetSpecificHostEntryByIP"}: values = {"NewHostName": "laptop", "NewIPAddress": IP, "NewMACAddress": MAC, "NewActive": "1", "NewInterfaceType": "Ethernet", "NewAddressSource": "DHCP", "NewLeaseTimeRemaining": "3600"}
        elif action == "GetTotalAssociations": values = {"NewTotalAssociations": "1"}
        elif action == "GetGenericAssociatedDeviceInfo": values = {"NewAssociatedDeviceMACAddress": MAC, "NewAssociatedDeviceIPAddress": IP, "NewX_AVM-DE_SignalStrength": "-40", "NewX_AVM-DE_Speed": "866", "NewAssociatedDeviceAuthState": "1"}
        elif action == "GetGenericDeviceInfos": values = {"NewAIN": AIN, "NewFunctionBitMask": "32768", "NewManufacturer": "AVM", "NewProductName": "FRITZ!DECT 200", "NewFirmwareVersion": "1.0"}
        response_values = "".join(f"<{key}>{value}</{key}>" for key, value in values.items())
        if action == "X_AVM-DE_GetOnlineMonitor":
            response = TRAFFIC_XML
        else:
            response = f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:{action}Response xmlns:u="urn:dslforum-org:service:test:1">{response_values}</u:{action}Response></s:Body></s:Envelope>'.encode()
        self.server.accepted.append(("POST", path, action, body))
        self.reply(response, "text/xml")

    def valid_digest(self, authorization: str, action: str) -> bool:
        fields = dict(re.findall(r'(\w+)=("[^"]*"|[^, ]+)', authorization.removeprefix("Digest ")))
        fields = {key: value.strip('"') for key, value in fields.items()}
        if fields.get("username") != USER or fields.get("realm") != REALM or fields.get("nonce") != NONCE: return False
        expected_uri = urlsplit(self.path).path
        if fields.get("uri") != expected_uri: return False
        ha1 = md5(f"{USER}:{REALM}:{PASSWORD}")
        ha2 = md5(f"POST:{expected_uri}")
        if fields.get("qop"):
            expected = md5(f"{ha1}:{NONCE}:{fields.get('nc', '')}:{fields.get('cnonce', '')}:{fields['qop']}:{ha2}")
        else:
            expected = md5(f"{ha1}:{NONCE}:{ha2}")
        return fields.get("response") == expected

    def reply(self, body: bytes, content_type: str, *, status: int = 200, extra: dict[str, str] | None = None) -> None:
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items(): self.send_header(key, value)
        self.end_headers(); self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None: pass


@dataclass
class Result:
    code: int
    stdout: bytes
    stderr: bytes


def private_address() -> str:
    """Find the address selected for an outbound private-network route."""
    def is_rfc1918(address: str) -> bool:
        try: return any(ipaddress.ip_address(address) in network for network in RFC1918)
        except ValueError: return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        address = str(sock.getsockname()[0])
        if is_rfc1918(address): return address
    finally:
        sock.close()
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        address = str(info[4][0])
        if is_rfc1918(address): return address
    raise AssertionError("could not discover a private RFC1918 interface address")


def environment(home: Path, *, fake: bool, extra: dict[str, str] | None = None, path_prefix: Path | None = None) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("SYMFRITZ_")}
    backend_free = home / "empty-path"; backend_free.mkdir(exist_ok=True)
    path = str(backend_free) if path_prefix is None else f"{path_prefix}{os.pathsep}{os.environ.get('PATH', '')}"
    env.update({"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"), "XDG_DATA_HOME": str(home / "data"), "TMPDIR": str(home / "tmp"), "TMP": str(home / "tmp"), "TEMP": str(home / "tmp"), "PATH": path, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    if fake:
        env.update({"SYMFRITZ_BOX_HOST": f"{PRIVATE_IP}:{PORT}", "SYMFRITZ_BOX_USER": USER, "SYMFRITZ_BOX_USE_TLS": "false", "SYMFRITZ_PASSWORD": PASSWORD, "SYMFRITZ_BOX_TIMEOUT_SECONDS": "1"})
    env.update(extra or {})
    return env


def run_process(binary: str, args: list[str], *, fake: bool = False, setup: Callable[[Path], None] | None = None, extra: dict[str, str] | None = None, path_prefix: Path | None = None, timeout: float = 8) -> tuple[Result, Path]:
    temp = tempfile.TemporaryDirectory(prefix="symfritz-cli-"); home = Path(temp.name)
    (home / "tmp").mkdir(); (home / "config").mkdir(); (home / "cache").mkdir(); (home / "data").mkdir()
    if setup: setup(home)
    try:
        process = subprocess.run([binary, *args], cwd=home, env=environment(home, fake=fake, extra=extra, path_prefix=path_prefix), capture_output=True, timeout=timeout)
        result = Result(process.returncode, process.stdout, process.stderr)
    except subprocess.TimeoutExpired as exc:
        temp.cleanup(); raise AssertionError(f"{binary} {args} exceeded {timeout}s") from exc
    temp.cleanup()
    return result, home


def run(binary: str, args: list[str], **kwargs: Any) -> Result:
    return run_process(binary, args, **kwargs)[0]


def normalize_paths(value: bytes, homes: list[Path]) -> bytes:
    for home in homes: value = value.replace(str(home).encode(), b"<HOME>")
    return value


def assert_bytes(label: str, left: Result, right: Result, homes: list[Path] | None = None) -> None:
    homes = homes or []
    values = [(left.code, normalize_paths(left.stdout, homes), normalize_paths(left.stderr, homes)), (right.code, normalize_paths(right.stdout, homes), normalize_paths(right.stderr, homes))]
    if values[0] != values[1]: raise AssertionError(f"{label}: exact mismatch Go={values[0]!r} Rust={values[1]!r}")


def assert_json(label: str, left: Result, right: Result) -> None:
    if left.code != right.code or left.stderr != right.stderr: raise AssertionError(f"{label}: exit/stderr mismatch: {left} != {right}")
    try: lobj, robj = json.loads(left.stdout), json.loads(right.stdout)
    except json.JSONDecodeError as exc: raise AssertionError(f"{label}: non-JSON output Go={left.stdout!r} Rust={right.stdout!r}") from exc
    def normalize(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: ([] if key == "groups" and item is None else normalize(item)) for key, item in value.items()}
        if isinstance(value, list): return [normalize(item) for item in value]
        return value
    if normalize(lobj) != normalize(robj): raise AssertionError(f"{label}: JSON mismatch Go={lobj!r} Rust={robj!r}")


def assert_help(label: str, left: Result, right: Result) -> None:
    if left.code != 0 or right.code != 0: raise AssertionError(f"{label}: help failed {left.code}, {right.code}")
    for output in (left.stdout, right.stdout):
        if b"Usage:" not in output or not output.endswith(b"\n"): raise AssertionError(f"{label}: missing Usage/newline")


def accepted_requests(server: StrictFakeBox) -> list[tuple[str, str, str, bytes]]:
    return list(server.accepted)


def accepted_actions(server: StrictFakeBox) -> list[tuple[str, str, str]]:
    return [(method, path, action) for method, path, action, _body in accepted_requests(server)]


def assert_server(server: StrictFakeBox, label: str, expected: list[tuple[str, str, str]] | None = None) -> None:
    if server.failures: raise AssertionError(f"{label}: fake-box failures: {'; '.join(server.failures)}")
    if expected is not None and accepted_actions(server) != expected: raise AssertionError(f"{label}: request sequence mismatch got={accepted_actions(server)!r} want={expected!r}")


def run_pair(server: StrictFakeBox, label: str, go: str, rust: str, args: list[str], *, kind: str = "bytes", expected: list[tuple[str, str, str]] | None = None, extra: dict[str, str] | None = None) -> None:
    server.reset(); left = run(go, args, fake=True, extra=extra); assert_server(server, label + " Go", expected); go_requests = accepted_requests(server)
    server.reset(); right = run(rust, args, fake=True, extra=extra); assert_server(server, label + " Rust", expected); rust_requests = accepted_requests(server)
    if go_requests != rust_requests: raise AssertionError(f"{label}: request/argument mismatch Go={go_requests!r} Rust={rust_requests!r}")
    if kind == "json": assert_json(label, left, right)
    else: assert_bytes(label, left, right)
    print(f"PASS {label}")


def parse_validation(root: Path) -> list[dict[str, Any]]:
    values = json.loads((root / "testdata/port/cli/command-contracts.json").read_text())["validation"]
    if len(values) != 17: raise AssertionError(f"fixture validation count changed: {len(values)}")
    return values


def config_setup(home: Path, content: str) -> None:
    path = home / "config" / "symfritz"; path.mkdir(parents=True)
    (path / "config.toml").write_text(content)


def config_init_pair(go: str, rust: str, force: bool, existing: bool) -> None:
    def run_config(binary: str) -> tuple[Result, bytes | None, int | None, str]:
        with tempfile.TemporaryDirectory(prefix="symfritz-config-") as raw:
            home = Path(raw)
            for name in ("tmp", "config", "cache", "data"): (home / name).mkdir()
            if existing: config_setup(home, "# existing\n[box]\nhost = \"old\"\n")
            args = ["config", "init"] + (["--force"] if force else [])
            process = subprocess.run([binary, *args], cwd=home, env=environment(home, fake=False), capture_output=True, timeout=8)
            result = Result(process.returncode, process.stdout, process.stderr)
            path = home / "config" / "symfritz" / "config.toml"
            if not path.exists(): return result, None, None, str(home)
            return result, path.read_bytes(), path.stat().st_mode & 0o777, str(home)
    left, left_bytes, left_mode, left_home = run_config(go); right, right_bytes, right_mode, right_home = run_config(rust)
    label = f"config-init-{('existing' if existing else 'fresh')}{('-force' if force else '')}"
    assert_bytes(label, left, right, [Path(left_home), Path(right_home)])
    if (left_bytes, left_mode) != (right_bytes, right_mode): raise AssertionError(f"{label}: config bytes/mode mismatch")
    print(f"PASS {label}")


def mock_symvault(directory: Path, metadata: Path) -> None:
    script = directory / "symvault"
    script.write_text(f"#!{sys.executable}\nimport json,sys\npayload=sys.stdin.buffer.read()\nwith open(sys.argv[0] + '.meta','a') as f: json.dump({{'args':sys.argv[1:],'length':len(payload),'newline':payload.endswith(b'\\n')}},f); f.write('\\n')\n")
    script.chmod(0o755)
    script.with_name("symvault.meta").write_text("")
    # The metadata file is read through this stable path after each run.
    _ = metadata


def run_auth_store_pair(go: str, rust: str) -> None:
    with tempfile.TemporaryDirectory(prefix="symfritz-vault-mock-") as raw:
        directory = Path(raw); mock_symvault(directory, directory / "metadata")
        left = run(go, ["auth", "store", "--symvault", "fritz.password"], fake=True, path_prefix=directory)
        right = run(rust, ["auth", "store", "--symvault", "fritz.password"], fake=True, path_prefix=directory)
        assert_bytes("auth-store-symvault", left, right)
        records = [json.loads(line) for line in (directory / "symvault.meta").read_text().splitlines() if line]
        if len(records) != 2 or any(record != {"args": ["set", "fritz.password", "--stdin-value"], "length": len(PASSWORD) + 1, "newline": True} for record in records): raise AssertionError(f"auth store mock metadata mismatch: {records!r}")
        if PASSWORD.encode() in left.stdout + left.stderr + right.stdout + right.stderr: raise AssertionError("auth store leaked password")
        print("PASS auth-store-symvault")


def completion_markers(shell: str, output: bytes) -> bool:
    markers = {
        "bash": b"_symfritz",
        "fish": b"complete -c symfritz",
        "powershell": b"Register-ArgumentCompleter",
        "zsh": b"#compdef symfritz",
    }
    return bool(output) and markers[shell] in output


def cli_inventory(binary: str, families: list[str]) -> tuple[frozenset[str], frozenset[str]]:
    commands = frozenset(families)
    flags: set[str] = set()
    for family in families:
        result = run(binary, ["help", family])
        if result.code != 0:
            raise AssertionError(f"{binary} help {family} failed while checking completion inventory")
        flags.update(match.decode() for match in re.findall(rb"--[a-z0-9-]+", result.stdout))
    flags.discard("--output")
    flags.discard("--json")
    if "--call-type" in flags:
        flags.remove("--call-type"); flags.add("--type")
    return commands, frozenset(flags)


def run_suite(go: str, rust: str, root: Path) -> None:
    global PRIVATE_IP
    PRIVATE_IP = private_address()
    server = StrictFakeBox(("0.0.0.0", PORT), PRIVATE_IP); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        families = ["auth", "call", "calls", "completion", "config", "detect", "diagnose", "dial", "doctor", "dsl", "hangup", "help", "home", "hosts", "log", "mesh", "reboot", "scrape", "services", "status", "traffic", "version", "wlan", "wol"]
        for family in families:
            assert_help(f"help-{family}", run(go, ["help", family]), run(rust, ["help", family])); print(f"PASS help-{family}")
        reference_inventory = cli_inventory(go, families)
        candidate_inventory = cli_inventory(rust, families)
        if reference_inventory != candidate_inventory: raise AssertionError(f"CLI completion inventory mismatch: Go={reference_inventory!r} Rust={candidate_inventory!r}")
        for shell in ("bash", "fish", "powershell", "zsh"):
            left, right = run(go, ["completion", shell]), run(rust, ["completion", shell])
            if left.code != right.code or left.stderr != right.stderr or not completion_markers(shell, left.stdout) or not completion_markers(shell, right.stdout): raise AssertionError(f"completion-{shell}: output/marker mismatch")
            print(f"PASS completion-{shell}-inventory")
        for label, args in [("version-text", ["version"]), ("version-json", ["version", "--output", "json"]), ("version-yaml", ["version", "--output", "yaml"]), ("invalid-output-9", ["version", "--output", "invalid"]), ("reboot-without-confirmation-9", ["reboot"])]:
            assert_bytes(label, run(go, args), run(rust, args)); print(f"PASS {label}")
        run_pair(server, "services-discovery", go, rust, ["services", "--json"], kind="json", expected=[("GET", "/tr64desc.xml", "")])
        run_pair(server, "detect-success", go, rust, ["detect", "--json"], kind="json", extra={"SYMFRITZ_HOST": PRIVATE_IP})
        run_pair(server, "config-detect-success", go, rust, ["config", "detect", "--json"], kind="json", extra={"SYMFRITZ_HOST": PRIVATE_IP})
        run_pair(server, "diagnose-private-port", go, rust, ["diagnose", PRIVATE_IP, "--port", str(PORT), "--json"], kind="json", expected=[("POST", "/upnp/control/hosts", "X_AVM-DE_GetSpecificHostEntryByIP")])
        run_pair(server, "status-json", go, rust, ["status", "--output", "json"], kind="json")
        run_pair(server, "hosts-list", go, rust, ["hosts", "list", "--json"], kind="json")
        run_pair(server, "hosts-active", go, rust, ["hosts", "active", "--json"], kind="json")
        run_pair(server, "hosts-by-name", go, rust, ["hosts", "get", "laptop", "--output", "json"], kind="json")
        run_pair(server, "wlan-radios", go, rust, ["wlan", "radios", "--json"], kind="json")
        run_pair(server, "wlan-clients", go, rust, ["wlan", "clients", "--json"], kind="json")
        run_pair(server, "wlan-guest-status", go, rust, ["wlan", "guest", "status", "--json"], kind="json")
        run_pair(server, "dsl", go, rust, ["dsl", "--output", "json"], kind="json")
        run_pair(server, "calls", go, rust, ["calls", "--json"], kind="json")
        run_pair(server, "log", go, rust, ["log", "--json"], kind="json")
        run_pair(server, "raw-call", go, rust, ["call", "deviceinfo", "GetInfo"], kind="json")
        run_pair(server, "mesh-path-and-sid", go, rust, ["mesh", "--output", "json"], kind="json")
        run_pair(server, "home-list-aha", go, rust, ["home", "list", "--output", "json"], kind="json")
        run_pair(server, "home-list-tr064", go, rust, ["home", "list", "--tr064", "--output", "json"], kind="json")
        run_pair(server, "scrape-data-lua", go, rust, ["scrape", "netDev", "foo=bar"], expected=[("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("POST", "/data.lua", "")])
        run_pair(server, "auth-test-http", go, rust, ["auth", "test"], expected=[("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("POST", "/upnp/control/deviceinfo", "GetInfo")])
        mutations = [("wol", ["wol", "--mac", MAC], [("POST", "/upnp/control/hosts", "X_AVM-DE_WakeOnLANByMACAddress")]), ("dial", ["dial", "123"], [("POST", "/upnp/control/x_voip", "X_AVM-DE_DialNumber")]), ("hangup", ["hangup"], [("POST", "/upnp/control/x_voip", "X_AVM-DE_DialHangup")]), ("guest-on", ["wlan", "guest", "on"], [("POST", "/upnp/control/wlanconfig3", "SetEnable")]), ("guest-off", ["wlan", "guest", "off"], [("POST", "/upnp/control/wlanconfig3", "SetEnable")]), ("home-switch-on", ["home", "switch", AIN, "on"], [("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("GET", "/webservices/homeautoswitch.lua", "setswitchon")]), ("home-temp", ["home", "temp", AIN, "20.5"], [("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("GET", "/webservices/homeautoswitch.lua", "sethkrtsoll")]), ("home-switch-tr064", ["home", "switch", AIN, "on", "--tr064"], [("POST", "/upnp/control/x_homeauto", "SetSwitch")]), ("reboot-confirmed", ["reboot", "--yes"], [("POST", "/upnp/control/deviceconfig", "Reboot")])]
        for label, args, expected in mutations: run_pair(server, label, go, rust, args, expected=expected)
        config_init_pair(go, rust, False, False); config_init_pair(go, rust, False, True); config_init_pair(go, rust, True, True)
        run_auth_store_pair(go, rust)
        if os.name != "nt":
            # SIGINT must flush at least one equivalent NDJSON snapshot and use 130.
            def watch(binary: str) -> Result:
                temp = tempfile.TemporaryDirectory(prefix="symfritz-watch-"); home = Path(temp.name)
                for name in ("tmp", "config", "cache", "data"): (home / name).mkdir()
                process = subprocess.Popen([binary, "traffic", "--watch", "--output", "json", "--interval", "10ms"], cwd=home, env=environment(home, fake=True), stdout=subprocess.PIPE, stderr=subprocess.PIPE); time.sleep(0.35); process.send_signal(signal.SIGINT); out, err = process.communicate(timeout=4); temp.cleanup(); return Result(process.returncode, out, err)
            server.reset(); left, right = watch(go), watch(rust)
            left_lines, right_lines = left.stdout.splitlines(), right.stdout.splitlines()
            if left.code != 130 or right.code != 130 or not left_lines or not right_lines or left.stderr != right.stderr:
                raise AssertionError("traffic watch cancellation mismatch")
            try:
                left_snapshots = [json.loads(line) for line in left_lines]
                right_snapshots = [json.loads(line) for line in right_lines]
            except json.JSONDecodeError as exc:
                raise AssertionError("traffic watch emitted invalid NDJSON") from exc
            if any(not isinstance(snapshot, dict) for snapshot in left_snapshots + right_snapshots):
                raise AssertionError("traffic watch emitted a non-object snapshot")
            if left_snapshots[-1] != right_snapshots[-1]:
                raise AssertionError("traffic watch final snapshot mismatch")
            print("PASS traffic-watch-json-cancel")
        for case in parse_validation(root):
            args = [str(value) for value in case["args"]]; assert_bytes(str(case["id"]), run(go, args), run(rust, args)); print(f"PASS {case['id']}")
        # Doctor is deterministic in both directions: a healthy configured box and a missing-config failure.
        healthy = "[box]\nhost = \"%s:%d\"\nuser = \"%s\"\nuse_tls = false\ntimeout_seconds = 1\n" % (PRIVATE_IP, PORT, USER)
        def setup_healthy(home: Path) -> None:
            path = home / ".config" / "symfritz"; path.mkdir(parents=True); (path / "config.toml").write_text(healthy)
        server.reset(); left, lh = run_process(go, ["doctor", "--output", "json"], fake=True, setup=setup_healthy); assert_server(server, "doctor healthy Go")
        server.reset(); right, rh = run_process(rust, ["doctor", "--output", "json"], fake=True, setup=setup_healthy); assert_server(server, "doctor healthy Rust")
        assert_json("doctor-healthy", Result(left.code, normalize_paths(left.stdout, [lh]), left.stderr), Result(right.code, normalize_paths(right.stdout, [rh]), right.stderr)); print("PASS doctor-healthy")
        server.reset(); left, lh = run_process(go, ["doctor", "--output", "json"], fake=True); assert_server(server, "doctor failure Go")
        server.reset(); right, rh = run_process(rust, ["doctor", "--output", "json"], fake=True); assert_server(server, "doctor failure Rust")
        if left.code == 0 or right.code == 0 or left.stderr.startswith(b"Error: doctor found failing checks") is False or right.stderr.startswith(b"Error: doctor found failing checks") is False:
            raise AssertionError("doctor expected failure status mismatch")
        assert_json("doctor-expected-failure", Result(left.code, normalize_paths(left.stdout, [lh]), b""), Result(right.code, normalize_paths(right.stdout, [rh]), b"")); print("PASS doctor-expected-failure")
        print(f"PASS strict-fake-http requests={len(server.requests)}")
    finally:
        server.shutdown(); server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--go", default="./symfritz"); parser.add_argument("--rust", default="./target/debug/symfritz-rust"); parser.add_argument("--root", default="."); args = parser.parse_args()
    try: run_suite(os.path.abspath(args.go), os.path.abspath(args.rust), Path(args.root).resolve())
    except (AssertionError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr); return 1
    return 0


if __name__ == "__main__": raise SystemExit(main())
