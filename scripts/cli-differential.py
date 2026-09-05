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
LOG_XML = b'''<?xml version="1.0"?><DeviceLog><Event><id>1</id><group>sys</group><date>01.01.26</date><time>12:00:00</time><msg>Started</msg></Event></DeviceLog>'''
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
        self.reject_auth = False

    def reset(self) -> None:
        self.requests.clear()
        self.accepted.clear()
        self.failures.clear()
        self.authenticated.clear()
        self.reject_auth = False


class StrictHandler(http.server.BaseHTTPRequestHandler):
    server: StrictFakeBox  # type: ignore[reportIncompatibleVariableOverride]

    def record(self, method: str, action: str, body: bytes, status: int) -> None:
        self.server.requests.append((method, self.path, action, body, status))

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        if path == "/login_sid.lua":
            supplied = query.get("response", [""])[0]
            if supplied and self.server.reject_auth:
                self.reply(b"", "text/xml", status=401)
                return
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
        bodies = {"/tr64desc.xml": (DESC_XML, "text/xml"), "/hosts.xml": (HOSTS_XML, "text/xml"), "/mesh.json": (MESH_JSON, "application/json"), "/log.xml": (LOG_XML, "text/xml"), "/calls.xml": (CALLS_XML, "text/xml"), "/devicelog.lua": (LOG_XML, "text/xml")}
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
            if authorization and self.server.reject_auth:
                self.reply(b"", "text/xml", status=401, extra={"WWW-Authenticate": f'Digest realm="{REALM}", nonce="{NONCE}", qop="auth", algorithm=MD5'})
                return
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
        elif action == "X_AVM-DE_GetDeviceLogPath": values = {"NewDeviceLogPath": "/devicelog.lua"}
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
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Cancellation tests may close an in-flight watch response.
            pass

    def log_message(self, format: str, *args: object) -> None: pass


@dataclass
class Result:
    code: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class FlagContract:
    name: str
    short: str
    takes_value: bool
    repeatable: bool
    default: str | None
    description: str


@dataclass(frozen=True)
class HelpContract:
    description: str
    usage: tuple[tuple[str, ...], ...]
    subcommands: dict[str, tuple[str, tuple[str, ...]]]
    aliases: tuple[str, ...]
    flags: dict[str, FlagContract]
    global_flags: dict[str, FlagContract]


_HELP_SECTIONS = {"Flags:", "Options:", "Global Flags:", "Available Commands:", "Commands:", "Aliases:"}
_GO_VALUE_TYPES = {"string", "int", "ints", "uint", "duration", "bool", "float"}


def _clean_help_text(lines: list[str]) -> str:
    return "\n".join(line.rstrip() for line in lines).strip()


def _parse_usage(path: str, lines: list[str]) -> tuple[tuple[str, ...], ...]:
    usages: list[str] = []
    has_subcommands = bool(_parse_subcommands(lines))
    for index, line in enumerate(lines):
        if not line.startswith("Usage:"):
            continue
        value = line.removeprefix("Usage:").strip()
        if value:
            usages.append(value)
        for continuation in lines[index + 1 :]:
            if not continuation.strip() or not continuation.startswith(" "):
                break
            if continuation.lstrip().startswith(tuple(_HELP_SECTIONS)):
                break
            usages.append(continuation.strip())
    shapes: set[tuple[str, ...]] = set()
    for usage in usages:
        if usage.startswith(path):
            usage = usage[len(path) :].strip()
        tokens = re.findall(r"<[^>]+>|\[[^]]+\](?:\.\.\.)?|\S+", usage)
        shape: list[str] = []
        for token in tokens:
            token_name = token.lower().removesuffix("...")
            if token_name in {"[flags]", "[options]"} or (has_subcommands and token_name in {"[command]", "[commands]", "<command>", "<commands>"}):
                continue
            token = token.replace("[Key=Value ...]", "[Key=Value]...")
            token = re.sub(r"\[([^]]+)\]\.\.\.", r"[\1]...", token)
            if token.endswith("...") and token.startswith("["):
                token = token[:-3] + "..."
            shape.append(token)
        shapes.add(tuple(shape))
    return tuple(sorted(shapes))


def _parse_subcommands(lines: list[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    result: dict[str, tuple[str, tuple[str, ...]]] = {}
    section = False
    for line in lines:
        if line.strip() in {"Available Commands:", "Commands:"}:
            section = True
            continue
        if section and line.strip() in _HELP_SECTIONS - {"Available Commands:", "Commands:"}:
            break
        if not section or not line.strip():
            continue
        match = re.match(r"^\s{2,}(\S+)(?:\s{2,})(.+?)\s*$", line)
        if not match:
            continue
        name, description = match.groups()
        aliases = tuple(re.findall(r"\[alias: ([^]]+)\]", description))
        description = re.sub(r"\s*\[alias: [^]]+\]", "", description).rstrip()
        if name != "help":
            result[name] = (description, aliases)
    return result


def _extract_default(description: str) -> tuple[str | None, str]:
    match = re.search(r'\(default "([^"]+)"\)|\(default ([^)]+)\)|\[default: ([^]]+)\]', description)
    if not match:
        return None, description.strip()
    default = next(value for value in match.groups() if value is not None).strip()
    return default, (description[: match.start()] + description[match.end() :]).strip()


def _parse_flags(lines: list[str]) -> tuple[dict[str, FlagContract], dict[str, FlagContract]]:
    local: dict[str, FlagContract] = {}
    inherited: dict[str, FlagContract] = {}
    section: str | None = None
    current: FlagContract | None = None
    for line in lines:
        stripped = line.strip()
        if stripped in {"Flags:", "Options:", "Global Flags:"}:
            section = stripped
            current = None
            continue
        if section and stripped in {"Available Commands:", "Commands:", "Aliases:"}:
            section = None
            current = None
            continue
        if section is None or not stripped:
            continue
        match = re.match(r"^\s+(?:(-[A-Za-z]),\s+)?(--[A-Za-z0-9-]+)(?:\s+(.*?))?\s*$", line)
        if match:
            short, name, rest = match.groups()
            rest = rest or ""
            marker = ""
            description = rest
            first, separator, remainder = rest.partition(" ")
            if first in _GO_VALUE_TYPES or first.startswith("<"):
                marker, description = first, remainder.strip()
            repeatable = marker.endswith("...") or marker == "ints"
            takes_value = bool(marker)
            default, description = _extract_default(description)
            current = FlagContract(name, short or "", takes_value, repeatable, default, description)
            (inherited if section == "Global Flags:" else local)[name] = current
            continue
        if current and line.startswith(" ") and not stripped.startswith(tuple(_HELP_SECTIONS)):
            # Clap wraps descriptions and defaults over multiple lines.
            description = current.description + " " + stripped
            default, description = _extract_default(description)
            current = FlagContract(current.name, current.short, current.takes_value, current.repeatable, default or current.default, description.strip())
            target = inherited if section == "Global Flags:" else local
            target[current.name] = current
    return local, inherited


def parse_help(path: str, output: bytes | str) -> HelpContract:
    text = output.decode() if isinstance(output, bytes) else output
    lines = text.replace("\r\n", "\n").splitlines()
    usage_index = next((index for index, line in enumerate(lines) if line.startswith("Usage:")), len(lines))
    description = _clean_help_text(lines[:usage_index])
    local, inherited = _parse_flags(lines)
    aliases: set[str] = set()
    for index, line in enumerate(lines):
        if line.strip() != "Aliases:":
            continue
        for alias_line in lines[index + 1 :]:
            if not alias_line.strip():
                break
            aliases.update(alias.strip() for alias in alias_line.split(","))
    return HelpContract(description, _parse_usage(path, lines), _parse_subcommands(lines), tuple(sorted(aliases)), local, inherited)


def _canonical_flag(flag: FlagContract, command_name: str) -> FlagContract:
    name = flag.name.removeprefix("--")
    description = flag.description
    if name == "help":
        description = f"help for {command_name}"
    if name == "json":
        description = "Output as JSON"
    return FlagContract(flag.name, flag.short, flag.takes_value, flag.repeatable, flag.default, description)


def _effective_flags(contract: HelpContract, root: HelpContract, command_name: str, inherited: dict[str, FlagContract] | None = None) -> dict[str, FlagContract]:
    flags = dict(inherited or {})
    flags.update(contract.global_flags)
    flags.update(contract.flags)
    if command_name != "symfritz":
        root_globals = dict(root.global_flags)
        root_globals.update({name: value for name, value in root.flags.items() if name.removeprefix("--") in {"output", "json"}})
        for name, flag in root_globals.items():
            flags.setdefault(name, flag)
    return {name: _canonical_flag(flag, command_name.rsplit(" ", 1)[-1]) for name, flag in flags.items()}


def aliases_for(path: str, contracts: dict[str, HelpContract]) -> tuple[str, ...]:
    aliases = set(contracts.get(path, HelpContract("", (), {}, (), {}, {})).aliases)
    if " " in path:
        parent, name = path.rsplit(" ", 1)
        aliases.update(contracts.get(parent, HelpContract("", (), {}, (), {}, {})).subcommands.get(name, ("", ()))[1])
    name = path.rsplit(" ", 1)[-1]
    aliases.discard(name)
    return tuple(sorted(aliases))


def compare_help_contract(label: str, expected: HelpContract, actual: HelpContract, root_expected: HelpContract, root_actual: HelpContract, path: str, expected_aliases: tuple[str, ...], actual_aliases: tuple[str, ...], expected_contracts: dict[str, HelpContract], actual_contracts: dict[str, HelpContract]) -> None:
    if expected.description != actual.description:
        raise AssertionError(f"{label}: long description mismatch Go={expected.description!r} Rust={actual.description!r}")
    if expected.usage != actual.usage:
        raise AssertionError(f"{label}: positional usage mismatch Go={expected.usage!r} Rust={actual.usage!r}")
    expected_commands = {name: description for name, (description, _aliases) in expected.subcommands.items()}
    actual_commands = {name: description for name, (description, _aliases) in actual.subcommands.items()}
    if expected_commands != actual_commands:
        raise AssertionError(f"{label}: subcommands mismatch Go={expected_commands!r} Rust={actual_commands!r}")
    if expected_aliases != actual_aliases:
        raise AssertionError(f"{label}: aliases mismatch Go={expected_aliases!r} Rust={actual_aliases!r}")
    expected_inherited: dict[str, FlagContract] = {}
    actual_inherited: dict[str, FlagContract] = {}
    parts = path.split()
    for index in range(1, len(parts) - 1):
        ancestor_path = " ".join(parts[:index + 1])
        expected_ancestor = expected_contracts.get(ancestor_path)
        actual_ancestor = actual_contracts.get(ancestor_path)
        for name in expected.global_flags:
            if expected_ancestor and name in expected_ancestor.flags:
                expected_inherited[name] = expected_ancestor.flags[name]
            if actual_ancestor and name in actual_ancestor.flags:
                actual_inherited[name] = actual_ancestor.flags[name]
    expected_flags = _effective_flags(expected, root_expected, path, expected_inherited)
    actual_flags = _effective_flags(actual, root_actual, path, actual_inherited)
    if expected_flags != actual_flags:
        raise AssertionError(f"{label}: flags mismatch Go={expected_flags!r} Rust={actual_flags!r}")


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
    env.update({"HOME": str(home), "USERPROFILE": str(home), "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"), "XDG_DATA_HOME": str(home / "data"), "TMPDIR": str(home / "tmp"), "TMP": str(home / "tmp"), "TEMP": str(home / "tmp"), "PATH": path, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
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


def _semantic_key(key: str) -> str:
    """Compare model fields by semantic snake_case, not Go/Rust casing."""
    first = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", key)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first).lower()


def _normalize_structured(value: Any) -> Any:
    if isinstance(value, dict):
        normalized = {_semantic_key(key): _normalize_structured(item) for key, item in value.items()}
        if normalized.get("groups") is None:
            normalized["groups"] = []
        return normalized
    if isinstance(value, list):
        return [_normalize_structured(item) for item in value]
    if isinstance(value, str):
        normalized_path = value.replace("\\", "/")
        if "/symfritz-cli-" in normalized_path and normalized_path.endswith(
            "/.config/symfritz/config.toml"
        ):
            return "<HOME>/.config/symfritz/config.toml"
    return value


def assert_json(label: str, left: Result, right: Result) -> None:
    if left.code != right.code or left.stderr != right.stderr: raise AssertionError(f"{label}: exit/stderr mismatch: {left} != {right}")
    try: lobj, robj = json.loads(left.stdout), json.loads(right.stdout)
    except json.JSONDecodeError as exc: raise AssertionError(f"{label}: non-JSON output Go={left.stdout!r} Rust={right.stdout!r}") from exc
    if _normalize_structured(lobj) != _normalize_structured(robj): raise AssertionError(f"{label}: JSON mismatch Go={lobj!r} Rust={robj!r}")


def _yaml_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"", "null", "~"}:
        return None
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    if value.startswith('"') and value.endswith('"'):
        return json.loads(value)
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def parse_minimal_yaml(output: bytes | str) -> Any:
    text = output.decode() if isinstance(output, bytes) else output
    rows = [(len(line) - len(line.lstrip(" ")), line.strip()) for line in text.replace("\\r\\n", "\\n").splitlines() if line.strip()]
    if not rows:
        raise AssertionError("empty YAML output")

    def block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(rows) or rows[index][0] != indent:
            raise AssertionError("invalid YAML indentation")
        is_list = rows[index][1].startswith("-")
        value: Any = [] if is_list else {}
        while index < len(rows) and rows[index][0] == indent:
            content = rows[index][1]
            if is_list:
                if not content.startswith("-"):
                    break
                item = content[1:].strip()
                index += 1
                if not item:
                    if index >= len(rows) or rows[index][0] <= indent:
                        value.append(None)
                    else:
                        child, index = block(index, rows[index][0])
                        value.append(child)
                    continue
                if ":" not in item:
                    value.append(_yaml_scalar(item))
                    continue
                key, raw = item.split(":", 1)
                key = key.strip()
                entry: dict[str, Any] = {}
                if raw.strip():
                    entry[key] = _yaml_scalar(raw)
                elif index < len(rows) and rows[index][0] > indent:
                    entry[key], index = block(index, rows[index][0])
                else:
                    entry[key] = None
                while index < len(rows) and rows[index][0] > indent:
                    child, next_index = block(index, rows[index][0])
                    if not isinstance(child, dict):
                        raise AssertionError("list mapping continuation is not a mapping")
                    entry.update(child)
                    index = next_index
                value.append(entry)
            else:
                if content.startswith("-") or ":" not in content:
                    raise AssertionError("invalid YAML mapping")
                key, raw = content.split(":", 1)
                key = key.strip()
                index += 1
                if raw.strip():
                    value[key] = _yaml_scalar(raw)
                elif index < len(rows) and rows[index][0] > indent:
                    # The renderer may put an empty collection on the next line
                    # when it is nested under a mapping key.
                    if rows[index][1] in {"[]", "{}"}:
                        value[key] = _yaml_scalar(rows[index][1])
                        index += 1
                    else:
                        value[key], index = block(index, rows[index][0])
                else:
                    value[key] = None
        return value, index

    parsed, index = block(0, rows[0][0])
    if index != len(rows):
        raise AssertionError("unsupported YAML document structure")
    return parsed


def assert_yaml(label: str, left: Result, right: Result) -> None:
    if left.code != right.code or left.stderr != right.stderr:
        raise AssertionError(f"{label}: exit/stderr mismatch: {left} != {right}")
    lobj, robj = parse_minimal_yaml(left.stdout), parse_minimal_yaml(right.stdout)
    if _normalize_structured(lobj) != _normalize_structured(robj):
        raise AssertionError(f"{label}: YAML mismatch Go={lobj!r} Rust={robj!r}")


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


def run_pair(server: StrictFakeBox, label: str, go: str, rust: str, args: list[str], *, kind: str = "bytes", expected: list[tuple[str, str, str]] | None = None, extra: dict[str, str] | None = None, unordered_requests: bool = False) -> None:
    server.reset(); left = run(go, args, fake=True, extra=extra); assert_server(server, label + " Go", expected); go_requests = accepted_requests(server)
    server.reset(); right = run(rust, args, fake=True, extra=extra); assert_server(server, label + " Rust", expected); rust_requests = accepted_requests(server)
    requests_match = (
        sorted(go_requests) == sorted(rust_requests)
        if unordered_requests
        else go_requests == rust_requests
    )
    if not requests_match: raise AssertionError(f"{label}: request/argument mismatch Go={go_requests!r} Rust={rust_requests!r}")
    if kind == "json": assert_json(label, left, right)
    elif kind == "yaml": assert_yaml(label, left, right)
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
            candidates = (
                home / "config" / "symfritz" / "config.toml",
                home / ".config" / "symfritz" / "config.toml",
            )
            path = next((candidate for candidate in candidates if candidate.exists()), candidates[0])
            if not path.exists(): return result, None, None, str(home)
            return result, path.read_bytes(), path.stat().st_mode & 0o777, str(home)
    left, left_bytes, left_mode, left_home = run_config(go); right, right_bytes, right_mode, right_home = run_config(rust)
    label = f"config-init-{('existing' if existing else 'fresh')}{('-force' if force else '')}"
    left_streams = (
        left.code,
        normalize_paths(left.stdout, [Path(left_home)]).replace(b"\\", b"/"),
        normalize_paths(left.stderr, [Path(left_home)]).replace(b"\\", b"/"),
    )
    right_streams = (
        right.code,
        normalize_paths(right.stdout, [Path(right_home)]).replace(b"\\", b"/"),
        normalize_paths(right.stderr, [Path(right_home)]).replace(b"\\", b"/"),
    )
    if left_streams != right_streams:
        raise AssertionError(f"{label}: exact mismatch Go={left_streams!r} Rust={right_streams!r}")
    if (left_bytes, left_mode) != (right_bytes, right_mode): raise AssertionError(f"{label}: config bytes/mode mismatch")
    print(f"PASS {label}")


def mock_symvault(directory: Path, metadata: Path) -> None:
    metadata.write_text("")
    helper = directory / "symvault.py"
    helper.write_text(
        "import json,sys\n"
        "payload=sys.stdin.buffer.read()\n"
        f"with open({str(metadata)!r},'a') as f:\n"
        " json.dump({'args':sys.argv[1:],'length':len(payload),'newline':payload.endswith(b'\\n')},f)\n"
        " f.write('\\n')\n"
    )
    if os.name == "nt":
        source = directory / "symvault.go"
        source.write_text(
            "package main\n"
            'import ("encoding/json"; "io"; "os")\n'
            "func main() {\n"
            " payload, _ := io.ReadAll(os.Stdin)\n"
            f" file, _ := os.OpenFile({json.dumps(str(metadata))}, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)\n"
            " defer file.Close()\n"
            " _ = json.NewEncoder(file).Encode(map[string]any{\"args\": os.Args[1:], \"length\": len(payload), \"newline\": len(payload) > 0 && payload[len(payload)-1] == '\\n'})\n"
            "}\n"
        )
        subprocess.run(
            ["go", "build", "-o", str(directory / "symvault.exe"), str(source)],
            check=True,
            capture_output=True,
        )
    else:
        script = directory / "symvault"
        script.write_text(f"#!{sys.executable}\nexec(compile(open({str(helper)!r}).read(), {str(helper)!r}, 'exec'))\n")
        script.chmod(0o755)


def run_auth_store_pair(go: str, rust: str) -> None:
    with tempfile.TemporaryDirectory(prefix="symfritz-vault-mock-") as raw:
        directory = Path(raw)
        metadata = directory / "symvault.meta"
        mock_symvault(directory, metadata)
        left = run(go, ["auth", "store", "--symvault", "fritz.password"], fake=True, path_prefix=directory)
        right = run(rust, ["auth", "store", "--symvault", "fritz.password"], fake=True, path_prefix=directory)
        assert_bytes("auth-store-symvault", left, right)
        records = [json.loads(line) for line in metadata.read_text().splitlines() if line]
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
        fixture_data = json.loads((root / "testdata/port/cli/command-contracts.json").read_text())
        command_cases = {case["path"]: case for case in fixture_data["commands"]}
        if len(command_cases) != 49:
            raise AssertionError(f"fixture command count changed: {len(command_cases)}")
        go_contracts: dict[str, HelpContract] = {}
        rust_contracts: dict[str, HelpContract] = {}
        for path, case in command_cases.items():
            left = run(go, case["help_args"])
            right = run(rust, case["help_args"])
            if left.code != 0 or right.code != 0 or left.stderr or right.stderr:
                raise AssertionError(f"help-{path}: command failed")
            fixture_contract = parse_help(path, case["stdout"])
            go_contracts[path] = parse_help(path, left.stdout)
            rust_contracts[path] = parse_help(path, right.stdout)
            # Windows Cobra help has platform-specific wrapping/console text
            # normalization. The live Go↔Rust canonical comparison below stays
            # mandatory there; committed-byte drift is gated on Unix where the
            # fixture was generated.
            if os.name != "nt" and go_contracts[path] != fixture_contract:
                raise AssertionError(f"help-{path}: committed Go oracle drifted")
            print(f"PASS help-{path}")
        root_go = go_contracts["symfritz"]
        root_rust = rust_contracts["symfritz"]
        for path in command_cases:
            compare_help_contract(
                f"help-{path}",
                go_contracts[path],
                rust_contracts[path],
                root_go,
                root_rust,
                path,
                aliases_for(path, go_contracts),
                aliases_for(path, rust_contracts),
                go_contracts,
                rust_contracts,
            )
        print("PASS help-contracts-49")
        families = ["auth", "call", "calls", "completion", "config", "detect", "diagnose", "dial", "doctor", "dsl", "hangup", "help", "home", "hosts", "log", "mesh", "reboot", "scrape", "services", "status", "traffic", "version", "wlan", "wol"]
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
        # The Go oracle probes per-radio association lists concurrently. Request
        # completion order is intentionally nondeterministic; the exact request
        # multiset and rendered client order remain contractual.
        run_pair(server, "wlan-clients", go, rust, ["wlan", "clients", "--json"], kind="json", unordered_requests=True)
        run_pair(server, "wlan-guest-status", go, rust, ["wlan", "guest", "status", "--json"], kind="json")
        run_pair(server, "dsl", go, rust, ["dsl", "--output", "json"], kind="json")
        run_pair(server, "calls", go, rust, ["calls", "--json"], kind="json")
        run_pair(server, "log", go, rust, ["log", "--json"], kind="json")
        run_pair(server, "raw-call", go, rust, ["call", "deviceinfo", "GetInfo"], kind="json")
        run_pair(server, "mesh-path-and-sid", go, rust, ["mesh", "--output", "json"], kind="json")
        run_pair(server, "home-list-aha", go, rust, ["home", "list", "--output", "json"], kind="json")
        run_pair(server, "home-list-tr064", go, rust, ["home", "list", "--tr064", "--output", "json"], kind="json")
        yaml_cases = [
            ("status-yaml", ["status", "--output", "yaml"], None, False),
            ("hosts-yaml", ["hosts", "list", "--output", "yaml"], None, False),
            ("wlan-radios-yaml", ["wlan", "radios", "--output", "yaml"], None, False),
            ("wlan-clients-yaml", ["wlan", "clients", "--output", "yaml"], None, True),
            ("dsl-yaml", ["dsl", "--output", "yaml"], None, False),
            ("calls-yaml", ["calls", "--output", "yaml"], None, False),
            ("log-yaml", ["log", "--output", "yaml"], None, False),
            ("traffic-yaml", ["traffic", "--output", "yaml"], None, False),
            ("diagnose-yaml", ["diagnose", PRIVATE_IP, "--port", str(PORT), "--output", "yaml"], None, False),
            ("mesh-yaml", ["mesh", "--output", "yaml"], None, False),
            ("home-list-yaml", ["home", "list", "--output", "yaml"], None, False),
            ("home-list-tr064-yaml", ["home", "list", "--tr064", "--output", "yaml"], None, False),
            ("raw-call-yaml", ["call", "deviceinfo", "GetInfo", "--output", "yaml"], None, False),
            ("services-yaml", ["services", "--output", "yaml"], None, False),
        ]
        for label, args, expected, unordered in yaml_cases:
            run_pair(server, label, go, rust, args, kind="yaml", expected=expected, unordered_requests=unordered)
        run_pair(server, "scrape-data-lua", go, rust, ["scrape", "netDev", "foo=bar"], expected=[("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("POST", "/data.lua", "")])
        run_pair(server, "auth-test-http", go, rust, ["auth", "test"], expected=[("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("POST", "/upnp/control/deviceinfo", "GetInfo")])
        mutations = [("wol", ["wol", "--mac", MAC], [("POST", "/upnp/control/hosts", "X_AVM-DE_WakeOnLANByMACAddress")]), ("dial", ["dial", "123"], [("POST", "/upnp/control/x_voip", "X_AVM-DE_DialNumber")]), ("hangup", ["hangup"], [("POST", "/upnp/control/x_voip", "X_AVM-DE_DialHangup")]), ("guest-on", ["wlan", "guest", "on"], [("POST", "/upnp/control/wlanconfig3", "SetEnable")]), ("guest-off", ["wlan", "guest", "off"], [("POST", "/upnp/control/wlanconfig3", "SetEnable")]), ("home-switch-on", ["home", "switch", AIN, "on"], [("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("GET", "/webservices/homeautoswitch.lua", "setswitchon")]), ("home-temp", ["home", "temp", AIN, "20.5"], [("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("GET", "/webservices/homeautoswitch.lua", "sethkrtsoll")]), ("home-switch-tr064", ["home", "switch", AIN, "on", "--tr064"], [("POST", "/upnp/control/x_homeauto", "SetSwitch")]), ("reboot-confirmed", ["reboot", "--yes"], [("POST", "/upnp/control/deviceconfig", "Reboot")])]
        for label, args, expected in mutations: run_pair(server, label, go, rust, args, expected=expected)
        config_init_pair(go, rust, False, False); config_init_pair(go, rust, False, True); config_init_pair(go, rust, True, True)
        run_auth_store_pair(go, rust)
        noauth_left = run(go, ["auth", "test", "--output", "json"])
        noauth_right = run(rust, ["auth", "test", "--output", "json"])
        if noauth_left.code != 3 or noauth_right.code != 3:
            raise AssertionError(f"missing credential must exit 3: {noauth_left.code}, {noauth_right.code}")
        assert_json("auth-missing-credential", noauth_left, noauth_right)
        print("PASS auth-missing-credential")

        server.reset()
        server.reject_auth = True
        unauthorized_left = run(go, ["auth", "test", "--output", "json"], fake=True)
        assert_server(server, "auth unauthorized Go")
        server.reset()
        server.reject_auth = True
        unauthorized_right = run(rust, ["auth", "test", "--output", "json"], fake=True)
        assert_server(server, "auth unauthorized Rust")
        if unauthorized_left.code != 3 or unauthorized_right.code != 3:
            raise AssertionError(f"unauthorized must exit 3: {unauthorized_left.code}, {unauthorized_right.code}")
        assert_bytes("auth-unauthorized", unauthorized_left, unauthorized_right)
        print("PASS auth-unauthorized")
        if os.name != "nt":
            # SIGINT must flush at least two equivalent NDJSON snapshots, use 130,
            # and stop issuing requests after a short cancellation grace period.
            def watch(binary: str) -> Result:
                server.reset()
                temp = tempfile.TemporaryDirectory(prefix="symfritz-watch-")
                home = Path(temp.name)
                for name in ("tmp", "config", "cache", "data"):
                    (home / name).mkdir()
                started = time.monotonic()
                process = subprocess.Popen(
                    [binary, "traffic", "--watch", "--output", "json", "--interval", "10ms"],
                    cwd=home,
                    env=environment(home, fake=True),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                time.sleep(0.35)
                process.send_signal(signal.SIGINT)
                out, err = process.communicate(timeout=4)
                elapsed = time.monotonic() - started
                request_count = len(server.requests)
                time.sleep(0.15)
                if len(server.requests) != request_count:
                    raise AssertionError(f"traffic watch {binary}: requests continued after cancellation grace")
                temp.cleanup()
                if elapsed > 4.5:
                    raise AssertionError(f"traffic watch {binary}: shutdown exceeded bound")
                return Result(process.returncode, out, err)

            left, right = watch(go), watch(rust)
            left_lines, right_lines = left.stdout.splitlines(), right.stdout.splitlines()
            if (
                left.code != 130
                or right.code != 130
                or len(left_lines) < 2
                or len(right_lines) < 2
                or left.stderr != b""
                or right.stderr != b""
            ):
                raise AssertionError("traffic watch cancellation mismatch")
            try:
                left_snapshots = [json.loads(line) for line in left_lines]
                right_snapshots = [json.loads(line) for line in right_lines]
            except json.JSONDecodeError as exc:
                raise AssertionError("traffic watch emitted invalid NDJSON") from exc
            if any(not isinstance(snapshot, dict) for snapshot in left_snapshots + right_snapshots):
                raise AssertionError("traffic watch emitted a non-object snapshot")
            expected_snapshot = _normalize_structured(left_snapshots[0])
            if any(
                _normalize_structured(snapshot) != expected_snapshot
                for snapshot in left_snapshots + right_snapshots
            ):
                raise AssertionError("traffic watch corresponding snapshots mismatch")
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
