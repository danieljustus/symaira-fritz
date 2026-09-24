#!/usr/bin/env python3
"""Strict executable contract coverage for the Rust CLI.

The fake box binds to every interface on a fixed high port.  The subprocesses
connect through this machine's private RFC1918 address, which exercises the
same explicit host:port origins used by a real local box. Every route,
SOAP action, argument, SID, digest challenge, and mutation sequence is
allow-listed; an unexpected request is a failure, never a generic 200.
"""
from __future__ import annotations

import argparse
import copy
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
import xml.etree.ElementTree as ET
try:
    import pty
except ImportError:  # Windows has no PTY module.
    pty = None
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Mapping, cast
from urllib.parse import parse_qsl, urlencode, urlsplit

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
<service><serviceType>urn:dslforum-org:service:WLANConfiguration:1</serviceType><controlURL>/upnp/control/wlanconfig1</controlURL></service>
<service><serviceType>urn:dslforum-org:service:WLANConfiguration:2</serviceType><controlURL>/upnp/control/wlanconfig2</controlURL></service>
<service><serviceType>urn:dslforum-org:service:WLANConfiguration:3</serviceType><controlURL>/upnp/control/wlanconfig3</controlURL></service>
</serviceList></device></root>'''
HOSTS_XML = b'''<?xml version="1.0"?><List><Item><IPAddress>192.168.1.20</IPAddress><MACAddress>AA:BB:CC:DD:EE:FF</MACAddress><Active>1</Active><HostName>laptop</HostName><InterfaceType>Ethernet</InterfaceType><AddressSource>DHCP</AddressSource><LeaseTimeRemaining>3600</LeaseTimeRemaining></Item></List>'''
MESH_JSON = b'''{"schema_version":"1","nodes":[{"uid":"node-1","device_name":"fritz.box","device_model":"FRITZ!Box","is_meshed":true,"mesh_role":"master","node_interfaces":[]}]}'''
LOG_XML = b'''<?xml version="1.0"?><DeviceLog><Event><id>1</id><group>sys</group><date>01.01.26</date><time>12:00:00</time><msg>Started</msg></Event></DeviceLog>'''
CALLS_XML = b'''<?xml version="1.0"?><CallList><Call><Type>1</Type><Caller>123</Caller><Called>456</Called><Name>Alice</Name><Date>01.01.26 12:00</Date><Duration>00:01</Duration></Call></CallList>'''
FILTERED_CALLS_XML = b'''<?xml version="1.0"?><CallList><Call><Type>1</Type><Caller>111</Caller><Called>999</Called><Name>Incoming</Name><Date>01.01.26 12:00</Date><Duration>00:01</Duration></Call><Call><Type>2</Type><Caller>222</Caller><Called>999</Called><Name>Missed</Name><Date>01.01.26 12:01</Date><Duration>00:01</Duration></Call></CallList>'''
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


def cap_call_list_xml(body: bytes, limit: int) -> bytes:
    start = body.index(b"<CallList>") + len(b"<CallList>")
    end = body.rindex(b"</CallList>")
    calls = re.findall(br"<Call>.*?</Call>", body[start:end], flags=re.DOTALL)
    return body[:start] + b"".join(calls[:limit]) + body[end:]


def _form_pairs(value: str, label: str) -> list[tuple[str, str]]:
    try:
        pairs = parse_qsl(value, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise AssertionError(f"{label}: malformed query/form data") from exc
    if any(not key for key, _value in pairs):
        raise AssertionError(f"{label}: query/form data contains an empty key")
    return pairs


def _canonical_form(pairs: list[tuple[str, str]]) -> str:
    return urlencode(pairs)


def _query_is_exact(raw_query: str, expected: list[tuple[str, str]]) -> bool:
    try:
        actual = _form_pairs(raw_query, "request query")
    except AssertionError:
        return False
    return actual == expected and raw_query == _canonical_form(expected)


def _login_query_options(response: str) -> tuple[list[tuple[str, str]], ...]:
    """Allow only the exact query order emitted by the two clients."""
    return (
        [("version", "2"), ("response", response), ("username", USER)],
        [("version", "2"), ("username", USER), ("response", response)],
        [("response", response), ("username", USER), ("version", "2")],
    )


def _expected_soap_namespaces(path: str, action: str) -> tuple[str, ...]:
    service = EXPECTED_SERVICES[path]
    if path.startswith("/igdupnp/"):
        prefixes = ("schemas-upnp-org",)
    elif path == "/upnp/control/wancommonifconfig1" and action in {
        "GetCommonLinkProperties",
        "GetAddonInfos",
    }:
        # The Go oracle uses the schema namespace for discovery-driven calls
        # and the dslforum namespace for its direct DSL path.
        prefixes = ("schemas-upnp-org", "dslforum-org")
    else:
        prefixes = ("dslforum-org",)
    return tuple(f"urn:{prefix}:service:{service}" for prefix in prefixes)


def _soap_arguments(
    body: bytes,
    expected_action: str | None = None,
    expected_namespaces: tuple[str, ...] = (),
) -> list[tuple[str, str]]:
    try:
        document = ET.fromstring(body)
    except ET.ParseError as exc:
        raise AssertionError("SOAP body is not well-formed XML") from exc

    def local_name(element: ET.Element) -> str:
        if not isinstance(element.tag, str):
            raise AssertionError("SOAP element has no local name")
        return element.tag.rsplit("}", 1)[-1]

    if local_name(document) != "Envelope" or len(document) != 1:
        raise AssertionError("SOAP body must contain one Envelope/Body pair")
    soap_body = document[0]
    if local_name(soap_body) != "Body" or len(soap_body) != 1:
        raise AssertionError("SOAP body must contain one action element")
    action_element = soap_body[0]
    action = local_name(action_element)
    if expected_action is not None and action != expected_action:
        raise AssertionError(f"SOAP body action {action!r} does not match {expected_action!r}")
    if expected_namespaces:
        expected_tags = {f"{{{namespace}}}{action}" for namespace in expected_namespaces}
        if action_element.tag not in expected_tags:
            raise AssertionError("SOAP body action uses the wrong service namespace")
    if action_element.attrib:
        raise AssertionError("SOAP action has unexpected attributes")
    arguments: list[tuple[str, str]] = []
    for element in action_element:
        name = local_name(element)
        if not name.startswith("New"):
            raise AssertionError(f"SOAP action has unexpected child {name!r}")
        if element.attrib or len(element):
            raise AssertionError(f"SOAP argument {name!r} must be a scalar element")
        arguments.append((name, element.text or ""))
    return arguments


def _expected_soap_arguments(
    action: str, private_ip: str
) -> tuple[tuple[tuple[str, str], ...], ...]:
    if action == "X_AVM-DE_GetOnlineMonitor":
        return ((('NewSyncGroupIndex', '0'),),)
    if action == "X_AVM-DE_DialNumber":
        return ((('NewX_AVM-DE_PhoneNumber', '123'),),)
    if action == "X_AVM-DE_WakeOnLANByMACAddress":
        return ((('NewMACAddress', MAC),),)
    if action == "GetGenericHostEntry":
        return ((('NewIndex', '0'),),)
    if action == "GetSpecificHostEntry":
        return ((('NewMACAddress', MAC),),)
    if action == "X_AVM-DE_GetSpecificHostEntryByIP":
        return ((('NewIPAddress', private_ip),),)
    if action == "GetGenericAssociatedDeviceInfo":
        return ((('NewAssociatedDeviceIndex', '0'),),)
    if action == "GetGenericDeviceInfos":
        return ((('NewIndex', '0'),), (('NewIndex', '1'),))
    if action == "SetEnable":
        return ((('NewEnable', '0'),), (('NewEnable', '1'),))
    if action == "SetSwitch":
        return (
            (('NewAIN', AIN), ('NewSwitchState', 'ON')),
            (('NewAIN', AIN), ('NewSwitchState', 'OFF')),
        )
    # All other allow-listed actions are no-argument calls.
    return ((),)


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
        self.call_list_xml = CALLS_XML
        self.challenge = CHALLENGE

    def reset(self) -> None:
        self.requests.clear()
        self.accepted.clear()
        self.failures.clear()
        self.authenticated.clear()
        self.reject_auth = False
        self.call_list_xml = CALLS_XML
        self.challenge = CHALLENGE


class StrictHandler(http.server.BaseHTTPRequestHandler):
    server: StrictFakeBox  # type: ignore[reportIncompatibleVariableOverride]

    def record(self, method: str, action: str, body: bytes, status: int) -> None:
        self.server.requests.append((method, self.path, action, body, status))

    def reject(self, message: str, *, status: int = 400) -> None:
        self.server.failures.append(message)
        self.reply(b"", "text/plain", status=status)

    def do_PUT(self) -> None:
        self.reject("unexpected HTTP method PUT", status=405)

    def do_PATCH(self) -> None:
        self.reject("unexpected HTTP method PATCH", status=405)

    def do_DELETE(self) -> None:
        self.reject("unexpected HTTP method DELETE", status=405)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        try:
            query_pairs = _form_pairs(parsed.query, f"GET {self.path}")
        except AssertionError as exc:
            self.reject(str(exc))
            return
        query = dict(query_pairs)
        if path == "/login_sid.lua":
            supplied = query.get("response", "")
            expected_response = legacy_response(self.server.challenge, PASSWORD)
            if supplied:
                expected_queries = _login_query_options(expected_response)
            else:
                expected_queries = [[("version", "2")]]
            if not any(
                _query_is_exact(parsed.query, expected_query)
                for expected_query in expected_queries
            ):
                self.reject(f"login_sid.lua carried non-canonical query {parsed.query!r}")
                return
            if supplied and self.server.reject_auth:
                self.reply(b"", "text/xml", status=401)
                return
            if supplied and supplied != expected_response:
                self.server.failures.append("login response did not authenticate test credential")
                self.reply(b"<SessionInfo><SID>0000000000000000</SID></SessionInfo>", "text/xml")
                return
            body = (
                f"<SessionInfo><SID>{SID if supplied else '0000000000000000'}</SID>"
                f"<Challenge>{self.server.challenge}</Challenge><BlockTime>0</BlockTime></SessionInfo>"
            ).encode()
            self.record("GET", "", b"", 200)
            self.server.accepted.append(("GET", path, "", b""))
            self.reply(body, "text/xml")
            return
        if path == "/webservices/homeautoswitch.lua":
            command = query.get("switchcmd", "")
            if command == "getdevicelistinfos":
                expected_query = [("sid", SID), ("switchcmd", command)]
            elif command in {"setswitchon", "setswitchoff"}:
                expected_query = [("ain", AIN), ("sid", SID), ("switchcmd", command)]
            elif command == "sethkrtsoll":
                expected_query = [
                    ("ain", AIN),
                    ("param", "41"),
                    ("sid", SID),
                    ("switchcmd", command),
                ]
            else:
                self.reject(f"unexpected AHA command {command!r}")
                return
            if not _query_is_exact(parsed.query, expected_query):
                self.reject(f"unexpected AHA command/query {command!r} {parsed.query!r}")
                return
            body = AHA_XML if command == "getdevicelistinfos" else b"1"
            self.record("GET", command, b"", 200)
            self.server.accepted.append(("GET", path, command, b""))
            self.reply(body, "text/plain")
            return
        if path == "/query.lua":
            if not _query_is_exact(parsed.query, [("sid", SID)]):
                self.reject(f"query.lua carried non-canonical query {parsed.query!r}", status=403)
                return
            body = b'{"CPUTEMP":"42"}'
            self.record("GET", "", b"", 200)
            self.server.accepted.append(("GET", path, "", b""))
            self.reply(body, "application/json")
            return
        bodies = {
            "/tr64desc.xml": (DESC_XML, "text/xml"),
            "/hosts.xml": (HOSTS_XML, "text/xml"),
            "/mesh.json": (MESH_JSON, "application/json"),
            "/log.xml": (LOG_XML, "text/xml"),
            "/calls.xml": (self.server.call_list_xml, "text/xml"),
            "/devicelog.lua": (LOG_XML, "text/xml"),
        }
        if path not in bodies:
            self.reject(f"GET unexpected path {self.path!r}", status=404)
            return
        if path == "/mesh.json":
            expected_query = [("sid", SID)]
        elif path == "/calls.xml":
            if query_pairs and (
                len(query_pairs) != 1
                or query_pairs[0][0] != "max"
                or not query_pairs[0][1].isdigit()
                or int(query_pairs[0][1]) <= 0
            ):
                self.reject(f"calls.xml carried non-canonical query {parsed.query!r}")
                return
            expected_query = query_pairs
        elif path in {"/log.xml", "/devicelog.lua"}:
            if query_pairs and (
                len(query_pairs) != 1
                or query_pairs[0][0] != "filter"
                or query_pairs[0][1] not in {"sys", "net", "fon", "wlan", "usb"}
            ):
                self.reject(f"device log carried non-canonical query {parsed.query!r}")
                return
            expected_query = query_pairs
        else:
            expected_query = []
        if not _query_is_exact(parsed.query, expected_query):
            self.reject(f"GET {path} carried non-canonical query {parsed.query!r}")
            return
        body, content_type = bodies[path]
        if path == "/calls.xml" and query.get("max"):
            body = cap_call_list_xml(body, int(query["max"]))
        self.record("GET", "", b"", 200)
        self.server.accepted.append(("GET", path, "", b""))
        self.reply(body, content_type)

    def do_POST(self) -> None:
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            self.reject("POST Content-Length is not an integer")
            return
        if length < 0 or length > 1024 * 1024:
            self.server.failures.append("POST missing or oversized Content-Length")
            self.reply(b"", "text/plain", status=400)
            return
        body = self.rfile.read(length)
        request_url = urlsplit(self.path)
        if request_url.path == "/data.lua":
            expected_fields = [("foo", "bar"), ("page", "netDev"), ("sid", SID)]
            try:
                body_text = body.decode("ascii")
            except UnicodeDecodeError as exc:
                self.reject("data.lua body is not canonical ASCII form data")
                return
            if request_url.query or not _query_is_exact(body_text, expected_fields):
                self.reject(f"data.lua carried non-canonical form data {body_text!r}", status=401)
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
            self.reject(f"SOAP body omitted action {action!r}")
            return
        try:
            arguments = tuple(_soap_arguments(body, action, _expected_soap_namespaces(path, action)))
        except AssertionError as exc:
            self.reject(f"{action} carried malformed arguments: {exc}")
            return
        if arguments not in _expected_soap_arguments(action, self.server.private_ip):
            self.reject(f"{action} carried non-canonical arguments: {arguments!r}")
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


def _trace(value: object, label: str) -> list[tuple[str, str, str]]:
    if not isinstance(value, list):
        raise AssertionError(f"{label}: trace must be a list")
    trace: list[tuple[str, str, str]] = []
    for index, entry in enumerate(value):
        if not isinstance(entry, list) or len(entry) != 3 or not all(isinstance(part, str) for part in entry):
            raise AssertionError(f"{label}: trace entry {index} must contain method, path, action strings")
        method, path, action = entry
        if method not in {"GET", "POST"} or not path.startswith("/"):
            raise AssertionError(f"{label}: trace entry {index} is not a strict HTTP request shape")
        trace.append((method, path, action))
    return trace


_POLICY_ID = re.compile(r"^[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+$")
_PACKAGE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_CARGO_TARGET_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")

# These are the only scope labels that are covered by imperative harness code
# rather than one of the declarative rule collections. Keeping this allow-list
# next to the runner makes a policy-only scope expansion fail closed.
_DIRECT_CASE_BINDINGS: dict[str, frozenset[str]] = {
    "CAP-CALL-LIMIT-AFTER-FILTER": frozenset({"calls-filtered-limit"}),
    "CAP-MESH-UID-ALIASES": frozenset({"mesh-path-and-sid", "mesh-yaml"}),
    "SEC-HOST-SELECTOR-EXACTLY-ONE": frozenset({"hosts get", "wol"}),
    "MCP-HOME-SWITCH-BOOLEAN": frozenset({"home_switch"}),
}


class PolicyCaseCoverage:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.expected = {
            target["id"]: frozenset(target["scope"]["cases"])
            for target in policy["approved_target_changes"]
        }
        self.seen: dict[str, set[str]] = {target_id: set() for target_id in self.expected}

    def mark(self, target_id: str, case: str, label: str) -> None:
        if target_id not in self.expected or case not in self.expected[target_id]:
            raise AssertionError(f"{label}: {target_id} does not declare case {case!r}")
        self.seen[target_id].add(case)

    def assert_complete(self) -> None:
        missing = {
            target_id: sorted(self.expected[target_id] - cases)
            for target_id, cases in self.seen.items()
            if self.expected[target_id] - cases
        }
        if missing:
            raise AssertionError(f"policy cases were declared but never executed: {missing!r}")


_ACTIVE_POLICY_COVERAGE: PolicyCaseCoverage | None = None


def _mark_policy_case(policy: dict[str, Any], target_id: str, case: str, label: str) -> None:
    if _ACTIVE_POLICY_COVERAGE is not None:
        _ACTIVE_POLICY_COVERAGE.mark(target_id, case, label)


def _validated_rust_command(
    command: object, label: str, *, expected_test: str | None = None
) -> list[str]:
    if not isinstance(command, list) or not command or not all(
        isinstance(part, str) and part and "\x00" not in part for part in command
    ):
        raise AssertionError(f"{label}: Rust assertion command must be a non-empty argv list")
    argv = cast(list[str], command)
    if argv[:2] != ["cargo", "test"]:
        raise AssertionError(f"{label}: Rust assertion command must start with cargo test")
    if any(part in {";", "&&", "||", "|", ">", ">>", "<"} for part in argv):
        raise AssertionError(f"{label}: Rust assertion command contains a shell operator")

    package: str | None = None
    target_kind: str | None = None
    target_name: str | None = None
    filters: list[str] = []
    locked = 0
    index = 2
    while index < len(argv):
        part = argv[index]
        if part in {"-p", "--package"}:
            if package is not None or index + 1 >= len(argv):
                raise AssertionError(f"{label}: Rust assertion command has an invalid package selector")
            package = argv[index + 1]
            index += 2
            continue
        if part in {"--test", "--bin"}:
            if target_kind is not None or index + 1 >= len(argv):
                raise AssertionError(f"{label}: Rust assertion command has multiple or missing targets")
            target_kind, target_name = part, argv[index + 1]
            index += 2
            continue
        if part == "--lib":
            if target_kind is not None:
                raise AssertionError(f"{label}: Rust assertion command has multiple targets")
            target_kind = part
            index += 1
            continue
        if part == "--locked":
            locked += 1
            index += 1
            continue
        if part.startswith("-"):
            raise AssertionError(f"{label}: Rust assertion command has an unapproved option {part!r}")
        filters.append(part)
        index += 1

    if package is None or not _PACKAGE_NAME.fullmatch(package):
        raise AssertionError(f"{label}: Rust assertion command must name a valid package")
    if target_kind is None or (target_kind != "--lib" and not target_name):
        raise AssertionError(f"{label}: Rust assertion command must select one test target")
    if target_name is not None and not _CARGO_TARGET_NAME.fullmatch(target_name):
        raise AssertionError(f"{label}: Rust assertion command has an invalid target name")
    if len(filters) != 1 or not _CARGO_TARGET_NAME.fullmatch(filters[0]):
        raise AssertionError(f"{label}: Rust assertion command must have exactly one test filter")
    if expected_test is not None and filters != [expected_test]:
        raise AssertionError(f"{label}: Rust assertion command must run only the named test")
    if locked != 1:
        raise AssertionError(f"{label}: Rust assertion command must use --locked exactly once")
    return argv


def _validate_rust_assertion(root: Path, target: dict[str, Any], label: str) -> None:
    assertion = target.get("rust_assertion")
    if not isinstance(assertion, dict) or set(assertion) != {"path", "test", "command"}:
        raise AssertionError(f"{label}: rust_assertion must contain path, test, and command")
    source_path, test_name, command = assertion["path"], assertion["test"], assertion["command"]
    if (
        not isinstance(source_path, str)
        or not source_path.endswith(".rs")
        or Path(source_path).is_absolute()
        or ".." in Path(source_path).parts
        or not isinstance(test_name, str)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", test_name)
    ):
        raise AssertionError(f"{label}: invalid Rust assertion metadata")
    argv = _validated_rust_command(command, label, expected_test=test_name)
    root = root.resolve()
    source = (root / source_path).resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise AssertionError(f"{label}: Rust assertion source escapes the repository: {source_path}") from exc
    if not source.is_file():
        raise AssertionError(f"{label}: Rust assertion source does not exist: {source_path}")
    try:
        source_text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise AssertionError(f"{label}: cannot read Rust assertion source: {source_path}") from exc
    if not re.search(rf"\bfn\s+{re.escape(test_name)}\s*\(", source_text):
        raise AssertionError(f"{label}: Rust assertion test is not present in {source_path}")
    if "--test" in argv:
        target_index = argv.index("--test") + 1
        if target_index >= len(argv) or argv[target_index] != source.stem:
            raise AssertionError(f"{label}: --test target must match the assertion source file")


def _policy_target(policy: dict[str, Any], target_id: str, label: str) -> dict[str, Any]:
    targets = [
        target
        for target in policy["approved_target_changes"]
        if target.get("id") == target_id
    ]
    if len(targets) != 1:
        raise AssertionError(f"{label}: policy must contain exactly one target {target_id}")
    return targets[0]


def _require_target_case(policy: dict[str, Any], target_id: str, case: str, label: str) -> None:
    target = _policy_target(policy, target_id, label)
    if case not in target["scope"]["cases"]:
        raise AssertionError(f"{label}: case {case!r} is not covered by {target_id}")


def _unique_strings(value: object, *, allow_empty: bool = False) -> bool:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        return False
    return (allow_empty or bool(value)) and len(value) == len(set(value))


def _validate_scoped_cases(
    policy: dict[str, Any], target_id: str, cases: list[str], label: str
) -> None:
    target = _policy_target(policy, target_id, label)
    missing = sorted(set(cases) - set(target["scope"]["cases"]))
    if missing:
        raise AssertionError(f"{label}: cases are outside {target_id} scope: {missing!r}")


def _validate_scoped_paths(
    policy: dict[str, Any], target_id: str, paths: list[str], label: str
) -> None:
    target = _policy_target(policy, target_id, label)
    declared = target["scope"].get("paths", [])
    if not declared or set(paths) != set(declared):
        raise AssertionError(f"{label}: paths must exactly match {target_id} scope")


def _require_structured_success_case(policy: dict[str, Any], case: str, label: str) -> None:
    matches = [
        rule
        for rule in policy["harness"]["structured_success_cases"]
        if case in rule["cases"]
    ]
    if len(matches) != 1 or matches[0]["id"] != "CLI-STRUCTURED-MUTATION-OUTPUT":
        raise AssertionError(
            f"{label}: structured success case {case!r} is not covered by the policy"
        )


def validate_policy(root: Path, policy: object) -> dict[str, Any]:
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise AssertionError("divergence policy schema_version must be 1")
    oracle = policy.get("oracle")
    if oracle != {
        "implementation": "Go",
        "tag": "v0.7.0",
        "commit": "b1491793aea173eac926e1a0c9db5ba6dd4604a9",
    }:
        raise AssertionError("divergence policy must pin the immutable v0.7.0 Go oracle")
    harness = policy.get("harness")
    if not isinstance(harness, dict):
        raise AssertionError("divergence policy harness must be an object")
    collection_names = (
        "help_flag_overrides",
        "request_trace_overrides",
        "structured_transforms",
        "config_template_overrides",
        "byte_stream_overrides",
        "structured_success_cases",
    )
    collections = {name: harness.get(name) for name in collection_names}
    if any(not isinstance(value, list) for value in collections.values()):
        raise AssertionError("divergence policy rule collections must be lists")
    target_changes = policy.get("approved_target_changes")
    if not isinstance(target_changes, list) or not target_changes:
        raise AssertionError("divergence policy approved_target_changes must be a non-empty list")

    target_ids: set[str] = set()
    for index, target in enumerate(target_changes):
        label = f"approved_target_changes[{index}]"
        if not isinstance(target, dict):
            raise AssertionError(f"{label}: target must be an object")
        target_id = target.get("id")
        if (
            not isinstance(target_id, str)
            or not _POLICY_ID.fullmatch(target_id)
            or target_id in target_ids
        ):
            raise AssertionError(f"{label}: every target needs a unique stable ID")
        target_ids.add(target_id)
        for field in ("surface", "reason", "rationale", "test"):
            if not isinstance(target.get(field), str) or not target[field].strip():
                raise AssertionError(f"{label}: {field} must be a non-empty string")
        if target["reason"] != target["rationale"]:
            raise AssertionError(f"{label}: reason and rationale must agree")
        scope = target.get("scope")
        if not isinstance(scope, dict) or not isinstance(scope.get("kind"), str) or not scope["kind"].strip():
            raise AssertionError(f"{label}: scope must declare a kind")
        cases = scope.get("cases")
        if not _unique_strings(cases):
            raise AssertionError(f"{label}: scope cases must be unique non-empty strings")
        paths = scope.get("paths", [])
        if not _unique_strings(paths, allow_empty=True):
            raise AssertionError(f"{label}: scope paths must be unique non-empty strings")
        _validate_rust_assertion(root, target, label)
        assertion = target["rust_assertion"]
        expected_test = f"{assertion['path']}::{assertion['test']}"
        if target["test"] != expected_test:
            raise AssertionError(f"{label}: test must identify the declared Rust assertion")

    seen_help: set[tuple[str, str]] = set()
    for index, rule in enumerate(collections["help_flag_overrides"]):
        label = f"help_flag_overrides[{index}]"
        if (
            not isinstance(rule, dict)
            or rule.get("id") not in target_ids
            or not isinstance(rule.get("flag"), str)
            or not rule["flag"].startswith("--")
        ):
            raise AssertionError(f"{label}: invalid help override policy rule")
        paths_value = rule.get("paths")
        if not _unique_strings(paths_value):
            raise AssertionError(f"{label}: invalid help override policy rule")
        paths = cast(list[str], paths_value)
        _validate_scoped_paths(policy, rule["id"], paths, label)
        for side in ("oracle", "candidate"):
            value = rule.get(side)
            if (
                not isinstance(value, dict)
                or set(value) != {"default", "description"}
                or (value["default"] is not None and not isinstance(value["default"], str))
                or not isinstance(value["description"], str)
            ):
                raise AssertionError(f"{label}: invalid {side} help override")
        for command_path in rule["paths"]:
            if not isinstance(command_path, str) or not command_path or (command_path, rule["flag"]) in seen_help:
                raise AssertionError(f"{label}: help override paths must be unique strings")
            seen_help.add((command_path, rule["flag"]))

    seen_cases: set[str] = set()
    for index, rule in enumerate(collections["request_trace_overrides"]):
        label = f"request_trace_overrides[{index}]"
        if not isinstance(rule, dict) or rule.get("id") not in target_ids or not isinstance(rule.get("cases"), dict) or not rule["cases"]:
            raise AssertionError(f"{label}: invalid request trace override policy rule")
        _validate_scoped_cases(policy, rule["id"], list(rule["cases"]), label)
        for case, traces in rule["cases"].items():
            if not isinstance(case, str) or not case or case in seen_cases or not isinstance(traces, dict) or set(traces) != {"go", "rust"}:
                raise AssertionError(f"{label}: request trace case ids must be unique")
            _trace(traces["go"], f"{label} {case} Go")
            _trace(traces["rust"], f"{label} {case} Rust")
            seen_cases.add(case)

    seen_transform_cases: set[str] = set()
    for index, rule in enumerate(collections["structured_transforms"]):
        label = f"structured_transforms[{index}]"
        if (
            not isinstance(rule, dict)
            or set(rule) != {"id", "cases", "kind", "paths", "test"}
            or rule.get("id") not in target_ids
            or rule.get("kind") not in {"remove_one_terminal_z", "null_to_empty_array"}
            or not isinstance(rule.get("test"), str)
            or not rule["test"].strip()
        ):
            raise AssertionError(f"{label}: invalid structured transform policy rule")
        cases = rule.get("cases")
        paths_by_case = rule.get("paths")
        if not _unique_strings(cases):
            raise AssertionError(f"{label}: structured transform case ids must be unique strings")
        if not isinstance(paths_by_case, dict):
            raise AssertionError(f"{label}: structured transform paths must be a case mapping")
        cases = cast(list[str], cases)
        if set(paths_by_case) != set(cases):
            raise AssertionError(f"{label}: transform paths must cover exactly the declared cases")
        _validate_scoped_cases(policy, rule["id"], cases, label)
        for case in cases:
            if case in seen_transform_cases:
                raise AssertionError(f"{label}: structured transform case ids must be globally unique")
            path_values = paths_by_case[case]
            if not _unique_strings(path_values):
                raise AssertionError(f"{label} {case}: exact JSON paths must be unique non-empty strings")
            for path in path_values:
                _json_path_tokens(path, f"{label} {case}")
            seen_transform_cases.add(case)

    seen_template_cases: set[str] = set()
    for index, rule in enumerate(collections["config_template_overrides"]):
        label = f"config_template_overrides[{index}]"
        cases = rule.get("cases") if isinstance(rule, dict) else None
        if not isinstance(rule, dict) or rule.get("id") not in target_ids or not isinstance(rule.get("candidate_insert"), str) or not rule["candidate_insert"]:
            raise AssertionError(f"{label}: invalid config template override policy rule")
        if not _unique_strings(cases):
            raise AssertionError(f"{label}: config template case ids must be unique strings")
        cases = cast(list[str], cases)
        _validate_scoped_cases(policy, rule["id"], cases, label)
        for case in cases:
            if case in seen_template_cases:
                raise AssertionError(f"{label}: config template case ids must be globally unique")
            seen_template_cases.add(case)

    seen_byte_cases: set[str] = set()
    for index, rule in enumerate(collections["byte_stream_overrides"]):
        label = f"byte_stream_overrides[{index}]"
        cases = rule.get("cases") if isinstance(rule, dict) else None
        if not isinstance(rule, dict) or rule.get("id") not in target_ids or not isinstance(cases, dict) or not cases:
            raise AssertionError(f"{label}: invalid byte stream override policy rule")
        _validate_scoped_cases(policy, rule["id"], list(cases), label)
        for case, prefixes in cases.items():
            if not isinstance(case, str) or not case or case in seen_byte_cases or not isinstance(prefixes, dict) or set(prefixes) != {"oracle_stdout_prefix", "candidate_stdout_prefix"}:
                raise AssertionError(f"{label}: byte stream case ids must be unique")
            if not all(isinstance(prefixes.get(key), str) for key in ("oracle_stdout_prefix", "candidate_stdout_prefix")):
                raise AssertionError(f"{label}: byte stream override prefixes must be strings")
            seen_byte_cases.add(case)

    seen_success_cases: set[str] = set()
    valid_schema_types = {"boolean", "integer", "number", "string", "array", "object"}
    for index, rule in enumerate(collections["structured_success_cases"]):
        label = f"structured_success_cases[{index}]"
        cases = rule.get("cases") if isinstance(rule, dict) else None
        schemas = rule.get("schemas") if isinstance(rule, dict) else None
        if (
            not isinstance(rule, dict)
            or set(rule) != {"id", "cases", "schemas", "test"}
            or rule.get("id") not in target_ids
            or not _unique_strings(cases)
            or not isinstance(rule.get("test"), str)
            or not rule["test"].strip()
            or not isinstance(schemas, dict)
        ):
            raise AssertionError(f"{label}: invalid structured success policy rule")
        cases = cast(list[str], cases)
        if set(schemas) != set(cases):
            raise AssertionError(f"{label}: success schemas must cover exactly the declared cases")
        _validate_scoped_cases(policy, rule["id"], cases, label)
        for case in cases:
            if case in seen_success_cases:
                raise AssertionError(f"{label}: structured success case ids must be unique strings")
            schema = schemas[case]
            if not isinstance(schema, dict) or set(schema) != {"required", "properties"}:
                raise AssertionError(f"{label} {case}: schema must declare required and properties")
            required = schema["required"]
            properties = schema["properties"]
            if not _unique_strings(required) or not isinstance(properties, dict) or set(properties) != set(required):
                raise AssertionError(f"{label} {case}: required fields must exactly match properties")
            for field in required:
                specification = properties[field]
                if (
                    not isinstance(specification, dict)
                    or not set(specification).issubset({"type", "const", "non_empty"})
                    or specification.get("type") not in valid_schema_types
                ):
                    raise AssertionError(f"{label} {case}: invalid schema for field {field!r}")
                if "non_empty" in specification and not isinstance(specification["non_empty"], bool):
                    raise AssertionError(f"{label} {case}: non_empty must be boolean")
                if "const" in specification and not _matches_json_type(specification["const"], specification["type"]):
                    raise AssertionError(f"{label} {case}: const has the wrong type for field {field!r}")
            seen_success_cases.add(case)

    bound_cases: dict[str, set[str]] = {}
    for collection_name in (
        "request_trace_overrides",
        "structured_transforms",
        "config_template_overrides",
        "byte_stream_overrides",
        "structured_success_cases",
    ):
        for rule in collections[collection_name]:
            rule = cast(dict[str, Any], rule)
            target_id = rule["id"]
            rule_cases = rule["cases"]
            if collection_name in {"request_trace_overrides", "byte_stream_overrides"}:
                cases = cast(dict[str, Any], rule_cases).keys()
            else:
                cases = cast(list[str], rule_cases)
            bound_cases.setdefault(target_id, set()).update(cases)
    for target_id, cases in _DIRECT_CASE_BINDINGS.items():
        bound_cases.setdefault(target_id, set()).update(cases)
    for target in target_changes:
        target_id = target["id"]
        declared = set(target["scope"]["cases"])
        if bound_cases.get(target_id, set()) != declared:
            raise AssertionError(
                f"{target_id}: scope cases must be bound to executed harness assertions"
            )
    if set(bound_cases) != target_ids:
        raise AssertionError("every approved target must have an executed harness assertion binding")
    return policy


def _assertion_ran_one_test(output: bytes, test_name: str, label: str) -> None:
    text = output.decode("utf-8", "replace")
    if not re.search(r"(?m)^running 1 test$", text):
        raise AssertionError(f"{label}: Rust assertion command ran zero or multiple tests")
    if not re.search(
        rf"(?m)^test [^\r\n]*\b{re.escape(test_name)} \.\.\. ok$", text
    ):
        raise AssertionError(f"{label}: named Rust assertion did not pass")


def run_rust_assertions(root: Path, policy: dict[str, Any]) -> None:
    """Run every policy assertion through cargo without invoking a shell."""
    for index, target in enumerate(policy["approved_target_changes"]):
        label = f"approved_target_changes[{index}] {target['id']}"
        assertion = target["rust_assertion"]
        command = _validated_rust_command(
            assertion["command"], label, expected_test=assertion["test"]
        )
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                env={**os.environ, "CARGO_TERM_COLOR": "never"},
                shell=False,
                capture_output=True,
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AssertionError(f"{label}: Rust assertion could not execute") from exc
        if completed.returncode != 0:
            raise AssertionError(
                f"{label}: Rust assertion failed with exit code {completed.returncode}"
            )
        _assertion_ran_one_test(completed.stdout + completed.stderr, assertion["test"], label)
        if target["id"] == "MCP-HOME-SWITCH-BOOLEAN":
            for case in _DIRECT_CASE_BINDINGS[target["id"]]:
                _mark_policy_case(policy, target["id"], case, label)


def load_policy(root: Path) -> dict[str, Any]:
    path = root / "testdata/port/divergence-policy.json"
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssertionError(f"invalid divergence policy {path}: {exc}") from exc
    return validate_policy(root, policy)


def _apply_help_overrides(path: str, flags: dict[str, FlagContract], policy: dict[str, Any], side: str) -> dict[str, FlagContract]:
    result = dict(flags)
    for rule in policy["harness"]["help_flag_overrides"]:
        if path not in rule["paths"]:
            continue
        flag_name = rule["flag"]
        flag = result.get(flag_name)
        expected = rule[side]
        if flag is None or flag.default != expected["default"] or flag.description != expected["description"]:
            raise AssertionError(f"{rule['id']} {path}: unexpected {side} help flag contract for {flag_name}: {flag!r}")
        result[flag_name] = replace(flag, default="<approved-target-change>", description=rule["id"])
    return result


def compare_help_contract(label: str, expected: HelpContract, actual: HelpContract, root_expected: HelpContract, root_actual: HelpContract, path: str, expected_aliases: tuple[str, ...], actual_aliases: tuple[str, ...], expected_contracts: dict[str, HelpContract], actual_contracts: dict[str, HelpContract], policy: dict[str, Any]) -> None:
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
    expected_flags = _apply_help_overrides(path, _effective_flags(expected, root_expected, path, expected_inherited), policy, "oracle")
    actual_flags = _apply_help_overrides(path, _effective_flags(actual, root_actual, path, actual_inherited), policy, "candidate")
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


def temporary_directory(prefix: str) -> tempfile.TemporaryDirectory[str]:
    """Create harness state below Python's native platform temporary root."""
    return tempfile.TemporaryDirectory(prefix=prefix, dir=tempfile.gettempdir())


def runtime_path_entries(source: Mapping[str, str], *, is_windows: bool) -> list[str]:
    if not is_windows:
        return []
    system_root = source.get("SystemRoot") or source.get("WINDIR")
    if not system_root:
        raise AssertionError("Windows runtime PATH requires SystemRoot or WINDIR")
    return [str(PureWindowsPath(system_root) / "System32")]


def isolated_path(home: Path, path_prefix: Path | None, source: Mapping[str, str], *, is_windows: bool) -> str:
    backend_free = home / "empty-path"; backend_free.mkdir(exist_ok=True)
    entries = ([str(path_prefix)] if path_prefix is not None else []) + [str(backend_free)]
    if path_prefix is not None and not is_windows:
        # Unix helper and PTY tests need the host runtime only in explicit helper mode.
        entries.append(source.get("PATH", ""))
    entries.extend(runtime_path_entries(source, is_windows=is_windows))
    separator = ";" if is_windows else os.pathsep
    return separator.join(entry for entry in entries if entry)


def environment(home: Path, *, fake: bool, extra: dict[str, str] | None = None, path_prefix: Path | None = None) -> dict[str, str]:
    source = os.environ
    env = {key: value for key, value in source.items() if not key.upper().startswith("SYMFRITZ_")}
    path = isolated_path(home, path_prefix, source, is_windows=os.name == "nt")
    env.update({"HOME": str(home), "USERPROFILE": str(home), "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"), "XDG_DATA_HOME": str(home / "data"), "TMPDIR": str(home / "tmp"), "TMP": str(home / "tmp"), "TEMP": str(home / "tmp"), "PATH": path, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    if fake:
        env.update({"SYMFRITZ_BOX_HOST": f"{PRIVATE_IP}:{PORT}", "SYMFRITZ_BOX_USER": USER, "SYMFRITZ_BOX_USE_TLS": "false", "SYMFRITZ_PASSWORD": PASSWORD, "SYMFRITZ_BOX_TIMEOUT_SECONDS": "1"})
    env.update(extra or {})
    return env


def run_process(binary: str, args: list[str], *, fake: bool = False, setup: Callable[[Path], None] | None = None, extra: dict[str, str] | None = None, path_prefix: Path | None = None, timeout: float = 8) -> tuple[Result, Path]:
    temp = temporary_directory("symfritz-cli-"); home = Path(temp.name)
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


def run_pty_process(binary: str, args: list[str], *, fake: bool = False, path_prefix: Path | None = None, password: str = PASSWORD) -> Result:
    if pty is None:
        raise AssertionError("auth login PTY coverage is unavailable on this platform")
    with temporary_directory("symfritz-login-") as raw:
        home = Path(raw)
        for name in ("tmp", "config", "cache", "data"):
            (home / name).mkdir()
        master, slave = pty.openpty()
        child_env = environment(home, fake=fake, path_prefix=path_prefix)
        child_env.pop("SYMFRITZ_PASSWORD", None)
        process = subprocess.Popen(
            [binary, *args],
            cwd=home,
            env=child_env,
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(slave)
        os.write(master, password.encode() + b"\n")
        stdout, stderr = process.communicate(timeout=8)
        os.close(master)
        return Result(process.returncode, stdout, stderr)


def _structured_success_schema(
    policy: dict[str, Any], case: str, label: str
) -> dict[str, Any]:
    matches = [
        rule
        for rule in policy["harness"]["structured_success_cases"]
        if case in rule["cases"]
    ]
    if len(matches) != 1:
        raise AssertionError(f"{label}: structured success case {case!r} is not uniquely covered")
    return matches[0]["schemas"][case]


def _matches_json_type(value: Any, type_name: str) -> bool:
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "object":
        return isinstance(value, dict)
    return False


def assert_success_object(
    label: str,
    result: Result,
    kind: str,
    policy: dict[str, Any],
    *,
    case: str,
) -> Any:
    if result.code != 0:
        raise AssertionError(f"{label}: command failed with {result.code}: {result.stderr!r}")
    try:
        value = json.loads(result.stdout) if kind == "json" else parse_minimal_yaml(result.stdout)
    except (json.JSONDecodeError, AssertionError) as exc:
        raise AssertionError(f"{label}: structured output is invalid: {result.stdout!r}") from exc
    schema = _structured_success_schema(policy, case, label)
    required = schema["required"]
    properties = schema["properties"]
    if not isinstance(value, dict) or set(value) != set(required):
        raise AssertionError(
            f"{label}: structured success keys mismatch: got={sorted(value) if isinstance(value, dict) else value!r} "
            f"want={sorted(required)!r}"
        )
    for name in required:
        specification = properties[name]
        actual = value[name]
        if not _matches_json_type(actual, specification["type"]):
            raise AssertionError(
                f"{label}: structured success field {name!r} has wrong type: {actual!r}"
            )
        if "const" in specification and actual != specification["const"]:
            raise AssertionError(
                f"{label}: structured success field {name!r} has wrong value: {actual!r}"
            )
        if specification.get("non_empty") and not actual:
            raise AssertionError(f"{label}: structured success field {name!r} is empty")
    _mark_policy_case(policy, "CLI-STRUCTURED-MUTATION-OUTPUT", case, label)
    return value


def normalize_paths(value: bytes, homes: list[Path]) -> bytes:
    for home in homes: value = value.replace(str(home).encode(), b"<HOME>")
    return value


def _byte_stream_transform(label: str, value: bytes, policy: dict[str, Any] | None, side: str) -> bytes:
    if policy is None:
        return value
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for rule in policy["harness"]["byte_stream_overrides"]:
        cases = rule["cases"]
        if label in cases:
            matches.append((rule, cases[label]))
    if not matches:
        return value
    if len(matches) != 1:
        raise AssertionError(f"{label}: multiple byte stream overrides apply")
    rule, prefixes = matches[0]
    key = f"{side}_stdout_prefix"
    _mark_policy_case(policy, rule["id"], label, label)
    prefix = prefixes[key].format(private_ip=PRIVATE_IP, port=PORT).encode()
    if not value.startswith(prefix):
        raise AssertionError(f"{label}: {side} stdout did not match the declared approved prefix")
    return value[len(prefix) :]


def assert_bytes(
    label: str,
    left: Result,
    right: Result,
    homes: list[Path] | None = None,
    policy: dict[str, Any] | None = None,
) -> None:
    homes = homes or []
    values = [
        (left.code, _byte_stream_transform(label, normalize_paths(left.stdout, homes), policy, "oracle"), normalize_paths(left.stderr, homes)),
        (right.code, _byte_stream_transform(label, normalize_paths(right.stdout, homes), policy, "candidate"), normalize_paths(right.stderr, homes)),
    ]
    if values[0] != values[1]: raise AssertionError(f"{label}: exact mismatch Go={values[0]!r} Rust={values[1]!r}")


def _normalize_structured(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize_structured(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_structured(item) for item in value]
    if isinstance(value, str):
        normalized_path = value.replace("\\", "/")
        if "/symfritz-cli-" in normalized_path and normalized_path.endswith(
            "/.config/symfritz/config.toml"
        ):
            return "<HOME>/.config/symfritz/config.toml"
    return value


def _json_path_tokens(path: str, label: str) -> list[str | int]:
    if not isinstance(path, str) or not path.startswith("$") or path == "$":
        raise AssertionError(f"{label}: transform path must start with $ and select a value")
    tokens: list[str | int] = []
    index = 1
    while index < len(path):
        if path[index] == ".":
            match = re.match(r"\.([A-Za-z_][A-Za-z0-9_]*)", path[index:])
            if match is None:
                raise AssertionError(f"{label}: malformed JSON path {path!r}")
            tokens.append(match.group(1))
            index += len(match.group(0))
        elif path[index] == "[":
            match = re.match(r"\[(0|[1-9][0-9]*)\]", path[index:])
            if match is None:
                raise AssertionError(f"{label}: malformed JSON path {path!r}")
            tokens.append(int(match.group(1)))
            index += len(match.group(0))
        else:
            raise AssertionError(f"{label}: malformed JSON path {path!r}")
    return tokens


def _path_value(value: Any, tokens: list[str | int], label: str) -> Any:
    current = value
    for token in tokens:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise AssertionError(f"{label}: JSON path does not exist")
        else:
            if not isinstance(current, dict) or token not in current:
                raise AssertionError(f"{label}: JSON path does not exist")
        current = current[token]
    return current


def _set_path_value(value: Any, tokens: list[str | int], replacement: Any, label: str) -> None:
    parent = _path_value(value, tokens[:-1], label) if len(tokens) > 1 else value
    token = tokens[-1]
    if isinstance(token, int):
        if not isinstance(parent, list) or token >= len(parent):
            raise AssertionError(f"{label}: JSON path does not exist")
    elif not isinstance(parent, dict) or token not in parent:
        raise AssertionError(f"{label}: JSON path does not exist")
    parent[token] = replacement


def _structured_transform(label: str, value: Any, policy: dict[str, Any] | None, side: str) -> Any:
    normalized = _normalize_structured(value)
    if policy is None:
        return normalized
    matches = [rule for rule in policy["harness"]["structured_transforms"] if label in rule["cases"]]
    if not matches:
        return normalized
    if len(matches) != 1:
        raise AssertionError(f"{label}: multiple structured transforms apply")
    rule = matches[0]
    paths = rule["paths"].get(label)
    if not isinstance(paths, list) or not paths:
        raise AssertionError(f"{rule['id']} {label}: no exact transform paths declared")
    transformed = copy.deepcopy(normalized)
    changed = 0
    for path in paths:
        tokens = _json_path_tokens(path, f"{rule['id']} {label}")
        current = _path_value(transformed, tokens, f"{rule['id']} {label} {path}")
        replacement = current
        if rule["kind"] == "remove_one_terminal_z":
            if isinstance(current, str) and current.endswith("Z"):
                replacement = current[:-1]
        elif rule["kind"] == "null_to_empty_array":
            if current is None:
                replacement = []
        if replacement is not current:
            _set_path_value(transformed, tokens, replacement, f"{rule['id']} {label} {path}")
            changed += 1
    if side == "oracle" and changed != len(paths):
        raise AssertionError(
            f"{rule['id']} {label}: frozen Go output changed {changed} "
            f"of {len(paths)} declared JSON path occurrences"
        )
    if side == "candidate" and changed != 0:
        raise AssertionError(f"{rule['id']} {label}: Rust output still contains a declared Go-only difference")
    _mark_policy_case(policy, rule["id"], label, label)
    return transformed


def assert_json(label: str, left: Result, right: Result, policy: dict[str, Any] | None = None) -> None:
    if left.code != right.code or left.stderr != right.stderr: raise AssertionError(f"{label}: exit/stderr mismatch: {left} != {right}")
    try: lobj, robj = json.loads(left.stdout), json.loads(right.stdout)
    except json.JSONDecodeError as exc: raise AssertionError(f"{label}: non-JSON output Go={left.stdout!r} Rust={right.stdout!r}") from exc
    if _structured_transform(label, lobj, policy, "oracle") != _structured_transform(label, robj, policy, "candidate"):
        raise AssertionError(f"{label}: JSON mismatch Go={lobj!r} Rust={robj!r}")


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


def assert_yaml(
    label: str,
    left: Result,
    right: Result,
    policy: dict[str, Any] | None = None,
) -> None:
    if left.code != right.code or left.stderr != right.stderr:
        raise AssertionError(f"{label}: exit/stderr mismatch: {left} != {right}")
    lobj, robj = parse_minimal_yaml(left.stdout), parse_minimal_yaml(right.stdout)
    lobj = _structured_transform(label, lobj, policy, "oracle")
    robj = _structured_transform(label, robj, policy, "candidate")
    if lobj != robj:
        raise AssertionError(f"{label}: YAML mismatch Go={lobj!r} Rust={robj!r}")


def assert_help(label: str, left: Result, right: Result) -> None:
    if left.code != 0 or right.code != 0: raise AssertionError(f"{label}: help failed {left.code}, {right.code}")
    for output in (left.stdout, right.stdout):
        if b"Usage:" not in output or not output.endswith(b"\n"): raise AssertionError(f"{label}: missing Usage/newline")


def accepted_requests(server: StrictFakeBox) -> list[tuple[str, str, str, bytes]]:
    return list(server.accepted)


def accepted_actions(server: StrictFakeBox) -> list[tuple[str, str, str]]:
    return [(method, path, action) for method, path, action, _body in accepted_requests(server)]


def assert_server(
    server: StrictFakeBox,
    label: str,
    expected: list[tuple[str, str, str]] | None = None,
    *,
    unordered: bool = False,
) -> None:
    if server.failures: raise AssertionError(f"{label}: fake-box failures: {'; '.join(server.failures)}")
    if expected is None: return
    actual = accepted_actions(server)
    if unordered:
        # The Go oracle fans radio probes out concurrently, so only the request
        # multiset is contractual for cases declared unordered.
        if sorted(actual) != sorted(expected): raise AssertionError(f"{label}: request multiset mismatch got={actual!r} want={expected!r}")
    elif actual != expected: raise AssertionError(f"{label}: request sequence mismatch got={actual!r} want={expected!r}")


def _trace_override(policy: dict[str, Any] | None, label: str) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]] | None:
    if policy is None:
        return None
    matches: list[dict[str, Any]] = []
    for rule in policy["harness"]["request_trace_overrides"]:
        cases = rule["cases"]
        if label in cases:
            matches.append(cases[label])
    if not matches:
        return None
    if len(matches) != 1:
        raise AssertionError(f"{label}: multiple request trace overrides apply")
    traces = matches[0]
    return _trace(traces["go"], f"{label} Go"), _trace(traces["rust"], f"{label} Rust")


def assert_shared_request_bodies(
    label: str,
    go_requests: list[tuple[str, str, str, bytes]],
    rust_requests: list[tuple[str, str, str, bytes]],
    expected_go: list[tuple[str, str, str]],
    expected_rust: list[tuple[str, str, str]],
) -> None:
    """Keep payloads strict for the request legs shared by an approved trace."""
    shared = set(expected_go) & set(expected_rust)
    for request in shared:
        go_bodies = [
            body
            for method, path, action, body in go_requests
            if (method, path, action) == request
        ]
        rust_bodies = [
            body
            for method, path, action, body in rust_requests
            if (method, path, action) == request
        ]
        expected_go_count = expected_go.count(request)
        expected_rust_count = expected_rust.count(request)
        if len(go_bodies) != expected_go_count or len(rust_bodies) != expected_rust_count:
            raise AssertionError(
                f"{label}: shared request cardinality mismatch for {request}: "
                f"Go={len(go_bodies)}/{expected_go_count} "
                f"Rust={len(rust_bodies)}/{expected_rust_count}"
            )
        # An asymmetric count is an approved trace difference. Every occurrence
        # that exists on both sides is still compared by its occurrence index.
        for index in range(min(len(go_bodies), len(rust_bodies))):
            if go_bodies[index] != rust_bodies[index]:
                raise AssertionError(f"{label}: shared request body mismatch for {request} at occurrence {index}")


def run_pair(
    server: StrictFakeBox,
    label: str,
    go: str,
    rust: str,
    args: list[str],
    *,
    kind: str = "bytes",
    expected: list[tuple[str, str, str]] | None = None,
    extra: dict[str, str] | None = None,
    unordered_requests: bool = False,
    policy: dict[str, Any] | None = None,
) -> None:
    override = _trace_override(policy, label)
    if override is not None:
        expected_go, expected_rust = override
        if expected is not None and expected != expected_rust:
            raise AssertionError(f"{label}: inline expectation disagrees with divergence policy")
    else:
        expected_go = expected
        expected_rust = expected
    # A divergence-policy case may still be declared unordered: the oracle's
    # per-radio fan-out has no contractual completion order.
    unordered_trace = override is not None and unordered_requests
    server.reset(); left = run(go, args, fake=True, extra=extra); assert_server(server, label + " Go", expected_go, unordered=unordered_trace); go_requests = accepted_requests(server)
    server.reset(); right = run(rust, args, fake=True, extra=extra); assert_server(server, label + " Rust", expected_rust, unordered=unordered_trace); rust_requests = accepted_requests(server)
    if override is None:
        requests_match = (
            sorted(go_requests) == sorted(rust_requests)
            if unordered_requests
            else go_requests == rust_requests
        )
        if not requests_match: raise AssertionError(f"{label}: request/argument mismatch Go={go_requests!r} Rust={rust_requests!r}")
    else:
        assert expected_go is not None and expected_rust is not None
        assert_shared_request_bodies(label, go_requests, rust_requests, expected_go, expected_rust)
    if kind == "json": assert_json(label, left, right, policy)
    elif kind == "yaml": assert_yaml(label, left, right, policy)
    else: assert_bytes(label, left, right)
    if override is not None:
        assert policy is not None
        for rule in policy["harness"]["request_trace_overrides"]:
            if label in rule["cases"]:
                _mark_policy_case(policy, rule["id"], label, label)
                break
    print(f"PASS {label}")


def run_calls_filter_limit_target(
    server: StrictFakeBox,
    go: str,
    rust: str,
    policy: dict[str, Any],
) -> None:
    _require_target_case(
        policy,
        "CAP-CALL-LIMIT-AFTER-FILTER",
        "calls-filtered-limit",
        "calls-filtered-limit",
    )
    args = ["calls", "--type", "missed", "--limit", "1", "--json"]

    def run_target(binary: str, label: str) -> tuple[Result, str]:
        server.reset()
        server.call_list_xml = FILTERED_CALLS_XML
        result = run(binary, args, fake=True)
        assert_server(
            server,
            label,
            [
                ("POST", "/upnp/control/x_contact", "GetCallList"),
                ("GET", "/calls.xml", ""),
            ],
        )
        call_request = next(
            request[1]
            for request in reversed(server.requests)
            if request[0] == "GET" and urlsplit(request[1]).path == "/calls.xml"
        )
        return result, call_request

    oracle, oracle_request = run_target(go, "calls-filtered-limit Go")
    candidate, candidate_request = run_target(rust, "calls-filtered-limit Rust")
    if urlsplit(oracle_request).query != "max=1":
        raise AssertionError(f"calls-filtered-limit: Go must pass router max before filtering: {oracle_request!r}")
    if urlsplit(candidate_request).query:
        raise AssertionError(f"calls-filtered-limit: Rust must omit router max while filtering: {candidate_request!r}")
    oracle_json = json.loads(oracle.stdout)
    candidate_json = json.loads(candidate.stdout)
    if oracle.code != 0 or candidate.code != 0 or oracle.stderr or candidate.stderr:
        raise AssertionError("calls-filtered-limit: command execution mismatch")
    if oracle_json is not None:
        raise AssertionError(f"calls-filtered-limit: Go baseline must lose the filtered row: {oracle_json!r}")
    if (
        not isinstance(candidate_json, list)
        or len(candidate_json) != 1
        or candidate_json[0].get("Type") != 2
        or candidate_json[0].get("Caller") != "Missed"
        or candidate_json[0].get("Date", "").endswith("Z")
    ):
        raise AssertionError(f"calls-filtered-limit: Rust target result mismatch: {candidate_json!r}")
    print("PASS calls-filtered-limit")
    _mark_policy_case(policy, "CAP-CALL-LIMIT-AFTER-FILTER", "calls-filtered-limit", "calls-filtered-limit")


def run_structured_matrix(
    server: StrictFakeBox,
    binary: str,
    label: str,
    args: list[str],
    expected: list[tuple[str, str, str]],
    *,
    policy: dict[str, Any],
    extra: dict[str, str] | None = None,
    unordered_requests: bool = False,
) -> None:
    _require_structured_success_case(policy, label, label)
    for format_name, kind in (("json", "json"), ("yaml", "yaml")):
        format_args = args + (["--json"] if format_name == "json" else ["--output", "yaml"])
        server.reset()
        result = run(binary, format_args, fake=True, extra=extra)
        assert_server(server, f"{label}-{format_name}", expected)
        assert_success_object(
            f"{label}-{format_name}",
            result,
            kind,
            policy,
            case=label,
        )
        if unordered_requests:
            # This helper is used only for deterministic mutation routes.
            raise AssertionError(f"{label}: unordered structured mutation coverage is unsupported")
        print(f"PASS {label}-{format_name}")


def parse_validation(root: Path) -> list[dict[str, Any]]:
    values = json.loads((root / "testdata/port/cli/command-contracts.json").read_text(encoding="utf-8"))["validation"]
    if len(values) != 17: raise AssertionError(f"fixture validation count changed: {len(values)}")
    return values


def config_setup(home: Path, content: str) -> None:
    path = home / ".config" / "symfritz"; path.mkdir(parents=True)
    (path / "config.toml").write_text(content)


def _config_template_transform(label: str, value: bytes | None, policy: dict[str, Any], side: str) -> bytes | None:
    if value is None:
        return None
    matches = [rule for rule in policy["harness"]["config_template_overrides"] if label in rule["cases"]]
    if not matches:
        return value
    if len(matches) != 1:
        raise AssertionError(f"{label}: multiple config template overrides apply")
    rule = matches[0]
    addition = rule["candidate_insert"].encode()
    if side == "oracle":
        if addition in value:
            raise AssertionError(f"{rule['id']} {label}: frozen Go template unexpectedly contains the Rust-only setting")
        _mark_policy_case(policy, rule["id"], label, label)
        return value
    if value.count(addition) != 1:
        raise AssertionError(f"{rule['id']} {label}: Rust template must contain exactly one approved setting block")
    _mark_policy_case(policy, rule["id"], label, label)
    return value.replace(addition, b"", 1)


def config_init_pair(go: str, rust: str, force: bool, existing: bool, policy: dict[str, Any]) -> None:
    def run_config(binary: str) -> tuple[Result, bytes | None, int | None, str]:
        with temporary_directory("symfritz-config-") as raw:
            home = Path(raw)
            for name in ("tmp", "config", "cache", "data"): (home / name).mkdir()
            if existing: config_setup(home, "# existing\n[box]\nhost = \"old\"\n")
            args = ["config", "init"] + (["--force"] if force else [])
            process = subprocess.run([binary, *args], cwd=home, env=environment(home, fake=False), capture_output=True, timeout=8)
            result = Result(process.returncode, process.stdout, process.stderr)
            path = home / ".config" / "symfritz" / "config.toml"
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
    left_bytes = _config_template_transform(label, left_bytes, policy, "oracle")
    right_bytes = _config_template_transform(label, right_bytes, policy, "candidate")
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
        source = directory / "symvault.rs"
        source.write_text(
            "use std::{env, fs::OpenOptions, io::{self, Read, Write}};\n"
            "fn main() {\n"
            " let mut payload = Vec::new(); io::stdin().read_to_end(&mut payload).unwrap();\n"
            f" let mut file = OpenOptions::new().create(true).append(true).open({json.dumps(str(metadata))}).unwrap();\n"
            " let args: Vec<String> = env::args().skip(1).map(|value| format!(\"\\\"{}\\\"\", value)).collect();\n"
            " writeln!(file, \"{{\\\"args\\\":[{}],\\\"length\\\":{},\\\"newline\\\":{}}}\", args.join(\",\"), payload.len(), payload.last() == Some(&b'\\n')).unwrap();\n"
            "}\n"
        )
        subprocess.run(
            ["rustc", "-o", str(directory / "symvault.exe"), str(source)],
            check=True,
            capture_output=True,
        )
    else:
        script = directory / "symvault"
        script.write_text(f"#!{sys.executable}\nexec(compile(open({str(helper)!r}).read(), {str(helper)!r}, 'exec'))\n")
        script.chmod(0o755)


def run_auth_store_pair(go: str, rust: str, policy: dict[str, Any]) -> None:
    with temporary_directory("symfritz-vault-mock-") as raw:
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
        _require_structured_success_case(policy, "auth-store-symvault", "auth-store-symvault")
        for format_name, kind in (("json", "json"), ("yaml", "yaml")):
            metadata.write_text("")
            flag = ["--json"] if format_name == "json" else ["--output", "yaml"]
            result = run(rust, ["auth", "store", "--symvault", "fritz.password", *flag], fake=True, path_prefix=directory)
            assert_success_object(
                f"auth-store-symvault-{format_name}",
                result,
                kind,
                policy,
                case="auth-store-symvault",
            )
            records = [json.loads(line) for line in metadata.read_text().splitlines() if line]
            if len(records) != 1 or records[0] != {"args": ["set", "fritz.password", "--stdin-value"], "length": len(PASSWORD) + 1, "newline": True}:
                raise AssertionError(f"auth store {format_name} mock metadata mismatch: {records!r}")
            if PASSWORD.encode() in result.stdout + result.stderr:
                raise AssertionError(f"auth store {format_name} leaked password")
            print(f"PASS auth-store-symvault-{format_name}")


def run_auth_login_contracts(
    server: StrictFakeBox,
    binary: str,
    policy: dict[str, Any],
) -> None:
    if os.name != "nt" and pty is None:
        raise AssertionError("auth-login success coverage requires a PTY on non-Windows hosts")
    expected = [("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("POST", "/upnp/control/deviceinfo", "GetInfo")]
    _require_structured_success_case(policy, "auth-login", "auth-login")
    with temporary_directory("symfritz-login-vault-") as raw:
        directory = Path(raw)
        metadata = directory / "symvault.meta"
        mock_symvault(directory, metadata)
        cases = (("text", None), ("json", ["--json"]), ("yaml", ["--output", "yaml"]))
        for format_name, flags in cases:
            metadata.write_text("")
            server.reset()
            if os.name == "nt":
                result = run(
                    binary,
                    ["auth", "login", "--symvault", "fritz.password", *(flags or [])],
                    fake=True,
                    path_prefix=directory,
                )
            else:
                result = run_pty_process(
                    binary,
                    ["auth", "login", "--symvault", "fritz.password", *(flags or [])],
                    fake=True,
                    path_prefix=directory,
                )
            if not server.accepted:
                raise AssertionError(f"auth-login-{format_name}: command result {result!r}")
            assert_server(server, f"auth-login-{format_name}", expected)
            if PASSWORD.encode() in result.stdout + result.stderr:
                raise AssertionError(f"auth login {format_name} leaked password")
            if format_name == "text":
                if b"Verified: web login" not in result.stdout or b"Stored in symvault" not in result.stdout:
                    raise AssertionError(f"auth login text output mismatch: {result.stdout!r}")
            else:
                assert_success_object(
                    f"auth-login-{format_name}",
                    result,
                    format_name,
                    policy,
                    case="auth-login",
                )
            records = [json.loads(line) for line in metadata.read_text().splitlines() if line]
            if len(records) != 1 or records[0] != {"args": ["set", "fritz.password", "--stdin-value"], "length": len(PASSWORD) + 1, "newline": True}:
                raise AssertionError(f"auth login {format_name} mock metadata mismatch: {records!r}")
            print(f"PASS auth-login-{format_name}")


def auth_trust_contracts(binary: str, policy: dict[str, Any]) -> None:
    _require_structured_success_case(policy, "auth-trust", "auth-trust")
    for format_name, flags in (("text", []), ("json", ["--json"]), ("yaml", ["--output", "yaml"])):
        result = run(binary, ["auth", "trust", "--reset", "no-pin-recorded", *flags])
        if format_name == "text":
            if result.code != 0 or result.stdout != b"No pin recorded for no-pin-recorded.\n":
                raise AssertionError(f"auth trust text output mismatch: {result!r}")
        else:
            assert_success_object(
                f"auth-trust-{format_name}",
                result,
                format_name,
                policy,
                case="auth-trust",
            )
        print(f"PASS auth-trust-{format_name}")


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
    go, rust = resolve_distinct_binaries(go, rust)
    policy = load_policy(root)
    coverage = PolicyCaseCoverage(policy)
    global _ACTIVE_POLICY_COVERAGE
    _ACTIVE_POLICY_COVERAGE = coverage
    try:
        run_rust_assertions(root, policy)
    except BaseException:
        _ACTIVE_POLICY_COVERAGE = None
        raise
    PRIVATE_IP = private_address()
    server = StrictFakeBox(("0.0.0.0", PORT), PRIVATE_IP); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        fixture_data = json.loads((root / "testdata/port/cli/command-contracts.json").read_text(encoding="utf-8"))
        command_cases = {case["path"]: case for case in fixture_data["commands"]}
        if len(command_cases) != 49:
            raise AssertionError(f"fixture command count changed: {len(command_cases)}")
        go_contracts: dict[str, HelpContract] = {}
        rust_contracts: dict[str, HelpContract] = {}
        for path, case in command_cases.items():
            left = run(go, case["help_args"])
            if left.code != 0 or left.stderr:
                raise AssertionError(f"help-{path}: frozen Go oracle command failed")
            if os.name != "nt":
                assert_bytes(f"help-fixture-{path}", left, Result(case["exit_code"], case["stdout"].encode(), case["stderr"].encode()))
            right = run(rust, case["help_args"])
            if right.code != 0 or right.stderr:
                raise AssertionError(f"help-{path}: command failed")
            go_contracts[path] = parse_help(path, left.stdout)
            rust_contracts[path] = parse_help(path, right.stdout)
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
                policy,
            )
        # The immutable fixture bytes are Unix-frozen. Both executable help trees
        # remain structurally compared on every native platform, including Windows.
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
        run_pair(server, "diagnose-router-json", go, rust, ["diagnose", "router", "--json"], kind="json", extra={"SYMFRITZ_HOST": PRIVATE_IP})
        run_pair(server, "diagnose-router-output-json", go, rust, ["diagnose", "router", "--output", "json"], kind="json", extra={"SYMFRITZ_HOST": PRIVATE_IP})
        run_pair(server, "diagnose-output-after-target", go, rust, ["diagnose", PRIVATE_IP, "--port", str(PORT), "--output", "json"], kind="json", expected=[("POST", "/upnp/control/hosts", "X_AVM-DE_GetSpecificHostEntryByIP")])
        run_pair(server, "status-json", go, rust, ["status", "--output", "json"], kind="json")
        run_pair(server, "hosts-list", go, rust, ["hosts", "list", "--json"], kind="json")
        run_pair(server, "hosts-active", go, rust, ["hosts", "active", "--json"], kind="json")
        _require_target_case(policy, "SEC-HOST-SELECTOR-EXACTLY-ONE", "hosts get", "hosts-by-name")
        run_pair(server, "hosts-by-name", go, rust, ["hosts", "get", "laptop", "--output", "json"], kind="json")
        _mark_policy_case(policy, "SEC-HOST-SELECTOR-EXACTLY-ONE", "hosts get", "hosts-by-name")
        run_pair(server, "wlan-radios", go, rust, ["wlan", "radios", "--json"], kind="json", policy=policy)
        # The Go oracle probes per-radio association lists concurrently. Request
        # completion order is intentionally nondeterministic; the exact request
        # multiset and rendered client order remain contractual. The divergence
        # policy pins both multisets and records that Rust adds the advertised-
        # radio discovery request the fixed three-radio oracle never sends.
        run_pair(server, "wlan-clients", go, rust, ["wlan", "clients", "--json"], kind="json", unordered_requests=True, policy=policy)
        run_pair(server, "wlan-guest-status", go, rust, ["wlan", "guest", "status", "--json"], kind="json", policy=policy)
        run_pair(server, "dsl", go, rust, ["dsl", "--output", "json"], kind="json")
        run_pair(server, "calls", go, rust, ["calls", "--json"], kind="json", policy=policy)
        run_calls_filter_limit_target(server, go, rust, policy)
        run_pair(server, "log", go, rust, ["log", "--json"], kind="json", policy=policy)
        run_pair(server, "raw-call", go, rust, ["call", "deviceinfo", "GetInfo"], kind="json")
        _require_target_case(policy, "CAP-MESH-UID-ALIASES", "mesh-path-and-sid", "mesh-path-and-sid")
        run_pair(server, "mesh-path-and-sid", go, rust, ["mesh", "--output", "json"], kind="json")
        _mark_policy_case(policy, "CAP-MESH-UID-ALIASES", "mesh-path-and-sid", "mesh-path-and-sid")
        run_pair(server, "home-list-aha", go, rust, ["home", "list", "--output", "json"], kind="json", policy=policy)
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
            if label == "mesh-yaml":
                _require_target_case(policy, "CAP-MESH-UID-ALIASES", "mesh-yaml", label)
            run_pair(server, label, go, rust, args, kind="yaml", expected=expected, unordered_requests=unordered, policy=policy)
            if label == "mesh-yaml":
                _mark_policy_case(policy, "CAP-MESH-UID-ALIASES", "mesh-yaml", label)
        run_pair(server, "scrape-data-lua", go, rust, ["scrape", "netDev", "foo=bar"], expected=[("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("POST", "/data.lua", "")])
        run_pair(server, "auth-test-http", go, rust, ["auth", "test"], expected=[("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("POST", "/upnp/control/deviceinfo", "GetInfo")])
        run_structured_matrix(server, rust, "auth-test-http", ["auth", "test"], [("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("POST", "/upnp/control/deviceinfo", "GetInfo")], policy=policy)
        auth_trust_contracts(rust, policy)
        run_auth_login_contracts(server, rust, policy)
        mutations = [("wol", ["wol", "--mac", MAC], [("POST", "/upnp/control/hosts", "X_AVM-DE_WakeOnLANByMACAddress")]), ("dial", ["dial", "123"], [("POST", "/upnp/control/x_voip", "X_AVM-DE_DialNumber")]), ("hangup", ["hangup"], [("POST", "/upnp/control/x_voip", "X_AVM-DE_DialHangup")]), ("guest-on", ["wlan", "guest", "on"], [("GET", "/tr64desc.xml", ""), ("POST", "/upnp/control/wlanconfig3", "SetEnable")]), ("guest-off", ["wlan", "guest", "off"], [("GET", "/tr64desc.xml", ""), ("POST", "/upnp/control/wlanconfig3", "SetEnable")]), ("guest-on-explicit-index", ["wlan", "guest", "on", "--guest-index", "3"], [("POST", "/upnp/control/wlanconfig3", "SetEnable")]), ("home-switch-on", ["home", "switch", AIN, "on"], [("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("GET", "/webservices/homeautoswitch.lua", "setswitchon")]), ("home-temp", ["home", "temp", AIN, "20.5"], [("GET", "/login_sid.lua", ""), ("GET", "/login_sid.lua", ""), ("GET", "/webservices/homeautoswitch.lua", "sethkrtsoll")]), ("home-switch-tr064", ["home", "switch", AIN, "on", "--tr064"], [("POST", "/upnp/control/x_homeauto", "SetSwitch")]), ("reboot-confirmed", ["reboot", "--yes"], [("POST", "/upnp/control/deviceconfig", "Reboot")])]
        for label, args, expected in mutations:
            if label == "wol":
                _require_target_case(policy, "SEC-HOST-SELECTOR-EXACTLY-ONE", "wol", label)
            run_pair(server, label, go, rust, args, expected=expected, policy=policy)
            if label == "wol":
                _mark_policy_case(policy, "SEC-HOST-SELECTOR-EXACTLY-ONE", "wol", label)
            run_structured_matrix(server, rust, label, args, expected, policy=policy)
        config_init_pair(go, rust, False, False, policy); config_init_pair(go, rust, False, True, policy); config_init_pair(go, rust, True, True, policy)
        run_auth_store_pair(go, rust, policy)
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
        assert_bytes("auth-unauthorized", unauthorized_left, unauthorized_right, policy=policy)
        print("PASS auth-unauthorized")
        if os.name != "nt":
            # SIGINT must flush at least two equivalent NDJSON snapshots, use 130,
            # and stop issuing requests after a short cancellation grace period.
            def watch(binary: str) -> Result:
                server.reset()
                temp = temporary_directory("symfritz-watch-")
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
        coverage.assert_complete()
        print(f"PASS strict-fake-http requests={len(server.requests)}")
    finally:
        _ACTIVE_POLICY_COVERAGE = None
        server.shutdown(); server.server_close()


def binary_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as binary:
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_distinct_binaries(go: str, rust: str) -> tuple[str, str]:
    go_path = Path(go).expanduser().resolve(strict=True)
    rust_path = Path(rust).expanduser().resolve(strict=True)
    for label, path in (("--go", go_path), ("--rust", rust_path)):
        if not path.is_file():
            raise AssertionError(f"{label} must resolve to a file: {path}")
    if os.path.samefile(go_path, rust_path):
        raise AssertionError("self-comparison is forbidden: --go and --rust resolve to the same executable")
    if binary_digest(go_path) == binary_digest(rust_path):
        raise AssertionError("self-comparison is forbidden: --go and --rust have identical binary content")
    for label, path in (("--go", go_path), ("--rust", rust_path)):
        if not os.access(path, os.X_OK):
            raise AssertionError(f"{label} must resolve to an executable file: {path}")
    return str(go_path), str(rust_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, help="path to the immutable v0.7.0 Go oracle binary")
    parser.add_argument("--rust", required=True, help="path to the current Rust candidate binary")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    try:
        go, rust = resolve_distinct_binaries(args.go, args.rust)
        run_suite(go, rust, Path(args.root).resolve())
    except (AssertionError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr); return 1
    return 0


if __name__ == "__main__": raise SystemExit(main())
