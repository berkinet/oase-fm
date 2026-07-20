#!/usr/bin/env python3
"""Reusable protocol and controller support for OASE InScenio FM-Master EGC.

Protocol ported from mr-suw/ioBroker.oasecontrol (MIT licensed).
The OASE unit is contacted by UDP and then connects back to this program's TLS
server. The program can read outlet states, switch outlets 1-4, and set the
outlet-4 dimmer value.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import logging
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

LOG = logging.getLogger("oase")

START = b"\\#OA"
VERSION = 2
UDP_PORT = 5959
TLS_PORT = 5999

DISCOVERY = 4096
ALIVE = 4352
ALIVE_REPLY = 4607
TCP_REQ = 5120
PASSWORD_CHECK = 40704
SET_LIVE_SCENE = 50176
GET_LIVE_SCENE = 50432

# EGC/RDM packet types discovered in the decompiled OASE libraries.
RDM_DISCOVERY = 0x7000
RDM_DISCOVERY_REPLY = 0x70FF
RDM_REQUEST = 0x7100
RDM_REPLY = 0x71FF

RDM_START_CODE = 0xCC
RDM_SUB_START_CODE = 0x01
RDM_GET = 0x20
RDM_SET = 0x30
RDM_GET_RESPONSE = 0x21
RDM_SET_RESPONSE = 0x31
RDM_SOURCE_UID = bytes.fromhex("000000000001")

# Standard ANSI E1.20 RDM sensor parameter IDs and identifiers used by OASE
# EGC pumps for live telemetry.
RDM_DEVICE_INFO = 0x0060
RDM_SENSOR_DEFINITION = 0x0200
RDM_SENSOR_VALUE = 0x0201
RDM_SENSOR_TYPE_TEMPERATURE = 0x00
RDM_SENSOR_TYPE_POWER = 0x05
RDM_SENSOR_TYPE_ANGULAR_VELOCITY = 0x15
RDM_SENSOR_UNIT_CELSIUS = 0x01
RDM_SENSOR_UNIT_WATTS = 0x0A

RDM_PREFIX_FACTORS = {
    0x00: 1.0,
    0x01: 1e-1,
    0x02: 1e-2,
    0x03: 1e-3,
    0x04: 1e-6,
    0x05: 1e-9,
    0x06: 1e-12,
    0x07: 1e-15,
    0x08: 1e-18,
    0x09: 1e-21,
    0x0A: 1e-24,
    0x11: 1e1,
    0x12: 1e2,
    0x13: 1e3,
    0x14: 1e6,
    0x15: 1e9,
    0x16: 1e12,
    0x17: 1e15,
    0x18: 1e18,
    0x19: 1e21,
    0x1A: 1e24,
}


class OaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class Packet:
    length: int
    version: int
    transaction: int
    packet_type: int
    payload: bytes


@dataclass(frozen=True)
class Discovery:
    hardware_type: int
    device_index: int
    name: str
    serial_number: str
    long_name: str
    order_number: int
    firmware: int
    firmware_low: int
    firmware_high: int
    wifi_channel: int
    network_type: int
    status: str


@dataclass(frozen=True)
class OutletState:
    outlet1: bool
    outlet2: bool
    outlet3: bool
    outlet4: bool
    dimmer4: int


@dataclass(frozen=True)
class ControllerState:
    serial_number: str
    rssi: Optional[int]
    increments: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class EgcDevice:
    article_number: int
    device_identifier: int
    manufacturer_identifier: int
    subdevice_count: int

    @property
    def uid(self) -> bytes:
        return struct.pack(
            ">HI",
            self.manufacturer_identifier,
            self.device_identifier,
        )

    @property
    def uid_text(self) -> str:
        return (
            f"{self.manufacturer_identifier:04X}:"
            f"{self.device_identifier:08X}"
        )


@dataclass(frozen=True)
class EgcDiscoveryResult:
    discover_only_new_devices: int
    devices: tuple[EgcDevice, ...]


@dataclass(frozen=True)
class EgcState:
    device: EgcDevice
    on: bool
    power: int
    rpm: Optional[float] = None
    watts: Optional[float] = None
    module_temperature: Optional[float] = None
    pcb_temperature: Optional[float] = None
    water_temperature: Optional[float] = None


@dataclass(frozen=True)
class RdmSensorDefinition:
    sensor_number: int
    sensor_type: int
    unit: int
    prefix: int
    range_min: int
    range_max: int
    normal_min: int
    normal_max: int
    recorded_value_support: int
    description: str


@dataclass(frozen=True)
class RdmSensorValue:
    sensor_number: int
    present: int
    lowest: int
    highest: int
    recorded: int


@dataclass(frozen=True)
class EgcTelemetrySensors:
    rpm: Optional[RdmSensorDefinition] = None
    watts: Optional[RdmSensorDefinition] = None
    module_temperature: Optional[RdmSensorDefinition] = None
    pcb_temperature: Optional[RdmSensorDefinition] = None
    water_temperature: Optional[RdmSensorDefinition] = None


@dataclass(frozen=True)
class RdmMessage:
    destination_uid: bytes
    source_uid: bytes
    transaction: int
    port_or_response_type: int
    message_count: int
    subdevice: int
    command_class: int
    parameter_id: int
    parameter_data: bytes
    checksum: int


class Protocol:
    def __init__(self) -> None:
        self._transaction = 0

    def make_packet(self, packet_type: int, payload: bytes = b"") -> bytes:
        txn = self._transaction
        self._transaction = (self._transaction + 1) & 0xFF
        # Header is 16 bytes. Bytes 12-15 are reserved and remain zero.
        header = bytearray(16)
        header[0:4] = START
        struct.pack_into("<I", header, 4, len(payload))
        header[8] = VERSION
        header[9] = txn
        struct.pack_into("<H", header, 10, packet_type)
        return bytes(header) + payload

    @staticmethod
    def parse_packet(data: bytes) -> Packet:
        if len(data) < 16:
            raise OaseError(f"Packet too short: {len(data)} bytes")
        if data[:4] != START:
            raise OaseError(f"Bad packet delimiter: {data[:4].hex()}")
        length = struct.unpack_from("<I", data, 4)[0]
        total = 16 + length
        if len(data) < total:
            raise OaseError(f"Incomplete packet: expected {total}, got {len(data)}")
        return Packet(
            length=length,
            version=data[8],
            transaction=data[9],
            packet_type=struct.unpack_from("<H", data, 10)[0],
            payload=data[16:total],
        )


def _cstring(data: bytes) -> str:
    return data.decode("ascii", errors="replace").rstrip("\x00")


def parse_discovery(payload: bytes) -> Discovery:
    if len(payload) < 324:
        raise OaseError(f"Discovery reply too short: {len(payload)}")
    return Discovery(
        hardware_type=payload[0],
        device_index=payload[1],
        name=_cstring(payload[2:34]),
        serial_number=_cstring(payload[34:46]),
        long_name=_cstring(payload[66:130]),
        order_number=struct.unpack_from("<I", payload, 130)[0],
        firmware=payload[187],
        firmware_low=payload[194],
        firmware_high=payload[195],
        wifi_channel=payload[196],
        network_type=payload[197],
        status=_cstring(payload[199:323]),
    )


def parse_alive(payload: bytes) -> ControllerState:
    """Parse an OASE AliveReply, including RSSI on modern controllers."""
    if len(payload) < 33:
        raise OaseError(f"Alive reply too short: {len(payload)} bytes")

    serial_number = _cstring(payload[:12])
    if len(payload) == 33:
        # The legacy 33-byte reply ends with only the device-table increment.
        return ControllerState(serial_number=serial_number, rssi=None)

    rssi = struct.unpack_from("<b", payload, 32)[0]
    increment_count = payload[33]
    expected = 34 + increment_count * 3
    if len(payload) < expected:
        raise OaseError(
            f"Incomplete Alive reply: expected {expected} bytes, got {len(payload)}"
        )

    increments = tuple(
        (
            struct.unpack_from("<H", payload, 34 + index * 3)[0],
            payload[36 + index * 3],
        )
        for index in range(increment_count)
    )
    return ControllerState(
        serial_number=serial_number,
        rssi=rssi,
        increments=increments,
    )


def make_password_payload(password: str) -> bytes:
    # The ioBroker adapter receives a JSON-style escaped string and decodes
    # sequences such as "\\u00xx" before UTF-8 encoding it into a 64-byte field.
    import re

    decoded = re.sub(
        r"\\u([0-9A-Fa-f]{4})",
        lambda m: chr(int(m.group(1), 16)),
        password,
    )
    encoded = decoded.encode("utf-8")[:64]
    return encoded.ljust(64, b"\x00")


def make_get_scene_payload() -> bytes:
    return struct.pack("<BI", 4, 0)


def make_set_scene_payload(item_id: int, value: int) -> bytes:
    if item_id not in range(5):
        raise ValueError("item_id must be 0-4")
    if value not in range(256):
        raise ValueError("value must be 0-255")
    return struct.pack("<BIIBBBB", 4, 0, 0, 100, 2, item_id, value)


def parse_live_scene(payload: bytes) -> bytes:
    if len(payload) < 11:
        raise OaseError(f"Live-scene reply too short: {len(payload)}")
    scene_len = payload[10]
    if len(payload) < 11 + scene_len:
        raise OaseError("Incomplete live-scene data")
    return payload[11 : 11 + scene_len]


def parse_outlets(scene_data: bytes) -> OutletState:
    if len(scene_data) != 5:
        raise OaseError(f"Expected 5 outlet-state bytes, got {len(scene_data)}")
    return OutletState(
        outlet1=scene_data[0] == 0xFF,
        outlet2=scene_data[1] == 0xFF,
        outlet3=scene_data[2] == 0xFF,
        outlet4=scene_data[3] == 0xFF,
        dimmer4=scene_data[4],
    )


def parse_egc_discovery(payload: bytes) -> EgcDiscoveryResult:
    """Parse an OASE 0x70FF EGC/RDM discovery reply.

    All fields in this OASE wrapper are little-endian:
      uint32 discover_only_new_devices
      uint32 number_of_discovered_devices
      repeated:
        uint32 article_number
        uint32 device_identifier
        uint16 manufacturer_identifier
        uint16 subdevice_count
    """
    if len(payload) < 8:
        raise OaseError(f"EGC discovery reply too short: {len(payload)} bytes")

    discover_only_new, count = struct.unpack_from("<II", payload, 0)
    expected = 8 + count * 12
    if len(payload) < expected:
        raise OaseError(
            f"Incomplete EGC discovery reply: expected {expected} bytes, "
            f"got {len(payload)}"
        )

    devices: list[EgcDevice] = []
    offset = 8
    for _ in range(count):
        article, device_id, manufacturer, subdevices = struct.unpack_from(
            "<IIHH", payload, offset
        )
        devices.append(
            EgcDevice(
                article_number=article,
                device_identifier=device_id,
                manufacturer_identifier=manufacturer,
                subdevice_count=subdevices,
            )
        )
        offset += 12

    if len(payload) != expected:
        LOG.debug(
            "EGC discovery reply has %d trailing byte(s): %s",
            len(payload) - expected,
            payload[expected:].hex().upper(),
        )

    return EgcDiscoveryResult(
        discover_only_new_devices=discover_only_new,
        devices=tuple(devices),
    )


def parse_uid(value: str) -> bytes:
    """Parse an RDM UID written as MMMM:DDDDDDDD or 12 hexadecimal digits."""
    compact = value.replace(":", "").replace("-", "").strip()
    if len(compact) != 12:
        raise ValueError(
            "UID must be MMMM:DDDDDDDD or exactly 12 hexadecimal digits"
        )
    try:
        uid = bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError("UID contains non-hexadecimal characters") from exc
    if len(uid) != 6:
        raise ValueError("UID must contain exactly 6 bytes")
    return uid


def parse_hex_bytes(value: str) -> bytes:
    """Parse optional RDM parameter data written as hexadecimal bytes."""
    compact = value.replace(" ", "").replace(":", "").replace("-", "").strip()
    if not compact:
        return b""
    if len(compact) % 2:
        raise ValueError("hexadecimal parameter data must contain whole bytes")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError("parameter data contains non-hexadecimal characters") from exc


def make_rdm_message(
    destination_uid: bytes,
    transaction: int,
    command_class: int,
    parameter_id: int,
    parameter_data: bytes = b"",
    *,
    source_uid: bytes = RDM_SOURCE_UID,
    subdevice: int = 0,
    port_id: int = 1,
) -> bytes:
    """Build a standard RDM request frame for the OASE 0x7100 wrapper."""
    if len(destination_uid) != 6:
        raise ValueError("destination UID must be 6 bytes")
    if len(source_uid) != 6:
        raise ValueError("source UID must be 6 bytes")
    if transaction not in range(256):
        raise ValueError("transaction must be 0-255")
    if command_class not in (RDM_GET, RDM_SET):
        raise ValueError("command class must be RDM GET (0x20) or SET (0x30)")
    if parameter_id not in range(0x10000):
        raise ValueError("parameter ID must be 0-65535")
    if subdevice not in range(0x10000):
        raise ValueError("subdevice must be 0-65535")
    if port_id not in range(256):
        raise ValueError("port ID must be 0-255")
    if len(parameter_data) > 231:
        raise ValueError("RDM parameter data cannot exceed 231 bytes")

    # RDM's message-length byte excludes the final two checksum bytes.
    message_length = 24 + len(parameter_data)
    frame = bytearray(
        (
            RDM_START_CODE,
            RDM_SUB_START_CODE,
            message_length,
        )
    )
    frame.extend(destination_uid)
    frame.extend(source_uid)
    frame.extend(
        (
            transaction,
            port_id,
            0,  # message count
        )
    )
    frame.extend(struct.pack(">H", subdevice))
    frame.append(command_class)
    frame.extend(struct.pack(">H", parameter_id))
    frame.append(len(parameter_data))
    frame.extend(parameter_data)

    checksum = sum(frame) & 0xFFFF
    frame.extend(struct.pack(">H", checksum))
    return bytes(frame)


def parse_rdm_message(data: bytes) -> RdmMessage:
    """Parse and validate a standard RDM frame returned inside 0x71FF."""
    if len(data) < 26:
        raise OaseError(f"RDM reply too short: {len(data)} bytes")
    if data[0] != RDM_START_CODE or data[1] != RDM_SUB_START_CODE:
        raise OaseError(
            "Bad RDM start code: "
            f"{data[:2].hex().upper()} (expected CC01)"
        )

    message_length = data[2]
    total = message_length + 2
    if len(data) < total:
        raise OaseError(
            f"Incomplete RDM reply: expected {total} bytes, got {len(data)}"
        )

    frame = data[:total]
    received_checksum = struct.unpack_from(">H", frame, total - 2)[0]
    calculated_checksum = sum(frame[:-2]) & 0xFFFF
    if received_checksum != calculated_checksum:
        raise OaseError(
            "Bad RDM checksum: "
            f"received 0x{received_checksum:04X}, "
            f"calculated 0x{calculated_checksum:04X}"
        )

    parameter_data_length = frame[23]
    expected_message_length = 24 + parameter_data_length
    if message_length != expected_message_length:
        raise OaseError(
            f"RDM length mismatch: header says {message_length}, "
            f"PDL implies {expected_message_length}"
        )

    if len(data) > total:
        LOG.debug(
            "RDM wrapper has %d trailing byte(s): %s",
            len(data) - total,
            data[total:].hex().upper(),
        )

    return RdmMessage(
        destination_uid=frame[3:9],
        source_uid=frame[9:15],
        transaction=frame[15],
        port_or_response_type=frame[16],
        message_count=frame[17],
        subdevice=struct.unpack_from(">H", frame, 18)[0],
        command_class=frame[20],
        parameter_id=struct.unpack_from(">H", frame, 21)[0],
        parameter_data=frame[24 : 24 + parameter_data_length],
        checksum=received_checksum,
    )


def parse_rdm_sensor_definition(data: bytes) -> RdmSensorDefinition:
    """Parse an ANSI E1.20 SENSOR_DEFINITION response payload."""
    if len(data) < 13:
        raise OaseError(
            f"RDM sensor definition too short: {len(data)} bytes"
        )
    return RdmSensorDefinition(
        sensor_number=data[0],
        sensor_type=data[1],
        unit=data[2],
        prefix=data[3],
        range_min=struct.unpack_from(">h", data, 4)[0],
        range_max=struct.unpack_from(">h", data, 6)[0],
        normal_min=struct.unpack_from(">h", data, 8)[0],
        normal_max=struct.unpack_from(">h", data, 10)[0],
        recorded_value_support=data[12],
        description=data[13:45].decode("utf-8", errors="replace").rstrip("\x00"),
    )


def parse_rdm_sensor_value(data: bytes) -> RdmSensorValue:
    """Parse an ANSI E1.20 SENSOR_VALUE response payload."""
    if len(data) < 9:
        raise OaseError(f"RDM sensor value too short: {len(data)} bytes")
    present, lowest, highest, recorded = struct.unpack_from(">hhhh", data, 1)
    return RdmSensorValue(
        sensor_number=data[0],
        present=present,
        lowest=lowest,
        highest=highest,
        recorded=recorded,
    )


def scale_rdm_sensor_value(
    definition: RdmSensorDefinition,
    value: RdmSensorValue,
) -> float:
    """Apply the SI prefix declared by an RDM sensor definition."""
    if value.sensor_number != definition.sensor_number:
        raise OaseError(
            "RDM sensor number mismatch: "
            f"definition {definition.sensor_number}, value {value.sensor_number}"
        )
    try:
        factor = RDM_PREFIX_FACTORS[definition.prefix]
    except KeyError as exc:
        raise OaseError(
            f"Unsupported RDM sensor prefix 0x{definition.prefix:02X}"
        ) from exc
    return value.present * factor


def _generate_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "com.oase.easycontrol")]
    )
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=7))
        .not_valid_after(now + dt.timedelta(days=7))
        .sign(key, hashes.SHA256())
    )
    key_path = directory / "oase-key.pem"
    cert_path = directory / "oase-cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


class TlsCallbackServer:
    def __init__(self, host: str, port: int, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._listener: Optional[socket.socket] = None
        self._tls_socket: Optional[ssl.SSLSocket] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._connected = threading.Event()
        self._error: Optional[BaseException] = None
        self._tempdir: Optional[tempfile.TemporaryDirectory[str]] = None
        self._rx = bytearray()

    def start(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory(prefix="oase-")
        cert, key = _generate_certificate(Path(self._tempdir.name))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        # Match the cipher set used by the Node implementation. SECLEVEL=0 is
        # needed on modern OpenSSL for compatibility with this older device.
        context.set_ciphers(
            "AES128-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5:"
            "AES256-SHA:AES128-SHA256:AES256-SHA256:@SECLEVEL=0"
        )
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, self.port))
        self._listener.listen(1)
        self._listener.settimeout(self.timeout)

        def accept_loop() -> None:
            self._ready.set()
            try:
                assert self._listener is not None
                raw, addr = self._listener.accept()
                LOG.info("Controller connected from %s:%s", *addr)
                raw.settimeout(self.timeout)
                self._tls_socket = context.wrap_socket(raw, server_side=True)
                self._tls_socket.settimeout(self.timeout)
                LOG.debug(
                    "TLS established: protocol=%s cipher=%s",
                    self._tls_socket.version(),
                    self._tls_socket.cipher(),
                )
                self._connected.set()
            except BaseException as exc:
                self._error = exc
                self._connected.set()

        self._thread = threading.Thread(target=accept_loop, daemon=True)
        self._thread.start()
        self._ready.wait(self.timeout)

    def wait_connected(self) -> None:
        if not self._connected.wait(self.timeout):
            raise OaseError("Timed out waiting for the controller TLS connection")
        if self._error is not None:
            raise OaseError(f"TLS callback failed: {self._error}") from self._error

    def request(self, packet: bytes) -> bytes:
        if self._tls_socket is None:
            raise OaseError("No TLS connection")
        packet_type = (
            struct.unpack_from("<H", packet, 10)[0] if len(packet) >= 12 else None
        )
        if packet_type == PASSWORD_CHECK:
            LOG.debug("TLS send: PASSWORD_CHECK payload=<redacted>")
        else:
            LOG.debug("TLS send: %s", packet.hex().upper())
        self._tls_socket.sendall(packet)
        return self._read_packet()

    def _read_packet(self) -> bytes:
        assert self._tls_socket is not None
        while len(self._rx) < 16:
            chunk = self._tls_socket.recv(4096)
            if not chunk:
                raise OaseError("TLS connection closed by controller")
            self._rx.extend(chunk)
        if self._rx[:4] != START:
            raise OaseError(f"Unexpected TLS data: {bytes(self._rx[:16]).hex()}")
        payload_len = struct.unpack_from("<I", self._rx, 4)[0]
        total = 16 + payload_len
        while len(self._rx) < total:
            chunk = self._tls_socket.recv(4096)
            if not chunk:
                raise OaseError("TLS connection closed during packet")
            self._rx.extend(chunk)
        result = bytes(self._rx[:total])
        del self._rx[:total]
        LOG.debug("TLS receive: %s", result.hex().upper())
        return result

    def close(self) -> None:
        for sock in (self._tls_socket, self._listener):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._tls_socket = None
        self._listener = None
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None

    def __enter__(self) -> "TlsCallbackServer":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class OaseController:
    def __init__(
        self,
        device_ip: str,
        local_ip: str,
        password: str,
        udp_port: int = UDP_PORT,
        tls_port: int = TLS_PORT,
        timeout: float = 10.0,
    ) -> None:
        ipaddress.ip_address(device_ip)
        ipaddress.ip_address(local_ip)
        self.device_ip = device_ip
        self.local_ip = local_ip
        self.password = password
        self.udp_port = udp_port
        self.tls_port = tls_port
        self.timeout = timeout
        self.protocol = Protocol()
        self._udp: Optional[socket.socket] = None
        self._tls: Optional[TlsCallbackServer] = None
        self._rdm_transaction = 0
        self._egc_telemetry_sensors: dict[bytes, EgcTelemetrySensors] = {}

    def _udp_request(self, packet_type: int, payload: bytes = b"") -> Packet:
        if self._udp is None:
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.settimeout(self.timeout)
            self._udp.connect((self.device_ip, self.udp_port))
        packet = self.protocol.make_packet(packet_type, payload)
        LOG.debug("UDP send: %s", packet.hex().upper())
        self._udp.send(packet)
        data = self._udp.recv(65535)
        LOG.debug("UDP receive: %s", data.hex().upper())
        return self.protocol.parse_packet(data)

    def connect(self) -> Discovery:
        self._tls = TlsCallbackServer(self.local_ip, self.tls_port, self.timeout)
        try:
            self._tls.start()
            discovery_packet = self._udp_request(DISCOVERY)
            discovery = parse_discovery(discovery_packet.payload)
            LOG.info(
                "Detected %s (%s), serial %s",
                discovery.long_name,
                discovery.name,
                discovery.serial_number,
            )
            if not discovery.long_name.startswith("FM-Master EGC"):
                raise OaseError(f"Unsupported device: {discovery.long_name}")

            tcp_payload = struct.pack(
                "<BHI",
                0,
                self.tls_port,
                int(time.time()) & 0xFFFFFFFF,
            )
            tcp_reply = self._udp_request(TCP_REQ, tcp_payload)
            if len(tcp_reply.payload) < 2 or tcp_reply.payload[0] != 1:
                raise OaseError(
                    "Controller rejected TLS callback request: "
                    f"{tcp_reply.payload.hex()}"
                )

            self._tls.wait_connected()
            pw_reply = self._tls_request(
                PASSWORD_CHECK,
                make_password_payload(self.password),
            )
            if len(pw_reply.payload) != 1 or pw_reply.payload[0] != 1:
                raise OaseError("Controller password authentication failed")
            LOG.info("Authenticated")
            return discovery
        except BaseException:
            # A failed discovery, callback, TLS, or authentication attempt must
            # release the callback port before callers retry the connection.
            self.close()
            raise

    def _tls_request(self, packet_type: int, payload: bytes = b"") -> Packet:
        if self._tls is None:
            raise OaseError("Not connected")
        raw = self._tls.request(self.protocol.make_packet(packet_type, payload))
        return self.protocol.parse_packet(raw)

    def get_state(self) -> OutletState:
        reply = self._tls_request(GET_LIVE_SCENE, make_get_scene_payload())
        return parse_outlets(parse_live_scene(reply.payload))

    def get_controller_state(self) -> ControllerState:
        reply = self._tls_request(ALIVE)
        if reply.packet_type != ALIVE_REPLY:
            raise OaseError(
                f"Unexpected Alive reply type: 0x{reply.packet_type:04X}"
            )
        return parse_alive(reply.payload)

    def set_item(self, item_id: int, value: int) -> None:
        reply = self._tls_request(SET_LIVE_SCENE, make_set_scene_payload(item_id, value))
        if not reply.payload or reply.payload[0] != 1:
            raise OaseError(f"Set command failed: {reply.payload.hex()}")

    def set_outlet(self, outlet: int, on: bool) -> None:
        if outlet not in (1, 2, 3, 4):
            raise ValueError("outlet must be 1-4")
        self.set_item(outlet - 1, 0xFF if on else 0x00)

    def set_dimmer4(self, value: int) -> None:
        if value not in range(256):
            raise ValueError("dimmer value must be 0-255")
        self.set_item(4, value)

    def discover_egc_devices(self, only_new: bool = False) -> EgcDiscoveryResult:
        reply = self._tls_request(
            RDM_DISCOVERY,
            bytes((1 if only_new else 0,)),
        )
        if reply.packet_type != RDM_DISCOVERY_REPLY:
            raise OaseError(
                f"Unexpected EGC discovery reply type: "
                f"0x{reply.packet_type:04X}"
            )
        return parse_egc_discovery(reply.payload)

    def rdm_request(
        self,
        destination_uid: bytes,
        command_class: int,
        parameter_id: int,
        parameter_data: bytes = b"",
        *,
        subdevice: int = 0,
    ) -> RdmMessage:
        transaction = self._rdm_transaction
        self._rdm_transaction = (self._rdm_transaction + 1) & 0xFF
        request = make_rdm_message(
            destination_uid=destination_uid,
            transaction=transaction,
            command_class=command_class,
            parameter_id=parameter_id,
            parameter_data=parameter_data,
            subdevice=subdevice,
        )
        reply = self._tls_request(RDM_REQUEST, request)
        if reply.packet_type != RDM_REPLY:
            raise OaseError(
                f"Unexpected RDM reply type: 0x{reply.packet_type:04X}"
            )
        message = parse_rdm_message(reply.payload)
        if message.transaction != transaction:
            raise OaseError(
                f"RDM transaction mismatch: sent {transaction}, "
                f"received {message.transaction}"
            )
        if message.parameter_id != parameter_id:
            raise OaseError(
                f"RDM PID mismatch: sent 0x{parameter_id:04X}, "
                f"received 0x{message.parameter_id:04X}"
            )
        return message

    def rdm_get(
        self,
        destination_uid: bytes,
        parameter_id: int,
        parameter_data: bytes = b"",
        *,
        subdevice: int = 0,
    ) -> RdmMessage:
        message = self.rdm_request(
            destination_uid,
            RDM_GET,
            parameter_id,
            parameter_data,
            subdevice=subdevice,
        )
        if message.command_class != RDM_GET_RESPONSE:
            raise OaseError(
                f"Unexpected RDM GET response class: "
                f"0x{message.command_class:02X}"
            )
        return message

    def rdm_set(
        self,
        destination_uid: bytes,
        parameter_id: int,
        parameter_data: bytes,
        *,
        subdevice: int = 0,
    ) -> RdmMessage:
        message = self.rdm_request(
            destination_uid,
            RDM_SET,
            parameter_id,
            parameter_data,
            subdevice=subdevice,
        )
        if message.command_class != RDM_SET_RESPONSE:
            raise OaseError(
                f"Unexpected RDM SET response class: "
                f"0x{message.command_class:02X}"
            )
        return message

    def get_single_egc_device(self) -> EgcDevice:
        result = self.discover_egc_devices()
        if not result.devices:
            raise OaseError("No EGC device was discovered")
        if len(result.devices) != 1:
            uids = ", ".join(device.uid_text for device in result.devices)
            raise OaseError(
                f"Expected one EGC device, found {len(result.devices)}: {uids}"
            )
        return result.devices[0]

    def get_rdm_sensor_definition(
        self,
        device: EgcDevice,
        sensor_number: int,
    ) -> RdmSensorDefinition:
        if sensor_number not in range(256):
            raise ValueError("sensor number must be 0-255")
        reply = self.rdm_get(
            device.uid,
            RDM_SENSOR_DEFINITION,
            bytes((sensor_number,)),
        )
        definition = parse_rdm_sensor_definition(reply.parameter_data)
        if definition.sensor_number != sensor_number:
            raise OaseError(
                "RDM sensor definition number mismatch: "
                f"requested {sensor_number}, received {definition.sensor_number}"
            )
        return definition

    def get_rdm_sensor_value(
        self,
        device: EgcDevice,
        definition: RdmSensorDefinition,
    ) -> float:
        reply = self.rdm_get(
            device.uid,
            RDM_SENSOR_VALUE,
            bytes((definition.sensor_number,)),
        )
        value = parse_rdm_sensor_value(reply.parameter_data)
        return scale_rdm_sensor_value(definition, value)

    def _discover_egc_telemetry_sensors(
        self,
        device: EgcDevice,
    ) -> EgcTelemetrySensors:
        cached = self._egc_telemetry_sensors.get(device.uid)
        if cached is not None:
            return cached

        rpm_definition = None
        watts_definition = None
        module_temperature_definition = None
        pcb_temperature_definition = None
        water_temperature_definition = None
        rpm_rank = 0
        watts_rank = 0
        try:
            info = self.rdm_get(device.uid, RDM_DEVICE_INFO)
            if len(info.parameter_data) < 19:
                raise OaseError(
                    "RDM DEVICE_INFO reply did not include the sensor count"
                )
            sensor_count = info.parameter_data[18]
        except OaseError as exc:
            LOG.warning("Unable to discover EGC telemetry sensors: %s", exc)
            result = EgcTelemetrySensors()
            self._egc_telemetry_sensors[device.uid] = result
            return result

        for sensor_number in range(sensor_count):
            try:
                definition = self.get_rdm_sensor_definition(device, sensor_number)
            except OaseError as exc:
                LOG.debug(
                    "Unable to read EGC sensor definition %d: %s",
                    sensor_number,
                    exc,
                )
                continue

            description = definition.description.casefold()
            compact_description = "".join(
                character for character in description if character.isalnum()
            )
            if "watt" in description or "consumption" in description:
                candidate_watts_rank = 3
            elif definition.unit == RDM_SENSOR_UNIT_WATTS:
                candidate_watts_rank = 2
            elif (
                definition.sensor_type == RDM_SENSOR_TYPE_POWER
                and "power" in description
            ):
                candidate_watts_rank = 1
            else:
                candidate_watts_rank = 0
            if candidate_watts_rank > watts_rank:
                watts_definition = definition
                watts_rank = candidate_watts_rank

            if "actualspeed" in compact_description:
                # OASE labels the live pump-speed sensor ActualSpeed and uses
                # the generic velocity type rather than angular velocity.
                candidate_rpm_rank = 4
            elif any(
                word in description
                for word in ("rpm", "rotation", "revolution")
            ):
                candidate_rpm_rank = 3
            elif (
                definition.sensor_type == RDM_SENSOR_TYPE_ANGULAR_VELOCITY
                and "speed" in description
            ):
                candidate_rpm_rank = 2
            elif definition.sensor_type == RDM_SENSOR_TYPE_ANGULAR_VELOCITY:
                candidate_rpm_rank = 1
            else:
                candidate_rpm_rank = 0
            if candidate_rpm_rank > rpm_rank:
                rpm_definition = definition
                rpm_rank = candidate_rpm_rank

            if (
                definition.sensor_type == RDM_SENSOR_TYPE_TEMPERATURE
                and definition.unit == RDM_SENSOR_UNIT_CELSIUS
            ):
                if "water" in compact_description:
                    water_temperature_definition = definition
                elif "pcb" in compact_description:
                    pcb_temperature_definition = definition
                elif "modul" in compact_description:
                    module_temperature_definition = definition

        result = EgcTelemetrySensors(
            rpm=rpm_definition,
            watts=watts_definition,
            module_temperature=module_temperature_definition,
            pcb_temperature=pcb_temperature_definition,
            water_temperature=water_temperature_definition,
        )
        self._egc_telemetry_sensors[device.uid] = result
        if rpm_definition is not None:
            LOG.info(
                "Using EGC RPM sensor %d (%s)",
                rpm_definition.sensor_number,
                rpm_definition.description or "unnamed",
            )
        if watts_definition is not None:
            LOG.info(
                "Using EGC wattage sensor %d (%s)",
                watts_definition.sensor_number,
                watts_definition.description or "unnamed",
            )
        for label, definition in (
            ("module temperature", module_temperature_definition),
            ("PCB temperature", pcb_temperature_definition),
            ("water temperature", water_temperature_definition),
        ):
            if definition is not None:
                LOG.info(
                    "Using EGC %s sensor %d (%s)",
                    label,
                    definition.sensor_number,
                    definition.description or "unnamed",
                )
        return result

    def _get_egc_telemetry(
        self,
        device: EgcDevice,
    ) -> tuple[
        Optional[float],
        Optional[float],
        Optional[float],
        Optional[float],
        Optional[float],
    ]:
        sensors = self._discover_egc_telemetry_sensors(device)

        def read(
            definition: Optional[RdmSensorDefinition],
            label: str,
        ) -> Optional[float]:
            if definition is None:
                return None
            try:
                return self.get_rdm_sensor_value(device, definition)
            except OaseError as exc:
                LOG.warning("Unable to read EGC %s: %s", label, exc)
                return None

        return (
            read(sensors.rpm, "RPM"),
            read(sensors.watts, "watts"),
            read(sensors.module_temperature, "module temperature"),
            read(sensors.pcb_temperature, "PCB temperature"),
            read(sensors.water_temperature, "water temperature"),
        )

    def get_egc_state(self, device: Optional[EgcDevice] = None) -> EgcState:
        """Read control state and available live telemetry for one EGC device."""
        if device is None:
            device = self.get_single_egc_device()

        on_reply = self.rdm_get(device.uid, 0x1010)
        power_reply = self.rdm_get(device.uid, 0x8039)
        if not on_reply.parameter_data:
            raise OaseError("EGC on/off reply contained no parameter data")
        if not power_reply.parameter_data:
            raise OaseError("EGC power reply contained no parameter data")

        raw_power = power_reply.parameter_data[0]
        power = 0 if raw_power == 0 else (raw_power * 100 + 254) // 255
        (
            rpm,
            watts,
            module_temperature,
            pcb_temperature,
            water_temperature,
        ) = self._get_egc_telemetry(device)
        return EgcState(
            device=device,
            on=bool(on_reply.parameter_data[0]),
            power=power,
            rpm=rpm,
            watts=watts,
            module_temperature=module_temperature,
            pcb_temperature=pcb_temperature,
            water_temperature=water_temperature,
        )

    def close(self) -> None:
        if self._tls is not None:
            self._tls.close()
            self._tls = None
        if self._udp is not None:
            self._udp.close()
            self._udp = None

    def __enter__(self) -> "OaseController":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()




def parse_set_operations(parts: list[str]) -> list[tuple[str, int, int]]:
    """Parse comma-separated FM-Master and EGC operations."""
    expression = " ".join(parts).strip()
    if not expression:
        raise ValueError("set requires at least one operation")

    clauses = [clause.strip() for clause in expression.split(",")]
    if any(not clause for clause in clauses):
        raise ValueError("empty operation in set expression")

    operations: list[tuple[str, int, int]] = []
    current_target: Optional[str] = None

    for clause in clauses:
        words = clause.lower().split()

        if words and words[0] == "egc":
            current_target = "egc"

            if len(words) == 2 and words[1] in ("on", "off"):
                operations.append(
                    ("egc_onoff", 0, 0xFF if words[1] == "on" else 0x00)
                )
                continue

            if len(words) == 3 and words[1] == "power":
                try:
                    percent = int(words[2], 10)
                except ValueError as exc:
                    raise ValueError("EGC power must be an integer from 1 to 100") from exc
                if percent not in range(1, 101):
                    raise ValueError("EGC power must be 1-100")
                operations.append(("egc_power", 0, percent))
                continue

            raise ValueError(
                "expected 'egc on', 'egc off', or 'egc power <1-100>'"
            )

        if words and words[0] == "power":
            if current_target != "egc":
                raise ValueError(
                    "'power' must follow 'egc', for example "
                    "'set egc on, power 50'"
                )
            if len(words) != 2:
                raise ValueError("power requires one value from 1 to 100")
            try:
                percent = int(words[1], 10)
            except ValueError as exc:
                raise ValueError("EGC power must be an integer from 1 to 100") from exc
            if percent not in range(1, 101):
                raise ValueError("EGC power must be 1-100")
            operations.append(("egc_power", 0, percent))
            continue

        current_target = None

        if len(words) != 2:
            raise ValueError(f"invalid set operation: {clause!r}")

        target, setting = words

        if target == "dimmer":
            try:
                value = int(setting, 10)
            except ValueError as exc:
                raise ValueError("dimmer value must be an integer from 0 to 255") from exc
            if value not in range(256):
                raise ValueError("dimmer value must be 0-255")
            operations.append(("dimmer", 4, value))
            continue

        try:
            outlet = int(target, 10)
        except ValueError as exc:
            raise ValueError(f"unknown set target: {target!r}") from exc

        if outlet not in (1, 2, 3, 4):
            raise ValueError("outlet must be 1-4")
        if setting not in ("on", "off"):
            raise ValueError(f"outlet {outlet} state must be 'on' or 'off'")

        operations.append(
            ("outlet", outlet, 0xFF if setting == "on" else 0x00)
        )

    return operations


def _format_state(state: OutletState) -> str:
    return (
        f"outlet1={'on' if state.outlet1 else 'off'}\n"
        f"outlet2={'on' if state.outlet2 else 'off'}\n"
        f"outlet3={'on' if state.outlet3 else 'off'}\n"
        f"outlet4={'on' if state.outlet4 else 'off'}\n"
        f"dimmer4={state.dimmer4}"
    )


def _format_controller_state(state: ControllerState) -> str:
    rssi = "unavailable" if state.rssi is None else str(state.rssi)
    return f"controller_rssi={rssi}"


def _format_egc_state(state: EgcState) -> str:
    rpm = "unavailable" if state.rpm is None else f"{state.rpm:g}"
    watts = "unavailable" if state.watts is None else f"{state.watts:g}"
    module_temperature = (
        "unavailable"
        if state.module_temperature is None
        else f"{state.module_temperature:g}"
    )
    pcb_temperature = (
        "unavailable"
        if state.pcb_temperature is None
        else f"{state.pcb_temperature:g}"
    )
    water_temperature = (
        "unavailable"
        if state.water_temperature is None
        else f"{state.water_temperature:g}"
    )
    return (
        f"egc={'on' if state.on else 'off'}\n"
        f"power={state.power}\n"
        f"rpm={rpm}\n"
        f"watts={watts}\n"
        f"module_temperature={module_temperature}\n"
        f"pcb_temperature={pcb_temperature}\n"
        f"water_temperature={water_temperature}\n"
        f"uid={state.device.uid_text}"
    )


def _format_egc_discovery(result: EgcDiscoveryResult) -> str:
    lines = [
        f"discover_only_new_devices={result.discover_only_new_devices}",
        f"device_count={len(result.devices)}",
    ]
    for index, device in enumerate(result.devices, start=1):
        lines.extend(
            (
                f"device[{index}].uid={device.uid_text}",
                f"device[{index}].article_number={device.article_number}",
                f"device[{index}].device_identifier={device.device_identifier}",
                (
                    f"device[{index}].manufacturer_identifier="
                    f"0x{device.manufacturer_identifier:04X}"
                ),
                f"device[{index}].subdevice_count={device.subdevice_count}",
            )
        )
    return "\n".join(lines)


def _format_rdm_message(message: RdmMessage) -> str:
    return (
        f"source_uid={message.source_uid.hex().upper()[:4]}:"
        f"{message.source_uid.hex().upper()[4:]}\n"
        f"destination_uid={message.destination_uid.hex().upper()[:4]}:"
        f"{message.destination_uid.hex().upper()[4:]}\n"
        f"transaction={message.transaction}\n"
        f"response_type=0x{message.port_or_response_type:02X}\n"
        f"message_count={message.message_count}\n"
        f"subdevice={message.subdevice}\n"
        f"command_class=0x{message.command_class:02X}\n"
        f"parameter_id=0x{message.parameter_id:04X}\n"
        f"parameter_data_length={len(message.parameter_data)}\n"
        f"parameter_data={message.parameter_data.hex().upper()}"
    )


def _int_auto(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid integer value: {value!r}"
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Control an OASE FM-Master EGC over the local network"
    )
    p.add_argument(
        "--device-ip",
        required=True,
        help="IPv4 address of the OASE controller",
    )
    p.add_argument(
        "--local-ip",
        required=True,
        help="IPv4 address of this computer, reachable by the controller",
    )
    p.add_argument(
        "--password",
        default=os.getenv("OASE_PASSWORD"),
        help="74-character app password; or set OASE_PASSWORD",
    )
    p.add_argument("--tls-port", type=int, default=TLS_PORT)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--debug", action="store_true")

    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Read outlet and EGC states")

    setp = sub.add_parser(
        "set",
        help="Set one or more outlets and/or the outlet-4 dimmer",
    )
    setp.add_argument(
        "operations",
        nargs="+",
        metavar="OPERATION",
        help="comma-separated operations, e.g. '4 on, 3 off, dimmer 128'",
    )

    egc = sub.add_parser("egc", help="EGC/RDM device operations")
    egc_sub = egc.add_subparsers(dest="egc_command", required=True)
    egc_discover = egc_sub.add_parser(
        "discover",
        help="Discover EGC/RDM devices attached to the FM-Master",
    )
    egc_discover.add_argument(
        "--only-new",
        action="store_true",
        help="request only newly attached devices",
    )

    rdm = sub.add_parser("rdm", help="Send raw RDM GET or SET requests")
    rdm_sub = rdm.add_subparsers(dest="rdm_command", required=True)

    for name in ("get", "set"):
        rp = rdm_sub.add_parser(name, help=f"Send an RDM {name.upper()} request")
        rp.add_argument(
            "uid",
            help="destination UID as MMMM:DDDDDDDD or 12 hex digits",
        )
        rp.add_argument(
            "pid",
            type=_int_auto,
            help="parameter ID in decimal or 0x-prefixed hexadecimal",
        )
        rp.add_argument(
            "data",
            nargs="?",
            default="",
            help="optional parameter data as hexadecimal bytes",
        )
        rp.add_argument(
            "--subdevice",
            type=_int_auto,
            default=0,
            help="RDM subdevice number; default 0",
        )

    return p


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    if not args.password:
        raise SystemExit("A password is required via --password or OASE_PASSWORD")

    operations: list[tuple[str, int, int]] = []
    rdm_uid = b""
    rdm_data = b""

    if args.command == "set":
        try:
            operations = parse_set_operations(args.operations)
        except ValueError as exc:
            raise SystemExit(f"Invalid set command: {exc}") from exc
    elif args.command == "rdm":
        try:
            rdm_uid = parse_uid(args.uid)
            rdm_data = parse_hex_bytes(args.data)
        except ValueError as exc:
            raise SystemExit(f"Invalid RDM command: {exc}") from exc
        if args.pid not in range(0x10000):
            raise SystemExit("Invalid RDM command: PID must be 0-65535")
        if args.subdevice not in range(0x10000):
            raise SystemExit(
                "Invalid RDM command: subdevice must be 0-65535"
            )
        if args.rdm_command == "set" and not rdm_data:
            raise SystemExit(
                "Invalid RDM SET command: parameter data is required"
            )

    ctl = OaseController(
        device_ip=args.device_ip,
        local_ip=args.local_ip,
        password=args.password,
        tls_port=args.tls_port,
        timeout=args.timeout,
    )
    try:
        ctl.connect()

        if args.command == "status":
            print(
                f"{_format_state(ctl.get_state())}\n"
                f"{_format_controller_state(ctl.get_controller_state())}\n"
                f"{_format_egc_state(ctl.get_egc_state())}"
            )

        elif args.command == "set":
            egc_device = None

            for kind, target, value in operations:
                if kind == "outlet":
                    ctl.set_outlet(target, value == 0xFF)

                elif kind == "dimmer":
                    ctl.set_dimmer4(value)

                elif kind == "egc_onoff":
                    if egc_device is None:
                        egc_device = ctl.get_single_egc_device()
                    ctl.rdm_set(
                        egc_device.uid,
                        0x1010,
                        bytes((value,)),
                    )

                elif kind == "egc_power":
                    if egc_device is None:
                        egc_device = ctl.get_single_egc_device()
                    raw = value * 255 // 100
                    ctl.rdm_set(
                        egc_device.uid,
                        0x8039,
                        bytes((raw,)),
                    )

            if egc_device is not None:
                print(_format_egc_state(ctl.get_egc_state(egc_device)))
            else:
                print(_format_state(ctl.get_state()))

        elif args.command == "egc":
            if args.egc_command == "discover":
                result = ctl.discover_egc_devices(args.only_new)
                print(_format_egc_discovery(result))

        elif args.command == "rdm":
            if args.rdm_command == "get":
                message = ctl.rdm_get(
                    rdm_uid,
                    args.pid,
                    rdm_data,
                    subdevice=args.subdevice,
                )
            else:
                message = ctl.rdm_set(
                    rdm_uid,
                    args.pid,
                    rdm_data,
                    subdevice=args.subdevice,
                )
            print(_format_rdm_message(message))

        return 0

    except (OaseError, OSError, ssl.SSLError) as exc:
        LOG.error("%s", exc)
        return 1
    finally:
        ctl.close()


if __name__ == "__main__":
    raise SystemExit(main())
