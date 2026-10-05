import base64
import binascii
import re


URL_PATTERN = re.compile(
    rb"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

BASE64_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9+/])"
    rb"[A-Za-z0-9+/]{16,}={0,2}"
    rb"(?![A-Za-z0-9+/])"
)

HEX_PATTERN = re.compile(
    rb"(?<![0-9a-fA-F])"
    rb"(?:[0-9a-fA-F]{2}){8,}"
    rb"(?![0-9a-fA-F])"
)


COMMAND_INDICATORS = [
    b"powershell",
    b"cmd.exe",
    b"cmd /c",
    b"bash",
    b"/bin/sh",
    b"/bin/bash",
    b"wscript",
    b"cscript",
    b"mshta",
    b"rundll32",
    b"regsvr32",
]


FILE_SIGNATURES = {
    b"MZ": "PE/Windows executable",
    b"\x7fELF": "ELF/Linux executable",
    b"PK\x03\x04": "ZIP/Office/JAR archive",
    b"%PDF": "PDF document",
}


def detect_file_signatures(data: bytes) -> list[str]:
    """Identify known file formats using magic bytes."""

    signatures = []

    for magic, description in FILE_SIGNATURES.items():
        if data.startswith(magic):
            signatures.append(description)

    return signatures


def detect_urls(data: bytes) -> list[str]:
    """Extract HTTP/HTTPS URLs from raw file content."""

    matches = URL_PATTERN.findall(data)

    return [
        match.decode("utf-8", errors="ignore")
        for match in matches
    ][:100]


def detect_command_indicators(data: bytes) -> list[str]:
    """Detect common command/interpreter indicators."""

    lowered = data.lower()
    indicators = []

    for command in COMMAND_INDICATORS:
        if command in lowered:
            indicators.append(
                command.decode("ascii")
            )

    return indicators


def is_valid_base64(candidate: bytes) -> bool:
    """Check whether a candidate is structurally valid Base64."""

    try:
        base64.b64decode(
            candidate,
            validate=True,
        )
        return True
    except (ValueError, binascii.Error):
        return False


def detect_base64_candidates(data: bytes) -> list[str]:
    """Detect Base64-like encoded content without decoding it."""

    candidates = []

    for match in BASE64_PATTERN.findall(data):
        if is_valid_base64(match):
            candidates.append(
                match.decode("ascii")
            )

    return list(dict.fromkeys(candidates))[:100]


def detect_hex_candidates(data: bytes) -> list[str]:
    """Detect long hexadecimal sequences."""

    matches = HEX_PATTERN.findall(data)

    return list(
        dict.fromkeys(
            match.decode("ascii")
            for match in matches
        )
    )[:100]


def extract_static_indicators(data: bytes) -> dict:
    """Run all static indicator extractors."""

    return {
        "file_signatures": detect_file_signatures(data),
        "urls": detect_urls(data),
        "command_indicators": detect_command_indicators(data),
        "base64_candidates": detect_base64_candidates(data),
        "hex_candidates": detect_hex_candidates(data),
    }