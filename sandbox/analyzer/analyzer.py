import hashlib
import json
import math
import string
from pathlib import Path
import base64
import binascii
import re
from extractors import extract_static_indicators

INPUT_DIR = Path("/sandbox/input")
OUTPUT_DIR = Path("/sandbox/output")
REPORT_PATH = OUTPUT_DIR / "report.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    frequencies = [0] * 256

    for byte in data:
        frequencies[byte] += 1

    entropy = 0.0
    length = len(data)

    for count in frequencies:
        if count == 0:
            continue

        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def extract_strings(
    data: bytes,
    minimum_length: int = 4,
) -> list[str]:
    printable = set(bytes(string.printable, "ascii"))

    results = []
    current = bytearray()

    for byte in data:
        if byte in printable and byte not in (9, 10, 13):
            current.append(byte)
        else:
            if len(current) >= minimum_length:
                results.append(
                    current.decode(
                        "ascii",
                        errors="ignore",
                    )
                )

            current = bytearray()

    if len(current) >= minimum_length:
        results.append(
            current.decode(
                "ascii",
                errors="ignore",
            )
        )

    return results[:500]

FILE_SIGNATURES = {
    b"MZ": "PE/Windows executable",
    b"\x7fELF": "ELF executable",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP/archive",
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF8": "GIF image",
}


COMMAND_PATTERNS = {
    "powershell": re.compile(r"\bpowershell(?:\.exe)?\b", re.IGNORECASE),
    "cmd": re.compile(r"\bcmd(?:\.exe)?\b", re.IGNORECASE),
    "bash": re.compile(r"\bbash\b", re.IGNORECASE),
    "sh": re.compile(r"(?:^|\s)/bin/sh\b", re.IGNORECASE),
}


URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)


BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])"
)


HEX_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{2}){8,}(?![A-Fa-f0-9])"
)


def detect_file_signature(data: bytes) -> list[str]:
    findings = []

    for signature, description in FILE_SIGNATURES.items():
        if data.startswith(signature):
            findings.append(description)

    return findings


def detect_urls(text: str) -> list[str]:
    return URL_PATTERN.findall(text)[:50]


def detect_commands(text: str) -> list[str]:
    findings = []

    for name, pattern in COMMAND_PATTERNS.items():
        if pattern.search(text):
            findings.append(name)

    return findings


def detect_base64(text: str) -> list[str]:
    candidates = BASE64_PATTERN.findall(text)

    valid = []

    for candidate in candidates[:50]:
        try:
            base64.b64decode(candidate, validate=True)
            valid.append(candidate)
        except (ValueError, binascii.Error):
            continue

    return valid


def detect_hex(text: str) -> list[str]:
    return HEX_PATTERN.findall(text)[:50]


def analyze_file(path: Path) -> dict:
    data = path.read_bytes()

    return {
        "file_name": path.name,
        "file_size": len(data),
        "sha256": sha256_file(path),
        "entropy": calculate_entropy(data),
        "strings": extract_strings(data),
        "static_indicators": extract_static_indicators(data),
        "analysis_mode": "static",
        "executed": False,
        "network_access": False,
        "status": "completed",
    }


def main() -> None:
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    files = [
        path
        for path in INPUT_DIR.iterdir()
        if path.is_file() and path.name != ".gitkeep"
    ]

    if not files:
        report = {
            "status": "no_input",
            "message": "No files were provided for analysis.",
            "executed": False,
        }

    else:
        report = {
            "status": "completed",
            "analysis_mode": "static",
            "executed": False,
            "network_access": False,
            "files": [
                analyze_file(path)
                for path in files
            ],
        }

    REPORT_PATH.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            report,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()