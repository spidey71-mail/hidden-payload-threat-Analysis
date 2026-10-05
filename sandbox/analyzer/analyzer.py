import hashlib
import json
import math
import string
from pathlib import Path


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


def analyze_file(path: Path) -> dict:
    data = path.read_bytes()

    return {
        "file_name": path.name,
        "file_size": len(data),
        "sha256": sha256_file(path),
        "entropy": calculate_entropy(data),
        "strings": extract_strings(data),
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