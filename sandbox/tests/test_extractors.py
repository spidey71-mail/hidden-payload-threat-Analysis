from sandbox.analyzer.extractors import (
    detect_file_signatures,
    detect_urls,
    detect_command_indicators,
    detect_base64_candidates,
    detect_hex_candidates,
)


def test_detect_pe_signature():
    data = b"MZ\x90\x00"
    result = detect_file_signatures(data)

    assert "PE/Windows executable" in result


def test_detect_elf_signature():
    data = b"\x7fELF\x02\x01"
    result = detect_file_signatures(data)

    assert "ELF/Linux executable" in result


def test_detect_url():
    data = b"Visit https://example.com/test for more information."

    result = detect_urls(data)

    assert result == ["https://example.com/test"]


def test_detect_powershell():
    data = b"powershell -Command Write-Output Hello"

    result = detect_command_indicators(data)

    assert "powershell" in result


def test_detect_cmd():
    data = b"cmd.exe /c whoami"

    result = detect_command_indicators(data)

    assert "cmd.exe" in result


def test_detect_base64():
    data = b"SGVsbG8gZnJvbSB0aGUgc2FuZGJveA=="

    result = detect_base64_candidates(data)

    assert "SGVsbG8gZnJvbSB0aGUgc2FuZGJveA==" in result


def test_detect_hex():
    data = b"00112233445566778899aabbccddeeff"

    result = detect_hex_candidates(data)

    assert "00112233445566778899aabbccddeeff" in result


def test_benign_text_has_no_indicators():
    data = b"This is a completely harmless text file."

    assert detect_file_signatures(data) == []
    assert detect_urls(data) == []
    assert detect_command_indicators(data) == []
    assert detect_base64_candidates(data) == []
    assert detect_hex_candidates(data) == []