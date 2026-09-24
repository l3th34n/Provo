"""Small, dependency-free checks for supported upload container signatures."""

from __future__ import annotations

from pathlib import Path


EXTENSION_FORMATS = {
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".png": "png",
    ".webp": "webp",
    ".mp4": "iso_bmff",
    ".mov": "iso_bmff",
}


def detect_media_format(header: bytes) -> str | None:
    """Identify the supported container family from its leading bytes."""
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"

    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"

    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"

    # MP4 and QuickTime/MOV are both ISO Base Media File Format containers.
    if len(header) >= 12 and header[4:8] == b"ftyp":
        return "iso_bmff"

    return None


def validate_media_header(filename: str, header: bytes) -> str:
    """Return the detected format or raise ValueError for invalid uploads."""
    extension = Path(filename).suffix.lower()
    expected = EXTENSION_FORMATS.get(extension)
    detected = detect_media_format(header)

    if expected is None:
        raise ValueError("Unsupported file extension")

    if detected is None:
        raise ValueError("The file does not have a supported media signature")

    if detected != expected:
        raise ValueError("The file content does not match its extension")

    return detected
