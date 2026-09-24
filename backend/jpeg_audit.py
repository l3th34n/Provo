"""Bounded JPEG marker mapping for exclusion coverage checks.

This maps structural regions; it is not a JPEG decoder or a JUMBF validator.
"""

MAX_SEGMENTS = 100_000


def jpeg_regions(data: bytes) -> list[tuple[int, int, str]]:
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("JPEG SOI marker is missing")
    regions = [(0, 2, "rendering")]
    pos = 2
    in_scan = False
    while pos < len(data):
        if len(regions) >= MAX_SEGMENTS:
            raise ValueError("JPEG segment budget exceeded")
        if in_scan:
            scan_start = pos
            while pos < len(data):
                marker_start = data.find(b"\xff", pos)
                if marker_start < 0:
                    raise ValueError("JPEG scan has no terminating marker")
                end = marker_start + 1
                while end < len(data) and data[end] == 0xFF:
                    end += 1
                if end == len(data):
                    raise ValueError("Truncated JPEG scan marker")
                if data[end] == 0 or 0xD0 <= data[end] <= 0xD7:
                    pos = end + 1
                    continue
                if marker_start > scan_start:
                    regions.append((scan_start, marker_start, "rendering"))
                pos = marker_start
                in_scan = False
                break
            if in_scan:
                raise ValueError("JPEG scan has no terminating marker")
        start = pos
        if data[pos] != 0xFF:
            raise ValueError("Unexpected byte outside a JPEG scan")
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos == len(data):
            raise ValueError("Truncated JPEG marker")
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            regions.append((start, pos, "rendering"))
            if pos < len(data):
                regions.append((pos, len(data), "trailing"))
            return regions
        if marker in (0, 0xD8) or 0xD0 <= marker <= 0xD7:
            raise ValueError("Unexpected standalone JPEG marker")
        if marker == 0x01:
            regions.append((start, pos, "rendering"))
            continue
        if pos + 2 > len(data):
            raise ValueError("Truncated JPEG segment length")
        length = int.from_bytes(data[pos:pos + 2], "big")
        end = pos + length
        if length < 2 or end > len(data):
            raise ValueError("Invalid JPEG segment length")
        payload = data[pos + 2:end]
        kind = "rendering"
        if 0xE0 <= marker <= 0xEF or marker == 0xFE:
            kind = "metadata"
        if marker == 0xEB and len(payload) >= 8 and payload[:2] == b"JP":
            kind = "app11_envelope"
        regions.append((start, end, kind))
        pos = end
        if marker == 0xDA:
            in_scan = True
        elif marker == 0xDC:
            # DNL inside a scan needs decoder-level interpretation; fail closed.
            raise ValueError("JPEG DNL scan continuation is not supported by this audit")
    raise ValueError("JPEG EOI marker is missing")


def exclusion_coverage(data: bytes, ranges: list[tuple[int, int]]) -> list[dict]:
    """Map validated [start, end) ranges to JPEG regions in linear order."""
    regions = jpeg_regions(data)
    findings = []
    region_index = 0
    for start, end in ranges:
        while region_index < len(regions) and regions[region_index][1] <= start:
            region_index += 1
        cursor = region_index
        kinds = set()
        partial_envelope = False
        while cursor < len(regions) and regions[cursor][0] < end:
            region_start, region_end, kind = regions[cursor]
            kinds.add(kind)
            if kind == "app11_envelope" and (start > region_start or end < region_end):
                partial_envelope = True
            cursor += 1
        if "rendering" in kinds:
            findings.append({
                "code": "provo.exclusion.renderingBytes", "level": "invalid",
                "category": "byte_coverage", "start": start, "length": end - start,
                "message": "An exclusion overlaps JPEG scan data or rendering markers; PROVO rejects this unsigned rendering region.",
            })
        elif kinds - {"app11_envelope"} or partial_envelope:
            findings.append({
                "code": "provo.exclusion.additionalBytes", "level": "review",
                "category": "byte_coverage", "start": start, "length": end - start,
                "message": "An exclusion covers metadata, trailing bytes, or a partial APP11 envelope; review its effect on rendering.",
            })
    return findings
