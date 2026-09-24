import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from media_validation import detect_media_format, validate_media_header


class MediaValidationTests(unittest.TestCase):
    def test_detects_supported_image_signatures(self):
        self.assertEqual(detect_media_format(b"\xff\xd8\xff\xe0"), "jpeg")
        self.assertEqual(detect_media_format(b"\x89PNG\r\n\x1a\n"), "png")
        self.assertEqual(detect_media_format(b"RIFF\x10\x00\x00\x00WEBP"), "webp")

    def test_detects_iso_bmff_video_container(self):
        self.assertEqual(detect_media_format(b"\x00\x00\x00\x18ftypisom"), "iso_bmff")

    def test_accepts_matching_extension_and_content(self):
        self.assertEqual(validate_media_header("photo.jpeg", b"\xff\xd8\xff\xe0"), "jpeg")
        self.assertEqual(validate_media_header("clip.mov", b"\x00\x00\x00\x18ftypqt  "), "iso_bmff")

    def test_rejects_disguised_file(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_media_header("payload.jpg", b"\x89PNG\r\n\x1a\n")

    def test_rejects_unknown_signature(self):
        with self.assertRaisesRegex(ValueError, "supported media signature"):
            validate_media_header("payload.jpg", b"not an image")


if __name__ == "__main__":
    unittest.main()
