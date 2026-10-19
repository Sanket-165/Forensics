from hashlib import sha256
from io import BytesIO
import json
import struct
import zlib

import numpy as np
from PIL import Image
import pytest

from image_forensics import (
    ELAUnsupportedError, ImageValidationError, MAX_FILE_BYTES, ReferenceHashError,
    analyze_image, calculate_sha256, compare_reference_hash, extract_metadata,
    image_statistics, perform_ela, safe_text, validate_image,
)
from report_generator import generate_json_report, generate_pdf_report


def make_image(fmt="PNG", mode="RGB", size=(32, 24), color=None, **save_options):
    buffer = BytesIO()
    with Image.new(mode, size, color if color is not None else 100) as image:
        image.save(buffer, format=fmt, **save_options)
    return buffer.getvalue()


def test_sha256_known_bytes():
    assert calculate_sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert calculate_sha256(b"\x00original\xff") == sha256(b"\x00original\xff").hexdigest()


@pytest.mark.parametrize("fmt", ["JPEG", "PNG"])
def test_metadata_dimensions_format_and_size(fmt):
    data = make_image(fmt=fmt, size=(37, 19))
    metadata = extract_metadata(data, "sample." + fmt.lower())
    assert (metadata["width"], metadata["height"]) == (37, 19)
    assert metadata["format"] == fmt
    assert metadata["pixel_count"] == 37 * 19
    assert metadata["size_bytes"] == len(data)
    assert metadata["channels"] == 3
    assert metadata["summary"]["Camera model"] == "Not available."
    json.dumps(metadata, allow_nan=False)


def test_exif_nested_directory_and_binary_values():
    exif = Image.Exif()
    exif[271] = "Test Camera"
    exif[272] = "Model A"
    exif[305] = "Test Editor"
    exif[274] = 6
    exif[0x8769] = {36867: "2025:01:02 03:04:05", 37500: b"private-binary"}
    metadata = extract_metadata(make_image("JPEG", exif=exif), "camera.jpg")
    assert metadata["summary"]["Camera manufacturer"] == "Test Camera"
    assert metadata["summary"]["Original date/time"] == "2025:01:02 03:04:05"
    assert "Rotate 90 CW" in metadata["summary"]["Orientation"]
    assert "Binary value omitted" in metadata["exif"]["MakerNote"]
    assert "private-binary" not in json.dumps(metadata)


def test_malformed_exif_does_not_prevent_pixel_analysis():
    data = make_image("JPEG", exif=b"Exif\x00\x00broken directory")
    report = analyze_image(data, "bad-exif.jpg").report
    assert report["ela"]["available"]
    assert report["metadata"]["notices"]


def test_filename_is_a_label_and_content_wins():
    metadata = extract_metadata(make_image(), "C:\\private\\folder\\wrong.jpg")
    assert metadata["filename"] == "wrong.jpg"
    assert metadata["format"] == "PNG"
    assert "extension differs" in metadata["notices"][0]


def test_text_sanitization_bounds_values():
    assert len(safe_text("a" * 5000)) < 1100
    assert safe_text(b"secret") == "[Binary value omitted: 6 bytes]"
    assert "\x00" not in safe_text("before\x00after")


def test_ela_rgb_jpeg_is_deterministic():
    rng = np.random.default_rng(42)
    buffer = BytesIO()
    Image.fromarray(rng.integers(0, 256, (48, 64, 3), dtype=np.uint8)).save(buffer, format="JPEG", quality=75)
    first, second = perform_ela(buffer.getvalue()), perform_ela(buffer.getvalue())
    assert first.image.mode == "RGB"
    assert first.image.size == (64, 48)
    assert first.image.tobytes() == second.image.tobytes()
    assert first.findings == second.findings
    assert 0 <= first.findings["mean_absolute_difference"] <= first.findings["maximum_channel_difference"] <= 255
    assert first.findings["quality"] == 90
    first.image.close()
    second.image.close()


def test_ela_uniform_black_image_has_no_division_by_zero():
    ela = perform_ela(make_image("JPEG", color=(0, 0, 0)))
    assert ela.findings["maximum_channel_difference"] == 0
    assert ela.findings["brightness_gain"] == 1
    assert ela.image.getbbox() is None
    ela.image.close()


def test_ela_grayscale_jpeg():
    ela = perform_ela(make_image("JPEG", mode="L"))
    assert ela.image.mode == "RGB"
    ela.image.close()


def test_ela_rejects_png():
    with pytest.raises(ELAUnsupportedError, match="not applicable to PNG"):
        perform_ela(make_image())


@pytest.mark.parametrize("data", [b"", b"not an image", b"\xff\xd8\xffgarbage", b"\x89PNG\r\n\x1a\n"])
def test_invalid_bytes_rejected(data):
    with pytest.raises(ImageValidationError):
        validate_image(data)


@pytest.mark.parametrize("fmt", ["GIF", "BMP", "TIFF"])
def test_other_actual_formats_rejected(fmt):
    with pytest.raises(ImageValidationError):
        validate_image(make_image(fmt))


def test_oversized_file_rejected_before_decode(monkeypatch):
    def forbidden_open(*args, **kwargs):
        raise AssertionError("Oversized files must not reach the decoder")
    monkeypatch.setattr(Image, "open", forbidden_open)
    with pytest.raises(ImageValidationError, match="15 MB"):
        validate_image(b"x" * (MAX_FILE_BYTES + 1))


def test_pixel_limit_checked_before_loading():
    data = bytearray(make_image())
    # Change the PNG IHDR dimensions and CRC without allocating 30 million pixels.
    data[16:24] = struct.pack(">II", 6000, 5001)
    data[29:33] = struct.pack(">I", zlib.crc32(data[12:29]))
    with pytest.raises(ImageValidationError, match="30 million"):
        validate_image(bytes(data))


@pytest.mark.parametrize("threshold", [60, 40])
def test_pillow_bomb_warning_and_error_are_rejected(monkeypatch, threshold):
    data = make_image(size=(10, 10))
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", threshold)
    with pytest.raises(ImageValidationError, match="decompression-bomb"):
        validate_image(data)


def test_corrupt_png_crc_rejected():
    data = bytearray(make_image())
    data[29] ^= 0xFF
    with pytest.raises(ImageValidationError):
        validate_image(bytes(data))


def test_truncated_jpeg_rejected():
    with pytest.raises(ImageValidationError):
        validate_image(make_image("JPEG")[:-30])


def test_animated_png_rejected():
    buffer = BytesIO()
    with Image.new("RGB", (12, 12), "red") as first, Image.new("RGB", (12, 12), "blue") as second:
        first.save(buffer, format="PNG", save_all=True, append_images=[second], duration=100)
    with pytest.raises(ImageValidationError, match="multi-frame"):
        validate_image(buffer.getvalue())


@pytest.mark.parametrize("reference", ["abc", "a" * 63, "a" * 65, "g" * 64, "a" * 32 + " " + "a" * 31])
def test_invalid_reference_hashes(reference):
    with pytest.raises(ReferenceHashError):
        compare_reference_hash(calculate_sha256(b"abc"), reference)


def test_hash_match_mismatch_and_missing():
    digest = calculate_sha256(b"abc")
    assert compare_reference_hash(digest, "  " + digest.upper() + "\n")["status"] == "MATCH"
    assert compare_reference_hash(digest, "0" * 64)["status"] == "MISMATCH"
    assert compare_reference_hash(digest, " \n")["status"] == "REFERENCE HASH NOT PROVIDED"
    assert compare_reference_hash(digest)["reference_sha256"] is None


@pytest.mark.parametrize("mode", ["1", "L", "LA", "RGB", "RGBA", "P", "I;16"])
def test_statistics_modes_have_exact_histogram_totals(mode):
    with validate_image(make_image(mode=mode)) as image:
        stats = image_statistics(image)
    assert all(sum(hist) == 32 * 24 for hist in stats["histograms"].values())
    assert all(len(hist) == 256 for hist in stats["histograms"].values())
    json.dumps(stats, allow_nan=False)


def test_rgba_statistics_use_underlying_colors_and_grayscale_weights():
    with Image.new("RGBA", (10, 10), (255, 0, 0, 0)) as image:
        stats = image_statistics(image)
    assert stats["channels"]["Red"]["mean"] == 255
    assert stats["channels"]["Grayscale"]["mean"] == 76
    assert stats["channels"]["Green"]["standard_deviation"] == 0


@pytest.mark.parametrize("fmt", ["JPEG", "PNG"])
def test_end_to_end_json_and_pdf(fmt):
    data = make_image(fmt)
    digest = calculate_sha256(data)
    result = analyze_image(data, "<img src='unsafe'>अभ्यास." + fmt.lower(), digest)
    report = result.report
    restored = json.loads(generate_json_report(report))
    assert restored == report
    assert restored["sha256"] == sha256(data).hexdigest()
    assert restored["integrity"]["status"] == "MATCH"
    assert restored["analysis_timestamp"].endswith("+00:00")
    assert restored["ela"]["available"] == (fmt == "JPEG")
    assert bool(result.ela_preview) == (fmt == "JPEG")
    assert not result.preview.info
    pdf = generate_pdf_report(report)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 2500


def test_pdf_handles_many_long_untrusted_exif_values():
    report = analyze_image(make_image(), "image.png").report
    report["metadata"]["exif"] = {f"Tag {i}": "<&>" + "a" * 997 for i in range(128)}
    assert generate_pdf_report(report).startswith(b"%PDF-")
