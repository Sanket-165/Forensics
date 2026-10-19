"""Local, deterministic image checks. Measurements are not authenticity verdicts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import re
import warnings

import numpy as np
from PIL import ExifTags, Image, ImageChops, ImageEnhance, ImageStat, UnidentifiedImageError

MAX_FILE_BYTES = 15 * 1024 * 1024
MAX_PIXELS = 30_000_000
ELA_QUALITY = 90
NOT_AVAILABLE = "Not available."
LIMITATIONS = [
    "This educational tool is not a certified forensic suite and does not determine authenticity.",
    "Metadata can be edited or removed. Missing metadata is not evidence of manipulation.",
    "A SHA-256 match establishes consistency only with a trustworthy reference. A mismatch means different file content, not necessarily malicious editing.",
    "ELA is an investigative aid for JPEG only. Content, compression history and editing workflows can explain uneven differences.",
    "ELA brightness enhancement is a visualization adjustment, not a calibrated forensic score or probability.",
    "Histograms and descriptive statistics are measurements, not evidence of authenticity or tampering.",
    "Previews and statistics use decoded pixels without ICC color management or automatic EXIF rotation. Transparency is ignored for statistics; underlying RGB values are measured.",
    "This tool does not scan for malware, establish chain of custody, detect all edits, or guarantee secure deletion from operating-system memory.",
]


class ImageValidationError(ValueError):
    """An upload is unsupported, malformed or exceeds a safety limit."""


class ReferenceHashError(ValueError):
    """A reference digest is not exactly 64 hexadecimal characters."""


class ELAUnsupportedError(ValueError):
    """JPEG recompression ELA cannot be applied to this format."""


@dataclass
class ELAResult:
    image: Image.Image
    findings: dict


@dataclass
class AnalysisResult:
    report: dict
    preview: Image.Image
    ela_preview: Image.Image | None


def calculate_sha256(data: bytes) -> str:
    """Hash exact input bytes, never a decoded or re-saved image."""
    return sha256(data).hexdigest()


def compare_reference_hash(digest: str, reference: str | None = None) -> dict:
    normalized = (reference or "").strip().lower()
    if not normalized:
        return {"status": "REFERENCE HASH NOT PROVIDED", "reference_sha256": None,
                "explanation": "The file hash was calculated; no reference comparison is possible."}
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ReferenceHashError("Enter exactly 64 hexadecimal characters (0-9, a-f), or leave the reference empty.")
    matches = normalized == digest.lower()
    return {
        "status": "MATCH" if matches else "MISMATCH",
        "reference_sha256": normalized,
        "explanation": (
            "The uploaded bytes match the supplied digest. This verifies consistency only if the reference is trustworthy."
            if matches else "The digests differ. File content differs from the reference; this does not establish malicious manipulation."
        ),
    }


def human_size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.2f} MiB"


def safe_text(value: object, limit: int = 1000) -> str:
    """Bound untrusted text and omit binary payloads from displays and reports."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"[Binary value omitted: {len(value)} bytes]"
    if isinstance(value, (tuple, list)):
        value = ", ".join(safe_text(item, 80) for item in value[:24]) + (" [more values omitted]" if len(value) > 24 else "")
    if isinstance(value, dict):
        return "[Nested metadata directory]"
    text = "".join(c if c.isprintable() else " " for c in str(value)).strip()
    return (text[:limit] + " [truncated]") if len(text) > limit else (text or NOT_AVAILABLE)


def safe_filename(filename: str) -> str:
    # Handle either OS's path separators; never use this label as a filesystem path.
    return safe_text(str(filename).replace("\\", "/").rsplit("/", 1)[-1], 240)


def validate_image(data: bytes) -> Image.Image:
    """Return a fully loaded independent image. The caller owns and closes it.

    Restrict Pillow plugins before opening, check dimensions before decoding, verify
    structure, then reopen and load pixels. Do not change Pillow's global limits.
    """
    if not data:
        raise ImageValidationError("The uploaded file is empty. Choose a JPEG or PNG image.")
    if len(data) > MAX_FILE_BYTES:
        raise ImageValidationError("The file exceeds the 15 MB limit (15,728,640 bytes).")
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data), formats=("JPEG", "PNG")) as candidate:
                if candidate.width * candidate.height > MAX_PIXELS:
                    raise ImageValidationError("The image exceeds the 30 million pixel limit.")
                if getattr(candidate, "n_frames", 1) != 1:
                    raise ImageValidationError("Animated or multi-frame PNG images are not supported. Use a single-frame image.")
                candidate.verify()
            with Image.open(BytesIO(data), formats=("JPEG", "PNG")) as decoded:
                decoded.load()
                result = decoded.copy()
                result.format = decoded.format
            if caught:
                result.info["imageguard_decode_notice"] = "Pillow reported a decoding or metadata warning; interpret available metadata cautiously."
            return result
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise ImageValidationError("Pillow rejected this image as a decompression-bomb risk. Choose a smaller image.") from exc
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError, OverflowError) as exc:
        if isinstance(exc, ImageValidationError):
            raise
        raise ImageValidationError("The file is malformed, incomplete, or not a supported JPEG/PNG image.") from exc


def _metadata(image: Image.Image, data: bytes, filename: str) -> dict:
    fields: dict[str, str] = {}
    notices: list[str] = []
    if image.info.get("imageguard_decode_notice"):
        notices.append(image.info["imageguard_decode_notice"])
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            exif = image.getexif()
            directories = [("", dict(exif), ExifTags.TAGS)]
            for tag, prefix, names in ((0x8769, "", ExifTags.TAGS), (0x8825, "GPS.", ExifTags.GPSTAGS)):
                if tag in exif:
                    directories.append((prefix, exif.get_ifd(tag), names))
            for prefix, values, names in directories:
                for tag, value in values.items():
                    if len(fields) >= 128:
                        notices.append("EXIF display limited to 128 fields; individual values limited to 1,000 characters.")
                        break
                    fields[prefix + names.get(tag, f"Tag {tag}")] = safe_text(value)
            if caught:
                notices.append("Some EXIF fields could not be read reliably. Available fields are shown.")
    except (OSError, ValueError, SyntaxError, TypeError, KeyError, IndexError, OverflowError):
        notices.append("EXIF metadata is malformed or unreadable. Image pixels remain available for analysis.")
    summary = {
        "Camera manufacturer": fields.get("Make", NOT_AVAILABLE),
        "Camera model": fields.get("Model", NOT_AVAILABLE),
        "Original date/time": fields.get("DateTimeOriginal", NOT_AVAILABLE),
        "Editing software": fields.get("Software", NOT_AVAILABLE),
        "Orientation": fields.get("Orientation", NOT_AVAILABLE),
    }
    orientation_names = {"1": "Normal", "2": "Mirror horizontal", "3": "Rotate 180", "4": "Mirror vertical",
                         "5": "Transpose", "6": "Rotate 90 CW", "7": "Transverse", "8": "Rotate 90 CCW"}
    if summary["Orientation"] in orientation_names:
        summary["Orientation"] += " (" + orientation_names[summary["Orientation"]] + ")"
    name = safe_filename(filename)
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    expected = {"JPEG": {"jpg", "jpeg"}, "PNG": {"png"}}[image.format]
    if extension not in expected:
        notices.append("Filename extension differs from the detected format. Analysis uses the actual image content.")
    if image.mode not in ("L", "LA", "RGB", "RGBA", "P", "1"):
        notices.append("Visual statistics convert this color mode to 8-bit RGB/grayscale; high bit-depth values may be clipped by Pillow.")
    return {
        "filename": name, "size_bytes": len(data), "size_human": human_size(len(data)),
        "format": image.format, "width": image.width, "height": image.height,
        "pixel_count": image.width * image.height, "color_mode": image.mode,
        "channels": len(image.getbands()), "exif": fields, "summary": summary,
        "notices": notices,
    }


def extract_metadata(data: bytes, filename: str = "uploaded-image") -> dict:
    with validate_image(data) as image:
        return _metadata(image, data, filename)


def _ela(image: Image.Image) -> ELAResult:
    if image.format != "JPEG":
        raise ELAUnsupportedError("JPEG recompression-based ELA is not applicable to PNG. Metadata, hashing and statistics remain available.")
    with image.convert("RGB") as source:
        buffer = BytesIO()
        source.save(buffer, format="JPEG", quality=ELA_QUALITY, subsampling=0, optimize=False, progressive=False)
        buffer.seek(0)
        with Image.open(buffer) as recompressed:
            recompressed.load()
            with ImageChops.difference(source, recompressed) as difference:
                extrema = difference.getextrema()
                maximum = max(high for _, high in extrema)
                mean = float(sum(ImageStat.Stat(difference).mean) / 3)
                # Bound the gain so tiny noise is not amplified without limit.
                gain = min(20.0, 255.0 / maximum) if maximum else 1.0
                enhanced = ImageEnhance.Brightness(difference).enhance(gain)
    return ELAResult(enhanced, {
        "available": True, "quality": ELA_QUALITY, "subsampling": "4:4:4 (0)",
        "mean_absolute_difference": round(mean, 6), "maximum_channel_difference": maximum,
        "brightness_gain": round(gain, 6),
        "observation": (
            "No decoded pixel differences at these recompression settings; the visualization is black. This does not establish authenticity."
            if maximum == 0 else
            "Brighter pixels show greater absolute differences after JPEG recompression. Differences can arise naturally from image content and compression history."
        ),
        "interpretation": "Mean and maximum are measured before enhancement on 0-255 RGB channel values. Adaptive gain (capped at 20x) is only a display adjustment, not a forensic score.",
    })


def perform_ela(data: bytes) -> ELAResult:
    """Decode original JPEG bytes and return visualization plus raw measurements."""
    with validate_image(data) as image:
        return _ela(image)


def image_statistics(image: Image.Image) -> dict:
    """Exact histograms accumulated in strips to bound NumPy working memory."""
    rgb_compatible = image.mode not in ("1", "L", "LA", "I", "F") and not image.mode.startswith("I;")
    histograms = {name: np.zeros(256, dtype=np.int64) for name in (["Red", "Green", "Blue"] if rgb_compatible else []) + ["Grayscale"]}
    for top in range(0, image.height, 256):
        with image.crop((0, top, image.width, min(top + 256, image.height))) as strip:
            with strip.convert("RGB") as rgb:
                if rgb_compatible:
                    pixels = np.asarray(rgb)
                    for channel, name in enumerate(("Red", "Green", "Blue")):
                        histograms[name] += np.bincount(pixels[:, :, channel].ravel(), minlength=256)
                with rgb.convert("L") as gray:
                    histograms["Grayscale"] += np.bincount(np.asarray(gray).ravel(), minlength=256)
    count = image.width * image.height
    levels = np.arange(256, dtype=np.float64)
    summaries = {}
    for name, counts in histograms.items():
        mean = float(np.dot(counts, levels) / count)
        variance = float(np.dot(counts, (levels - mean) ** 2) / count)
        occupied = np.flatnonzero(counts)
        summaries[name] = {"mean": round(mean, 4), "standard_deviation": round(variance ** 0.5, 4),
                           "minimum": int(occupied[0]), "maximum": int(occupied[-1])}
    return {"pixel_count": count, "rgb_available": rgb_compatible,
            "histograms": {name: counts.tolist() for name, counts in histograms.items()},
            "channels": summaries,
            "method": "Exact 256-bin counts of 8-bit decoded values; grayscale uses Pillow RGB-to-L luminance conversion. Alpha is ignored, not composited. No sampling, ICC color management or EXIF rotation is applied.",
            "interpretation": "Distribution, brightness and spread describe image content. They do not establish tampering."}


def _preview(image: Image.Image) -> Image.Image:
    preview = image.copy()
    preview.thumbnail((1400, 1000))
    converted = preview.convert("RGBA" if "A" in image.getbands() or "transparency" in image.info else "RGB")
    preview.close()
    # Do not send EXIF/GPS metadata to the preview's image encoder.
    converted.info.clear()
    return converted


def analyze_image(data: bytes, filename: str, reference: str | None = None) -> AnalysisResult:
    digest = calculate_sha256(data)
    integrity = compare_reference_hash(digest, reference)
    with validate_image(data) as image:
        metadata = _metadata(image, data, filename)
        statistics = image_statistics(image)
        ela_preview = None
        if image.format == "JPEG":
            ela = _ela(image)
            try:
                ela_preview = _preview(ela.image)
            finally:
                ela.image.close()
            ela_findings = ela.findings
        else:
            ela_findings = {"available": False, "reason": "JPEG recompression-based ELA is not applicable to PNG. No ELA was performed."}
        preview = _preview(image)
    report = {
        "schema_version": "1.0", "tool": "ImageGuard", "tool_version": "1.0.0",
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "metadata": metadata, "sha256": digest, "integrity": integrity,
        "ela": ela_findings, "statistics": statistics,
        "checks_performed": ["File-size and pixel-limit validation", "JPEG/PNG content verification and pixel decoding",
                             "Metadata extraction", "SHA-256 of exact uploaded bytes",
                             "Reference comparison" if integrity["reference_sha256"] else "Reference comparison not performed: no reference supplied",
                             "JPEG error level analysis" if ela_findings["available"] else "ELA not performed: PNG input",
                             "Color/grayscale histograms and descriptive statistics"],
        "limitations": list(LIMITATIONS),
    }
    return AnalysisResult(report, preview, ela_preview)
