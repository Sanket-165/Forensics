"""In-memory JSON and PDF reports; untrusted labels are escaped as plain text."""

from __future__ import annotations

from html import escape
from io import BytesIO
import json

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle


def generate_json_report(report: dict) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False).encode("utf-8")


def _pdf_text(value: object) -> str:
    # Core PDF fonts cannot represent all Unicode. Preserve unsupported characters
    # as visible escape sequences rather than silently replacing them with boxes.
    text = str(value).encode("cp1252", errors="backslashreplace").decode("cp1252")
    return escape(text).replace("\n", "<br/>")


def generate_pdf_report(report: dict) -> bytes:
    output = BytesIO()
    document = SimpleDocTemplate(
        output, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=20 * mm,
        title="ImageGuard — Digital Image Forensics Report", author="ImageGuard",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("ReportBody", fontName="Helvetica", fontSize=9, leading=13,
                              textColor=colors.HexColor("#243247"), spaceAfter=7,
                              splitLongWords=True, alignment=TA_LEFT))
    styles.add(ParagraphStyle("Cell", parent=styles["ReportBody"], fontSize=8, leading=11, spaceAfter=0))
    styles["Title"].textColor = colors.HexColor("#10213a")
    styles["Title"].fontSize = 23
    styles["Title"].leading = 28
    styles["Title"].alignment = TA_LEFT
    styles["Heading2"].textColor = colors.HexColor("#086b83")
    story = []

    def paragraph(value: object, style: str = "ReportBody") -> Paragraph:
        return Paragraph(_pdf_text(value), styles[style])

    def heading(value: str) -> None:
        story.append(paragraph(value, "Heading2"))

    def table(rows: list[tuple]) -> None:
        cells = [[paragraph(key, "Cell"), paragraph(value, "Cell")] for key, value in rows]
        block = LongTable(cells, colWidths=[48 * mm, 126 * mm], hAlign="LEFT")
        block.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#eef4f8"), colors.white]),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#d5e0e8")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.extend([block, Spacer(1, 7)])

    metadata = report["metadata"]
    integrity = report["integrity"]
    story.append(paragraph("ImageGuard — Digital Image Forensics Report", "Title"))
    story.append(paragraph("LOCAL ANALYSIS  /  EDUCATIONAL FORENSICS"))
    table([("Analysis timestamp (UTC)", report["analysis_timestamp"]),
           ("Tool / schema version", f"{report['tool_version']} / {report['schema_version']}"),
           ("Integrity comparison", integrity["status"])])
    story.append(paragraph("These results record measured properties and investigative observations. No authenticity or tampering verdict is issued."))

    heading("1. File properties")
    table([("Original filename (display label)", metadata["filename"]), ("Detected format", metadata["format"]),
           ("Dimensions", f"{metadata['width']} x {metadata['height']} pixels"),
           ("Total pixels", f"{metadata['pixel_count']:,}"),
           ("File size", f"{metadata['size_bytes']:,} bytes ({metadata['size_human']})"),
           ("Color mode / channels", f"{metadata['color_mode']} / {metadata['channels']}")])
    for notice in metadata["notices"]:
        story.append(paragraph("Notice: " + notice))

    heading("2. SHA-256 integrity verification")
    table([("Original bytes SHA-256", report["sha256"]),
           ("Reference SHA-256", integrity["reference_sha256"] or "Not provided."),
           ("Comparison result", integrity["status"])])
    story.append(paragraph(integrity["explanation"]))

    heading("3. Metadata findings")
    table(list(metadata["summary"].items()))
    if metadata["exif"]:
        story.append(paragraph("Available EXIF fields (binary values omitted; text bounded for safe display):"))
        table(list(metadata["exif"].items()))
    else:
        story.append(paragraph("No readable EXIF metadata is available. Missing metadata is not inherently suspicious."))
    story.append(paragraph("Metadata may contain private information, may be edited or removed, and cannot prove authenticity."))

    heading("4. Error level analysis")
    ela = report["ela"]
    if ela["available"]:
        table([("JPEG recompression quality", ela["quality"]), ("Chroma subsampling", ela["subsampling"]),
               ("Mean absolute difference", ela["mean_absolute_difference"]),
               ("Maximum channel difference", ela["maximum_channel_difference"]),
               ("Visualization brightness gain", f"{ela['brightness_gain']}x")])
        story.extend([paragraph(ela["observation"]), paragraph(ela["interpretation"])])
    else:
        story.append(paragraph(ela["reason"]))

    heading("5. Image statistics")
    stats = report["statistics"]
    story.append(paragraph(stats["method"]))
    table([(name, f"Mean: {values['mean']}; standard deviation: {values['standard_deviation']}; range: {values['minimum']}–{values['maximum']}")
           for name, values in stats["channels"].items()])
    story.append(paragraph(stats["interpretation"]))
    story.append(paragraph("The JSON report contains full 256-bin histogram counts. Visual histograms and ELA previews are available in the dashboard."))

    heading("6. Summary of checks")
    for item in report["checks_performed"]:
        story.append(paragraph("• " + item))
    heading("7. Limitations and interpretation")
    for item in report["limitations"]:
        story.append(paragraph("• " + item))
    story.append(paragraph("Unicode characters unavailable in the built-in PDF font are written as escaped code points. The JSON report preserves the original text values."))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#d5e0e8"))
        canvas.line(18 * mm, 15 * mm, 192 * mm, 15 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#52677e"))
        canvas.drawString(18 * mm, 10 * mm, "ImageGuard | Local image forensics | Educational use")
        canvas.drawRightString(192 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
