"""Run with: python -m streamlit run app.py"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from io import BytesIO

import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt
import numpy as np
import streamlit as st
from reportlab.platypus.doctemplate import LayoutError

from image_forensics import (
    ImageValidationError, ReferenceHashError, analyze_image,
    calculate_sha256, compare_reference_hash, MAX_FILE_BYTES,
)
from report_generator import generate_json_report, generate_pdf_report


def clear_analysis() -> None:
    """Keep analysis session-local; clear stale images and reports on replacement."""
    old = st.session_state.pop("analysis", None)
    if old:
        old.preview.close()
        if old.ela_preview:
            old.ela_preview.close()
    st.session_state.pop("analysis_key", None)
    st.session_state.pop("reference", None)


def show_table(values: dict) -> None:
    st.dataframe([{"Property": str(key), "Value": str(value)} for key, value in values.items()],
                 hide_index=True, width="stretch")


def histogram_figure(stats: dict):
    """Caller closes this figure after rendering."""
    with plt.rc_context({"font.size": 10, "text.color": "#e5edf8", "axes.labelcolor": "#c3d3e6",
                         "xtick.color": "#c3d3e6", "ytick.color": "#c3d3e6", "axes.edgecolor": "#33465f"}):
        figure, axes = plt.subplots(1, 2 if stats["rgb_available"] else 1, figsize=(11, 4), squeeze=False,
                                    facecolor="#131e32", layout="constrained")
        charts = axes.ravel()
        for axis in charts:
            axis.set_facecolor("#131e32")
            axis.set_xlabel("Intensity (0–255)")
            axis.set_ylabel("Pixel count")
            axis.set_xlim(0, 255)
            axis.grid(alpha=0.12)
            axis.ticklabel_format(axis="y", style="sci", scilimits=(0, 4))
        if stats["rgb_available"]:
            for name, color in (("Red", "#fb7185"), ("Green", "#4ade80"), ("Blue", "#60a5fa")):
                charts[0].plot(np.arange(256), stats["histograms"][name], color=color, label=name, linewidth=1.6)
            charts[0].set_title("RGB color distribution", color="#e5edf8")
            charts[0].legend(facecolor="#131e32", labelcolor="#e5edf8")
        gray_axis = charts[-1]
        gray_axis.fill_between(np.arange(256), stats["histograms"]["Grayscale"], color="#22d3ee", alpha=0.35)
        gray_axis.plot(stats["histograms"]["Grayscale"], color="#22d3ee", linewidth=1.5)
        gray_axis.set_title("Grayscale luminance distribution", color="#e5edf8")
        return figure


def main() -> None:
    st.set_page_config(page_title="ImageGuard | Digital Image Forensics", page_icon="🛡️", layout="wide")
    # Only trusted, static application styling is inserted as HTML.
    st.markdown("""
    <style>
    .block-container {max-width:1440px;padding-top:2.2rem;padding-bottom:3rem;}
    .ig-eyebrow {color:#67e8f9;font-size:.76rem;letter-spacing:.18em;font-weight:700;}
    .ig-title {font-size:clamp(2.4rem,5vw,3.6rem);font-weight:800;letter-spacing:-.055em;margin:.1rem 0;line-height:1.2;color:#f1f5ff;}
    .ig-subtitle {color:#c8d7ea;font-size:1.12rem;margin-top:.3rem;}
    div[data-testid="stMetric"] {background:#131e32;border:1px solid #263b55;border-radius:12px;padding:1rem;}
    div[data-testid="stMetricValue"] {font-size:1.55rem;}
    div[data-testid="stMetricLabel"] {color:#b8cce2;}
    button[data-baseweb="tab"] {padding:.7rem 1rem;}
    [data-testid="stFileUploader"] {border:1px solid #284962;border-radius:12px;padding:.5rem;}
    /* Hide old report controls while a reference/upload rerun replaces them. */
    [data-stale="true"] [data-testid="stDownloadButton"] {visibility:hidden;pointer-events:none;}
    </style>
    <div class="ig-eyebrow">LOCAL FORENSICS WORKSPACE</div>
    <div class="ig-title">ImageGuard</div>
    <p class="ig-subtitle">Digital Image Forensics &amp; Integrity Analysis</p>
    """, unsafe_allow_html=True)
    st.write("Analyze image metadata, verify file integrity, and inspect potential compression anomalies.")

    with st.sidebar:
        st.title("ImageGuard")
        st.caption("A focused workspace for image evidence exploration.")
        st.divider()
        st.markdown("**INPUT REQUIREMENTS**")
        st.write("JPEG / JPG / PNG")
        st.caption("Up to 15 MB (15 MiB) · 30 million pixels · single-frame images")
        st.markdown("**QUICK START**")
        st.write("1. Upload an image.\n2. Add a trusted reference hash, if available.\n3. Review the analysis tabs.\n4. Download PDF and JSON reports.")
        st.divider()
        st.markdown("**LOCAL & PRIVATE**")
        st.caption("Files are processed on this computer. Uploaded originals are held in memory and are not intentionally saved. No image data is sent to external services. Reports may contain private EXIF information.")
        st.info("Results are indicative and require forensic interpretation. This tool does not certify authenticity.")

    uploaded = st.file_uploader("Upload an image", type=["jpg", "jpeg", "png"],
                                help="Actual file contents are validated using Pillow.",
                                on_change=clear_analysis, key="upload")
    if uploaded is None:
        st.markdown("### Every investigation starts with the original bytes.")
        st.write("Explore what an image contains and compare it with a trusted reference, using transparent, explainable checks.")
        columns = st.columns(4)
        for column, number, title, description in zip(columns, ("01", "02", "03", "04"),
                ("Upload an image", "Metadata & integrity", "Inspect the analysis", "Download a report"),
                ("Choose a JPEG or PNG stored on your computer.", "Inspect file properties, EXIF and SHA-256.",
                 "Review JPEG compression differences and histograms.", "Export a readable PDF and structured JSON.")):
            with column:
                with st.container(border=True):
                    st.caption(number)
                    st.markdown(f"**{title}**")
                    st.write(description)
        st.info("No authenticity verdicts. ImageGuard presents measured facts, visualization aids and their limitations.")
        return

    if uploaded.size > MAX_FILE_BYTES:
        st.error("The file exceeds the 15 MB upload limit. Choose a smaller image.")
        return
    data = uploaded.getvalue()
    key = (calculate_sha256(data), uploaded.name)
    try:
        if st.session_state.get("analysis_key") != key:
            with st.spinner("Validating image and calculating local forensic measurements…"):
                clear_analysis()
                st.session_state.analysis = analyze_image(data, uploaded.name)
                st.session_state.analysis_key = key
        analysis = st.session_state.analysis
    except ImageValidationError as exc:
        st.error(str(exc))
        return
    except (OSError, MemoryError):
        st.error("The image could not be processed with the available resources. Try a smaller JPEG or PNG.")
        return

    reference = st.text_input("Reference SHA-256 (optional)", key="reference", max_chars=256,
                              placeholder="Paste a previously recorded, trusted 64-character SHA-256 hash",
                              help="Whitespace around the hash is ignored. Hexadecimal letters are case-insensitive.")
    invalid_reference = False
    try:
        integrity = compare_reference_hash(analysis.report["sha256"], reference)
    except ReferenceHashError as exc:
        st.error(str(exc))
        invalid_reference = True
        integrity = {"status": "INVALID REFERENCE", "explanation": "Correct or clear the reference to enable report downloads."}

    metadata = analysis.report["metadata"]
    metric_columns = st.columns(4)
    for column, label, value in zip(metric_columns,
            ("Image format", "Resolution", "File size", "SHA-256 integrity"),
            (metadata["format"], f"{metadata['width']} × {metadata['height']}", metadata["size_human"],
             "No reference" if integrity["status"] == "REFERENCE HASH NOT PROVIDED" else integrity["status"])):
        column.metric(label, value)
    st.caption("Analysis time (UTC): " + analysis.report["analysis_timestamp"])
    tabs = st.tabs(["Overview", "Metadata", "ELA Analysis", "Image Statistics", "Forensic Report"])

    with tabs[0]:
        left, right = st.columns([1.3, 1])
        with left:
            st.image(analysis.preview, caption="Original decoded image · preview may be scaled · EXIF rotation is not applied", width="stretch")
        with right:
            st.subheader("File information")
            show_table({"Filename": metadata["filename"], "Detected format": metadata["format"],
                        "Dimensions": f"{metadata['width']} × {metadata['height']}", "Pixels": f"{metadata['pixel_count']:,}",
                        "File size": f"{metadata['size_bytes']:,} bytes", "Color mode": metadata["color_mode"],
                        "Channels": metadata["channels"]})
            st.success("Upload passed format, file-size, pixel-count and decoding checks.")
            for notice in metadata["notices"]:
                st.warning(notice)
        st.subheader("SHA-256 · exact original bytes")
        st.code(analysis.report["sha256"], language=None)
        st.caption("Use the code block's copy control, or select the full digest and copy it.")
        status_function = st.success if integrity["status"] == "MATCH" else st.warning if integrity["status"] == "MISMATCH" else st.info
        status_function(integrity["status"] + ": " + integrity["explanation"])

    with tabs[1]:
        st.subheader("Metadata examination")
        st.info("Metadata can be modified or removed. Missing fields are not inherently suspicious and do not prove manipulation.")
        show_table(metadata["summary"])
        if metadata["exif"]:
            with st.expander(f"Available EXIF fields ({len(metadata['exif'])})", expanded=True):
                show_table(metadata["exif"])
            st.caption("Binary payloads are omitted. Up to 128 fields and 1,000 characters per field are displayed. GPS fields, if present, may reveal private locations.")
        else:
            st.info("No readable EXIF metadata is available. This is normal for many images and exports.")
        for notice in metadata["notices"]:
            st.warning(notice)

    with tabs[2]:
        st.subheader("Error level analysis")
        ela = analysis.report["ela"]
        if not ela["available"]:
            st.info(ela["reason"])
            st.write("Continue with metadata, SHA-256 integrity verification and image statistics.")
        else:
            left, right = st.columns(2)
            left.image(analysis.preview, caption="Original decoded JPEG", width="stretch")
            right.image(analysis.ela_preview, caption="Enhanced absolute recompression difference", width="stretch")
            columns = st.columns(3)
            columns[0].metric("Mean absolute difference", f"{ela['mean_absolute_difference']:.3f}")
            columns[1].metric("Maximum channel difference", ela["maximum_channel_difference"])
            columns[2].metric("Display brightness gain", f"{ela['brightness_gain']:.2f}×")
            st.write(ela["observation"])
            st.caption(f"Fixed JPEG quality {ela['quality']}; subsampling {ela['subsampling']}. " + ela["interpretation"])
        st.warning("ELA is an investigative aid, not conclusive proof of tampering. Uneven differences may reflect natural image content, compression history or an ordinary editing workflow.")

    with tabs[3]:
        st.subheader("Pixel distributions")
        stats = analysis.report["statistics"]
        figure = histogram_figure(stats)
        try:
            # Render explicitly to keep layout/DPI consistent across Streamlit versions.
            chart = BytesIO()
            figure.savefig(chart, format="png", dpi=130, bbox_inches="tight", pad_inches=0.15)
            st.image(chart.getvalue(), caption="Exact pixel counts by intensity", width="stretch")
        finally:
            plt.close(figure)
        st.dataframe([{"Channel": name, **values} for name, values in stats["channels"].items()],
                     hide_index=True, width="stretch")
        st.caption(stats["method"])
        st.info(stats["interpretation"])

    with tabs[4]:
        st.subheader("Forensic report")
        st.write("Export the file properties, digest, metadata, ELA measurements, statistics and interpretation limits.")
        st.code(analysis.report["sha256"], language=None)
        st.write("Integrity comparison: " + integrity["status"])
        st.write("ELA: " + ("JPEG analysis performed." if ela["available"] else ela["reason"]))
        with st.expander("Summary of checks and limitations", expanded=True):
            for limitation in analysis.report["limitations"]:
                st.write("• " + limitation)
        if invalid_reference:
            st.warning("Correct or clear the invalid reference hash to download an accurate report.")
        else:
            report = deepcopy(analysis.report)
            report["integrity"] = integrity
            report["checks_performed"][4] = "Reference comparison" if integrity["reference_sha256"] else "Reference comparison not performed: no reference supplied"
            report["report_generated_timestamp"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            stem = "imageguard_" + report["sha256"][:12]
            left, right = st.columns(2)
            try:
                pdf = generate_pdf_report(report)
                left.download_button("Download PDF report", data=pdf, file_name=stem + ".pdf", mime="application/pdf",
                                     key="pdf_" + report["sha256"] + (integrity["reference_sha256"] or "none"),
                                     on_click="ignore", width="stretch")
            except (OSError, ValueError, LayoutError, MemoryError):
                left.error("PDF formatting could not be completed. The JSON report remains available.")
            right.download_button("Download JSON report", data=generate_json_report(report),
                                  file_name=stem + ".json", mime="application/json",
                                  key="json_" + report["sha256"] + (integrity["reference_sha256"] or "none"),
                                  on_click="ignore", width="stretch")
            st.caption("Reports may include sensitive metadata. Downloads are saved only when you choose to save them in your browser.")


if __name__ == "__main__":
    main()
