# ImageGuard — Digital Image Forensics Tool

**Digital Image Forensics & Integrity Analysis**

An entirely local Python mini-project for Cyber Security and Digital Forensics. Upload a JPEG or PNG, examine metadata, compare SHA-256 digests, inspect JPEG recompression differences, and export PDF/JSON reports.

**Problem statement:** Design and develop a tool for digital forensics of images.

## Abstract

Digital images can be copied, recompressed, edited, or stripped of metadata without obvious visual changes. ImageGuard brings several understandable forensic checks into one Streamlit dashboard. Pillow validates and decodes the input, hashlib hashes its exact bytes, and NumPy and Matplotlib describe its pixels. JPEG Error Level Analysis (ELA) visualizes changes introduced by a controlled recompression. ReportLab produces a readable report, while JSON preserves structured results for further inspection. The application presents measurements and limitations; it does not classify images as authentic or manipulated.

## Motivation and objectives

- Make basic image-forensics techniques accessible in a classroom demonstration.
- Distinguish file integrity, metadata observations, and pixel measurements.
- Handle untrusted uploads with explicit resource and format limits.
- Produce repeatable measurements and portable reports without a cloud service.
- Encourage careful forensic interpretation rather than unsupported conclusions.

## Features

- JPEG/JPG and PNG uploads with content-based validation, a 15 MB limit, and a 30-million-pixel limit.
- Pillow structural verification and full decoding; decompression-bomb warnings/errors are rejected.
- Image preview, file properties, readable EXIF, nested camera/time fields, and available GPS fields.
- Exact-byte SHA-256 calculation and optional validated reference comparison.
- JPEG-only ELA with fixed quality 90, fixed 4:4:4 subsampling, raw difference statistics, and bounded adaptive brightness.
- Exact RGB and grayscale histograms plus mean, standard deviation, minimum, and maximum.
- Navy/cyan Streamlit interface with five analysis tabs and clear interpretation notices.
- In-memory PDF and JSON downloads, with UTC timestamps and limitations.
- Programmatically generated test images; no private images or network access required for tests.

## Technology stack

| Technology | Purpose |
| --- | --- |
| Python 3.10+ | Application and standard-library utilities |
| Streamlit | Local browser dashboard and downloads |
| Pillow | Validation, decoding, EXIF, JPEG recompression |
| NumPy | Histogram accumulation and descriptive statistics |
| Matplotlib | In-memory histogram charts |
| hashlib | SHA-256 of original bytes |
| ReportLab | PDF layout and generation |
| json / io / datetime | Structured reports, byte streams, UTC timestamps |
| Pytest | Unit and Streamlit integration tests |

There is no database, cloud API, machine learning model, authentication system, or paid service. Internet access is needed for initial package installation, not for analysis.

## System requirements

- Python 3.10 or newer, preferably 64-bit, with pip and venv.
- Windows, macOS, or Linux and a modern browser.
- A few hundred MB of disk space for dependencies; 4 GB RAM or more is recommended for normal classroom images. Very large images may need considerably more free memory.
- Use modest-resolution images for a smooth demonstration. The pixel limit bounds input size, but cannot guarantee that every supported image fits the available RAM.

## Project structure

The current `Forensics` folder is the project root; no additional `ImageGuard` subfolder is required.

```text
Forensics/
├── app.py                       # Streamlit dashboard and orchestration
├── image_forensics.py           # Validation, EXIF, hashes, ELA, statistics
├── report_generator.py          # In-memory PDF and JSON generation
├── requirements.txt
├── README.md
├── .gitignore
├── .streamlit/
│   └── config.toml              # Dark theme, loopback binding, upload limit
└── tests/
    ├── __init__.py
    ├── test_image_forensics.py
    └── test_app.py              # Headless Streamlit integration tests
```

## Installation and execution: Windows PowerShell

Open PowerShell in the project folder. For this workspace:

```powershell
cd C:\Users\sanke\Desktop\Forensics
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open **http://127.0.0.1:8501** in your browser. Keep the terminal running. Press **Ctrl+C** in that terminal to stop the application.

### If PowerShell blocks activation

Do not change system-wide execution policies. Activation is optional; invoke the virtual environment's Python directly:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

If the environment and packages already exist, start immediately with:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Always run from the project directory so Streamlit loads `.streamlit/config.toml`. The configuration binds the server to this computer's loopback address and disables usage telemetry. Keep these local defaults.

## Installation and execution: macOS / Linux

```bash
cd /path/to/Forensics
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Without activation, use `.venv/bin/python` in place of `python`.

## Testing

With the environment activated:

```powershell
python -m pytest -v
```

Without PowerShell activation:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Tests cover known SHA-256 values; image dimensions and EXIF; missing and malformed metadata; JPEG ELA determinism and black images; rejection of PNG ELA; malformed/truncated/unsupported input; file/pixel limits; decompression-bomb warnings/errors; animated PNG rejection; reference-hash validation and all comparison states; grayscale, RGB, RGBA, palette and 16-bit inputs; histogram counts; PDF/JSON generation; long/untrusted EXIF values; and Streamlit dashboard transitions. Streamlit AppTest exercises UI integration without a running web server. Generated test inputs stay in memory.

## How the techniques work

### 1. Upload validation

The browser filters extensions, but the backend checks actual content. Input is limited to **15 × 1,024 × 1,024 = 15,728,640 bytes** (15 MiB, labeled 15 MB by the upload UI). Pillow opens only JPEG/PNG decoders, checks **width × height ≤ 30,000,000**, verifies the file structure, reopens it, and loads the pixels. Decompression-bomb warnings/errors reject the upload. Animated PNGs are explicitly unsupported to keep frame handling unambiguous.

Filename extensions do not control analysis. A valid PNG named `.jpg` is identified as PNG and receives a mismatch notice. Non-image data named `.jpg` is rejected. Names are display labels, never filesystem paths or executable content. Passing these checks does not certify that a file is malware-free.

### 2. Metadata

File properties describe the original upload's size, detected format, stored dimensions, pixel count, mode, and channel count. EXIF extraction includes top-level tags plus available nested camera and GPS tags. Manufacturer, model, original date/time, software, and orientation are highlighted; missing values read **“Not available.”**

EXIF is optional and editable. An editor name does not establish malicious editing, and absent EXIF is normal for many exports. EXIF capture times are shown as recorded; they are not verified or assumed to be UTC. Analysis timestamps are UTC and include their offset.

For safe display, binary EXIF values are omitted, text is sanitized, values are capped at 1,000 characters, and at most 128 fields are included. This is a readable metadata summary, not a complete byte-level metadata preservation tool. PDF markup is escaped; Unicode unsupported by the built-in PDF font is represented using visible code-point escapes. JSON preserves the Unicode text values.

### 3. SHA-256 integrity

`hashlib.sha256(original_bytes).hexdigest()` produces a 64-character hexadecimal digest. The original bytes are hashed before any re-encoding. Re-saving visually identical pixels can change the digest because metadata and encoding are also part of the file.

| Outcome | Meaning |
| --- | --- |
| MATCH | Uploaded bytes have the supplied reference digest. Consistency depends on a trustworthy reference. |
| MISMATCH | Digests differ, so content differs from the reference. This is not necessarily malicious manipulation. |
| REFERENCE HASH NOT PROVIDED | A digest exists, but no comparison can be made. The metric card abbreviates this to “No reference.” |

Leading/trailing whitespace is removed and hex letters are normalized to lowercase. Anything other than exactly 64 hex characters produces an error. Invalid references disable report downloads until corrected or cleared, avoiding misleading reports. Copy the full digest using the code block's copy control or normal text selection.

### 4. JPEG Error Level Analysis

1. Decode the original JPEG to RGB.
2. Recompress in memory with JPEG **quality 90**, **subsampling 0 (4:4:4)**, optimization disabled, and progressive encoding disabled.
3. Calculate absolute per-channel differences using `ImageChops.difference`.
4. Measure the mean absolute difference across all RGB channels and pixels, and the maximum single-channel difference (both on a 0–255 scale).
5. For display only, multiply brightness by `min(20, 255 / maximum_difference)`. If the maximum is zero, use gain 1 and show a black image.

The gain is adaptive and capped at 20×. It is not a calibrated score. Equal brightness across separate ELA previews does not imply equal raw differences; compare the reported raw statistics and gain. Identical inputs and the same Pillow/JPEG environment produce deterministic measurements; library/codec versions can influence recompression across environments.

Natural edges, textures, compression history, and ordinary editing can produce uneven differences. A black ELA image does not establish authenticity. There is no tampering percentage or automatic verdict. PNG is lossless and this JPEG-recompression method is **not applied to PNG**; other checks remain available.

### 5. Histograms and statistics

Histograms count pixels at each intensity from 0 to 255. RGB-compatible images have separate red, green, and blue curves; all inputs have a grayscale histogram. Mean describes average intensity, standard deviation describes spread, and minimum/maximum describe range. Calculations use all pixels, accumulated in strips to reduce NumPy memory use; they are not sampled.

Grayscale follows Pillow's RGB-to-L luminance conversion. For RGBA images, underlying RGB values are counted even where pixels are transparent; alpha is not composited onto a background. Palette/CMYK modes are converted to RGB. High bit-depth images are converted to 8-bit for these visual statistics and may clip. ICC color management and automatic EXIF rotation are not applied. Stored dimensions and EXIF orientation are reported separately. These choices are documented in reports.

### 6. Reports

The **PDF** includes the title, timestamp, file properties, SHA-256, reference outcome, metadata, ELA observations, statistics, checks, limitations, and page numbers. It is a textual forensic summary; view images/charts in the dashboard.

The **JSON** additionally contains complete histogram arrays, schema/tool versions, and structured fields suitable for later comparison. Both formats are generated in memory and offered as downloads; the application does not create permanent report files. The download name uses a digest prefix instead of an untrusted filename.

## Privacy and reliability

- Processing stays on the local Python server; no image data is transmitted to remote services.
- Uploaded originals are not intentionally written to disk. Current analysis is retained only in the browser session's server-side memory, with no shared persistent image cache.
- Replacing or removing an upload clears the application's previous analysis. Stopping the server releases process memory. This is not a secure-erasure guarantee: browser/OS caching and swapping remain outside the tool's control.
- Image previews are scaled for display and stripped of EXIF; original bytes remain unchanged for hashing.
- Reports can include sensitive EXIF/GPS information. Share downloaded reports deliberately.
- Expected validation and processing errors have helpful messages. Unexpected programming errors are not silently hidden.

## Example demonstration workflow (5–10 minutes)

1. Start the app and explain the four welcome steps.
2. Upload a small JPEG of your choice. Review detected format, resolution, size, and the **No reference** state.
3. In Overview, copy SHA-256 and paste it into the reference field. Show **MATCH** and explain the need for a trustworthy prior reference.
4. Change one hex digit to show **MISMATCH**. Enter `not-a-hash` to demonstrate validation, then clear it.
5. Review camera fields or the normal missing-EXIF notice.
6. Open ELA Analysis; explain fixed recompression, raw statistics, and visualization gain without claiming that bright regions prove tampering.
7. Review histogram axes and channel statistics.
8. Download PDF and JSON and open them locally.
9. Upload a PNG to show that ELA is unavailable while the other checks still work.
10. Optionally upload a text file renamed `.jpg` to show graceful content validation.

## Screenshot suggestions for a college report

Capture the welcome screen; a JPEG overview with metrics and original preview; a reference **MATCH**; the missing-metadata or camera-EXIF table; side-by-side JPEG/ELA visualization; RGB/grayscale histograms; the PNG limitation notice; report download buttons; the first PDF page; and the passing pytest summary. Use non-sensitive images and avoid exposing personal location metadata.

## Limitations and future enhancements

This is an educational analysis tool, not a certified forensic suite. It cannot prove authenticity, recover all editing history, establish chain of custody, identify the creator, or reliably detect all manipulation. Metadata and statistical patterns require context. File validation is not antivirus scanning. Large images still require memory and processing time. The implementation deliberately limits format/frame support.

Possible future work includes explicit chain-of-custody records, more complete metadata extraction, optional ICC-aware visualization, additional formats with carefully bounded decoding, and externally validated forensic techniques. These are outside this mini-project's scope.

## Troubleshooting

- **`streamlit` is not recognized:** use `python -m streamlit` (or the explicit `.venv` Python path), not a bare `streamlit` command.
- **Module not found:** install requirements with the same Python executable used to launch the app.
- **Port 8501 is in use:** stop the previous app with Ctrl+C, or run `python -m streamlit run app.py --server.port 8502`.
- **Browser does not open automatically:** open the local URL printed in the terminal. Headless startup is intentional.
- **Image rejected:** confirm JPEG/PNG content, a single frame, size at most 15,728,640 bytes, and at most 30 million pixels. Try exporting a fresh, smaller copy while retaining your original separately.
- **ELA is black or looks unusual:** check the raw difference measurements and gain; neither establishes an authenticity verdict.
- **Package downloads fail:** check your internet/proxy settings. The application runs offline after dependencies are installed.

## Development verification

Development uses Windows and Python 3.13.1. Dependency ranges allow Python 3.10+; not every Python/OS combination is tested. Initial package installation was blocked by the execution sandbox's network restrictions, then retried with network permission. The restricted environment also prevented Matplotlib from saving its optional user-level font cache; chart rendering still succeeded. No package installation or network connection is performed by the application itself.

Verified on 16 October 2026:

- **46 pytest tests passed**, including report contents after reference-hash changes.
- `pip check` found no broken requirements; Python compilation checks passed.
- The documented `python -m streamlit run app.py` entry point started successfully at `http://127.0.0.1:8501`.
- Browser checks exercised JPEG upload, reference MATCH, analysis tabs, PNG ELA unavailability, malformed-upload rejection, and actual PDF/JSON downloads. Downloaded reports were checked for the current reference and digest; the browser console had no errors. A clipped-label issue in the framework's chart rendering was fixed by explicitly rendering Matplotlib charts to in-memory PNGs.
- JPEG and PNG PDFs were rendered and visually inspected, including their page breaks and footers. Poppler was unavailable; the development machine's existing PyMuPDF renderer was used for this check only. It is not an application dependency.
- Installed primary versions: Streamlit 1.66.0, Pillow 12.3.0, NumPy 2.5.4, Matplotlib 3.11.2, ReportLab 4.5.1, and Pytest 9.1.1.

Other operating systems, Python versions, browsers, and sustained large-image/concurrent workloads were not exhaustively tested. The 30-million-pixel rejection path was tested with a synthetic header rather than allocating an enormous test image. After editing a reference hash, allow the dashboard to finish refreshing before downloading; report buttons do not trigger an extra rerun. Synthetic development artifacts live only under ignored `tmp/` and `.playwright-mcp/` directories, and are not required to run the project.

## Primary documentation

- [Streamlit file uploader and upload limits](https://docs.streamlit.io/develop/api-reference/widgets/st.file_uploader)
- [Pillow image loading, EXIF and decompression-bomb protection](https://pillow.readthedocs.io/en/stable/reference/Image.html)

The uploader's filename filter is only a convenience; ImageGuard independently validates content. Pillow's built-in bomb protection is retained alongside the application's stricter pixel limit.
