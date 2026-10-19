"""Streamlit integration checks, no server or network required."""

from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest
from streamlit.testing.v1 import AppTest

from image_forensics import calculate_sha256
from report_generator import generate_json_report
from tests.test_image_forensics import make_image

APP = Path(__file__).resolve().parents[1] / "app.py"


class Upload(BytesIO):
    def __init__(self, data, name):
        super().__init__(data)
        self.name = name
        self.size = len(data)


def test_welcome_renders_without_errors():
    app = AppTest.from_file(str(APP), default_timeout=30).run()
    assert not app.exception
    assert not app.error


@pytest.mark.parametrize("fmt", ["JPEG", "PNG"])
def test_dashboard_and_reference_transitions(fmt):
    data = make_image(fmt)
    with patch("streamlit.file_uploader", return_value=Upload(data, "sample." + fmt.lower())), \
            patch("report_generator.generate_json_report", wraps=generate_json_report) as json_export:
        app = AppTest.from_file(str(APP), default_timeout=30).run()
        assert not app.exception
        assert not app.error
        assert app.metric[3].value == "No reference"
        assert len(app.get("download_button")) == 2
        assert json_export.call_args.args[0]["integrity"]["status"] == "REFERENCE HASH NOT PROVIDED"
        app.text_input[0].set_value(calculate_sha256(data)).run()
        assert not app.exception
        assert app.metric[3].value == "MATCH"
        assert json_export.call_args.args[0]["integrity"]["status"] == "MATCH"
        app.text_input[0].set_value("0" * 64).run()
        assert app.metric[3].value == "MISMATCH"
        assert json_export.call_args.args[0]["integrity"]["status"] == "MISMATCH"
        app.text_input[0].set_value("bad hash").run()
        assert not app.exception
        assert app.error
        assert len(app.get("download_button")) == 0
        app.text_input[0].set_value("").run()
        assert not app.error
        assert app.metric[3].value == "No reference"


def test_dashboard_invalid_upload_is_helpful_error():
    with patch("streamlit.file_uploader", return_value=Upload(b"garbage", "bad.png")):
        app = AppTest.from_file(str(APP), default_timeout=30).run()
        assert not app.exception
        assert "malformed" in app.error[0].value
        assert len(app.get("download_button")) == 0
