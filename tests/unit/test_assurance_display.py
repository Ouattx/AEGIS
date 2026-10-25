from __future__ import annotations

import math

import pytest

from aegis.assurance import AssuranceError, display_score, format_score


@pytest.mark.parametrize("score,text", [
    (1.0, ">0.99"), (0.9999, ">0.99"), (0.995, ">0.99"), (0.99, "0.99"), (0.5, "0.50"),
    (0.01, "0.01"), (0.0099, "<0.01"), (0.0, "<0.01"), (0.994, ">0.99"),
])
def test_two_digit_clamp(score, text):
    d = display_score(score, "iso-abc")
    assert d.text == text
    assert d.text not in ("1.00", "0.00", "1", "0")
    assert d.clamped == text.startswith((">", "<"))


def test_never_renders_certainty_over_a_grid():
    for i in range(0, 100001):
        s = i / 100000
        for digits in (2, 3):
            t = display_score(s, "iso-x", digits=digits).text
            assert t.lstrip("<>") not in ("1." + "0" * digits, "0." + "0" * digits)


def test_three_digits():
    assert display_score(0.9995, "c", digits=3).text == ">0.999"
    assert display_score(0.0004, "c", digits=3).text == "<0.001"
    assert display_score(0.123, "c", digits=3).text == "0.123"


def test_calibration_id_is_stated_for_probabilities():
    d = display_score(0.87, "iso-1234")
    assert d.is_probability and d.calibration_id == "iso-1234"
    assert str(d) == "0.87 (calibrated probability, calibration iso-1234)"
    assert format_score(1.0, "iso-1234") == ">0.99 (calibrated probability, calibration iso-1234)"
    assert d.to_dict()["display"] == str(d)


def test_uncalibrated_scores_are_not_called_probabilities():
    d = display_score(0.87, None)
    assert not d.is_probability and d.calibration_id is None
    assert "not a probability" in str(d)
    assert "calibration" not in str(d).replace("uncalibrated", "")
    assert display_score(1.0, "").text == ">0.99"


@pytest.mark.parametrize("bad", [math.nan, math.inf, -0.01, 1.01, "x", None])
def test_invalid_scores_raise(bad):
    with pytest.raises(AssuranceError):
        display_score(bad, "iso")  # type: ignore[arg-type]


def test_invalid_digits():
    with pytest.raises(AssuranceError):
        display_score(0.5, "iso", digits=1)
