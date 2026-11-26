"""Regression tests for the MMC-T201 predictor."""

import pytest

from xiaomi_ble.thermometer import MMCT201Temperature, decode_mmc_t201_temperature


def sample(
    thermometer: MMCT201Temperature,
    now: int,
    *,
    first: float | None = 37.0,
    second: float | None = 35.0,
) -> float | None:
    return thermometer.update(first, second, (now % 256, b"test"), now)


def test_uses_shared_predictor_and_rebases_after_a_measurement_gap():
    thermometer = MMCT201Temperature()
    assert sample(thermometer, 0) == pytest.approx(37.3)
    assert sample(thermometer, 0) is None
    assert sample(thermometer, 10) == pytest.approx(37.8251512)
    assert sample(thermometer, 300) == pytest.approx(37.8251512)
    assert sample(thermometer, 301) == pytest.approx(37.961464)
    assert sample(thermometer, 602) == pytest.approx(37.3)


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [(35.90, 35.35, 36.6547502), (35.99, 35.45, 36.714744504)],
)
def test_preserves_temperature_difference_below_the_cap(first, second, expected):
    thermometer = MMCT201Temperature()
    sample(thermometer, 0, first=first, second=second)
    assert sample(thermometer, 10, first=first, second=second) == pytest.approx(
        expected
    )
    assert sample(thermometer, 301, first=first, second=second) == pytest.approx(
        expected
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (-1, None),
        (0, None),
        (1, 0.01),
        (5000, 50.0),
        (5001, None),
        (0x7FF0, None),
        (0x7FF1, None),
        (0x7FF2, None),
    ],
)
def test_decodes_only_valid_channel_readings(raw, expected):
    assert decode_mmc_t201_temperature(raw) == expected


def test_missing_channels_do_not_start_prediction():
    thermometer = MMCT201Temperature()
    assert sample(thermometer, 0, first=None) is None
    assert sample(thermometer, 10, second=None) is None
    assert sample(thermometer, 20) == pytest.approx(37.3)


def test_cold_readings_are_suppressed_and_reset_the_estimate():
    thermometer = MMCT201Temperature()
    assert sample(thermometer, 0) == pytest.approx(37.3)
    assert sample(thermometer, 10) == pytest.approx(37.8251512)
    assert sample(thermometer, 20, first=31.9, second=30) is None
    assert sample(thermometer, 30, first=31.0, second=30) is None
    assert sample(thermometer, 40) == pytest.approx(37.3)


def test_warmup_limits_the_increase_until_t2_settles():
    thermometer = MMCT201Temperature()
    assert sample(thermometer, 0, first=30, second=30) is None
    assert sample(thermometer, 60, first=36) == pytest.approx(36.3)
    for now, expected in [(120, 36.5), (180, 36.7), (240, 36.9), (300, 36.931006)]:
        assert sample(thermometer, now, first=36) == pytest.approx(expected)
    # The initial cold reading expires after five minutes of continuous samples.
    assert sample(thermometer, 360, first=36) == pytest.approx(36.931006)
    assert sample(thermometer, 420, first=37) == pytest.approx(37.531006)


def test_stable_cool_samples_transition_to_warmup():
    thermometer = MMCT201Temperature()
    for now in range(0, 100, 10):
        sample(thermometer, now, first=32.5, second=30)
    assert sample(thermometer, 100, first=32.5, second=30) == pytest.approx(35.4332662)
    assert sample(thermometer, 110, first=36, second=30.6) == pytest.approx(36.3)
