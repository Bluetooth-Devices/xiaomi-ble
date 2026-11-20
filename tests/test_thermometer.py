"""Regression tests for the MMC-T201 predictor."""

import pytest

from xiaomi_ble.thermometer import MMCT201Temperature


def sample(
    thermometer: MMCT201Temperature,
    now: int,
    *,
    first: float = 37.0,
    second: float = 35.0,
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
