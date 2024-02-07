"""Event constants for xiaomi-ble."""
from __future__ import annotations

from sensor_state_data.enum import StrEnum


class EventDeviceKeys(StrEnum):
    """Keys for devices that send events."""

    # Button
    BUTTON = "button"

    # Cube
    CUBE = "cube"

    # Dimmer
    DIMMER = "dimmer"

    # Lock method
    ERROR = "error"

    # Motion
    MOTION = "motion"

    # Lock
    LOCK = "lock"
