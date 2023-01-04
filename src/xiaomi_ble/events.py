"""Event constants for xiaomi-ble."""
from __future__ import annotations

from sensor_state_data.enum import StrEnum


class EventDeviceKeys(StrEnum):
    """Keys for devices that send events."""

    # Button
    BUTTON = "button"

    # Dimmer
    DIMMER = "dimmer"

    # Motion
    MOTION = "motion"

    # Rocker switch
    SWITCH = "switch"
