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

    # Error
    ERROR = "error"

    # Fingerprint
    FINGERPRINT = "fingerprint"

    # Motion
    MOTION = "motion"

    # Lock
    LOCK = "lock"
