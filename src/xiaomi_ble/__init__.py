"""Parser for Xiaomi BLE advertisements.

This file is shamlessly copied from the following repository:
https://github.com/Ernst79/bleparser/blob/c42ae922e1abed2720c7fac993777e1bd59c0c93/package/bleparser/Xiaomi.py

MIT License applies.
"""
from __future__ import annotations

from sensor_state_data import (
    DeviceClass,
    DeviceKey,
    SensorDescription,
    SensorDeviceInfo,
    SensorUpdate,
    SensorValue,
    Units,
)

from .devices import SLEEPY_DEVICE_MODELS
from .parser import EncryptionScheme, XiaomiBluetoothDeviceData

__version__ = "0.16.4"

__all__ = [
    "SLEEPY_DEVICE_MODELS",
    "EncryptionScheme",
    "XiaomiBluetoothDeviceData",
    "SensorDescription",
    "SensorDeviceInfo",
    "DeviceClass",
    "DeviceKey",
    "SensorUpdate",
    "SensorDeviceInfo",
    "SensorValue",
    "Units",
]
