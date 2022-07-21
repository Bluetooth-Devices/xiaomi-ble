"""Parser for Xiaomi BLE advertisements."""
from __future__ import annotations

from bluetooth_sensor_state_data import SIGNAL_STRENGTH_KEY
from sensor_state_data import (
    DeviceClass,
    DeviceKey,
    SensorDescription,
    SensorUpdate,
    SensorValue,
)
from sensor_state_data.data import (
    ATTR_HW_VERSION,
    ATTR_MANUFACTURER,
    ATTR_MODEL,
    ATTR_NAME,
    ATTR_SW_VERSION,
    SensorDeviceInfo,
)

from .parser import XIAOMIBluetoothDeviceData

__version__ = "0.1.0"

__all__ = [
    "XIAOMIBluetoothDeviceData",
    "SIGNAL_STRENGTH_KEY",
    "ATTR_HW_VERSION",
    "ATTR_MANUFACTURER",
    "ATTR_MODEL",
    "ATTR_NAME",
    "ATTR_SW_VERSION",
    "SIGNAL_STRENGTH_KEY",
    "SensorDescription",
    "SensorDeviceInfo",
    "DeviceClass",
    "DeviceKey",
    "SensorUpdate",
    "SensorDeviceInfo",
    "SensorValue",
]
