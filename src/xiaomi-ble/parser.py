"""Parser for Xiaomi BLE advertisements.

This file is shamelessly copied from the following repository:
https://github.com/Ernst79/bleparser/blob/c42ae922e1abed2720c7fac993777e1bd59c0c93/package/bleparser/xiaomi.py

MIT License applies.
"""
from __future__ import annotations

import logging
from struct import unpack

from bluetooth_sensor_state_data import BluetoothData
from home_assistant_bluetooth import BluetoothServiceInfo
from sensor_state_data import SensorLibrary

_LOGGER = logging.getLogger(__name__)

BBQ_LENGTH_TO_TYPE = {
    12: ("iBBQ-1", "<h"),
    14: ("iBBQ-2", "<HH"),
    18: ("iBBQ-4", "<hhhh"),
    22: ("iBBQ-6", "<hhhhhh"),
}

# ToDo Change Inkbrid parser to Xiaomi
XIAOMI_NAMES = {
    "sps": "IBS-TH",
    "tps": "IBS-TH2/P01B",
}


def convert_temperature(temp: float) -> float:
    """Temperature converter."""
    if temp > 0:
        return temp / 10.0
    return 0


def short_address(address: str) -> str:
    """Convert a Bluetooth address to a short address."""
    results = address.replace("-", ":").split(":")
    if len(results[-1]) == 2:
        return f"{results[-2].upper()}{results[-1].upper()}"
    return results[-1].upper()


class XIAOMIBluetoothDeviceData(BluetoothData):
    """Date update for XIAOMI Bluetooth devices."""

    def _start_update(self, service_info: BluetoothServiceInfo) -> None:
        """Update from BLE advertisement data."""
        _LOGGER.debug("Parsing Xiaomi BLE advertisement data: %s", service_info)
        manufacturer_data = service_info.manufacturer_data
        if not manufacturer_data:
            return
        last_id = list(manufacturer_data)[-1]
        data = int(last_id).to_bytes(2, byteorder="little") + manufacturer_data[last_id]
        self.set_device_manufacturer("XIAOMI")
        self._process_update(service_info.name, service_info.address, data)

    def _process_update(self, local_name: str, address: str, data: bytes) -> None:
        """Update from BLE advertisement data."""
        _LOGGER.debug("Parsing XIAOMI BLE advertisement data: %s", data)
        msg_length = len(data)

        if (device_type := XIAOMI_NAMES.get(local_name)) and msg_length == 9:
            self.set_device_type(device_type)
            self.set_device_name(f"{device_type} {short_address(address)}")
            (temp, hum) = unpack("<hH", data[0:4])
            bat = int.from_bytes(data[7:8], "little")
            if local_name == "sps":
                self.update_predefined_sensor(SensorLibrary.TEMPERATURE, temp / 100)
                self.update_predefined_sensor(SensorLibrary.HUMIDITY, hum / 100)
                self.update_predefined_sensor(SensorLibrary.BATTERY, bat)
            elif local_name == "tps":
                self.update_predefined_sensor(SensorLibrary.TEMPERATURE, temp / 100)
                self.update_predefined_sensor(SensorLibrary.BATTERY, bat)
            return

        if "ibbq" in local_name.lower() and (
            bbq_data := BBQ_LENGTH_TO_TYPE.get(msg_length)
        ):
            dev_type, unpack_str = bbq_data
            self.set_device_name(f"{local_name} {short_address(address)}")
            self.set_device_type(dev_type)
            xvalue = data[10:]
            for idx, temp in enumerate(unpack(unpack_str, xvalue)):
                num = idx + 1
                self.update_predefined_sensor(
                    SensorLibrary.TEMPERATURE,
                    convert_temperature(temp),
                    key=f"temperature_probe_{num}",
                    name=f"Temperature Probe {num}",
                )
