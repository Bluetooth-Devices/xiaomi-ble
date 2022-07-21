from bluetooth_sensor_state_data import BluetoothServiceInfo, DeviceClass, SensorUpdate
from sensor_state_data import DeviceKey, SensorDescription, SensorValue

from xiaomi-ble.parser import XIAOMIBluetoothDeviceData


def test_can_create():
    XIAOMIBluetoothDeviceData()


def test_sps():
    parser = XIAOMIBluetoothDeviceData()
    service_info = BluetoothServiceInfo(
        name="sps",
        manufacturer_data={2044: b"\xc7\x12\x00\xc8=V\x06"},
        service_uuids=["0000fff0-0000-1000-8000-00805f9b34fb"],
        address="aa:bb:cc:dd:ee:ff",
        rssi=-60,
        service_data={},
        source="local",
    )
    result = parser.update(service_info)
    assert result == SensorUpdate(
        title=None,
        devices={
            None: {"manufacturer": "XIAOMI", "model": "IBS-TH", "name": "IBS-TH EEFF"}
        },
        entity_descriptions={
            DeviceKey(key="battery", device_id=None): SensorDescription(
                device_key=DeviceKey(key="battery", device_id=None),
                name="Battery",
                device_class=DeviceClass.BATTERY,
                native_unit_of_measurement="%",
            ),
            DeviceKey(key="signal_strength", device_id=None): SensorDescription(
                device_key=DeviceKey(key="signal_strength", device_id=None),
                name="Signal Strength",
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
            DeviceKey(key="temperature", device_id=None): SensorDescription(
                device_key=DeviceKey(key="temperature", device_id=None),
                name="Temperature",
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            DeviceKey(key="humidity", device_id=None): SensorDescription(
                device_key=DeviceKey(key="humidity", device_id=None),
                name="Humidity",
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement="%",
            ),
        },
        entity_values={
            DeviceKey(key="battery", device_id=None): SensorValue(
                device_key=DeviceKey(key="battery", device_id=None), native_value=86
            ),
            DeviceKey(key="signal_strength", device_id=None): SensorValue(
                device_key=DeviceKey(key="signal_strength", device_id=None),
                native_value=-60,
            ),
            DeviceKey(key="temperature", device_id=None): SensorValue(
                device_key=DeviceKey(key="temperature", device_id=None),
                native_value=20.44,
            ),
            DeviceKey(key="humidity", device_id=None): SensorValue(
                device_key=DeviceKey(key="humidity", device_id=None), native_value=48.07
            ),
        },
    )


def test_ibbq_4():
    parser = XIAOMIBluetoothDeviceData()
    service_info = BluetoothServiceInfo(
        name="iBBQ",
        manufacturer_data={
            0: b"\x00\x000\xe2\x83}\xb5\x02\x04\x01\xfa\x00\x04\x01\xfa\x00"
        },
        service_uuids=["0000fff0-0000-1000-8000-00805f9b34fb"],
        address="aa:bb:cc:dd:ee:ff",
        rssi=-60,
        service_data={},
        source="local",
    )
    result = parser.update(service_info)
    assert result == SensorUpdate(
        title=None,
        devices={
            None: {"manufacturer": "XIAOMI", "model": "iBBQ-4", "name": "iBBQ EEFF"}
        },
        entity_descriptions={
            DeviceKey(key="signal_strength", device_id=None): SensorDescription(
                device_key=DeviceKey(key="signal_strength", device_id=None),
                name="Signal Strength",
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
            DeviceKey(key="temperature_probe_1", device_id=None): SensorDescription(
                device_key=DeviceKey(key="temperature_probe_1", device_id=None),
                name="Temperature " "Probe " "1",
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            DeviceKey(key="temperature_probe_2", device_id=None): SensorDescription(
                device_key=DeviceKey(key="temperature_probe_2", device_id=None),
                name="Temperature " "Probe " "2",
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            DeviceKey(key="temperature_probe_3", device_id=None): SensorDescription(
                device_key=DeviceKey(key="temperature_probe_3", device_id=None),
                name="Temperature " "Probe " "3",
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            DeviceKey(key="temperature_probe_4", device_id=None): SensorDescription(
                device_key=DeviceKey(key="temperature_probe_4", device_id=None),
                name="Temperature " "Probe " "4",
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
        },
        entity_values={
            DeviceKey(key="signal_strength", device_id=None): SensorValue(
                device_key=DeviceKey(key="signal_strength", device_id=None),
                native_value=-60,
            ),
            DeviceKey(key="temperature_probe_1", device_id=None): SensorValue(
                device_key=DeviceKey(key="temperature_probe_1", device_id=None),
                native_value=26.0,
            ),
            DeviceKey(key="temperature_probe_2", device_id=None): SensorValue(
                device_key=DeviceKey(key="temperature_probe_2", device_id=None),
                native_value=25.0,
            ),
            DeviceKey(key="temperature_probe_3", device_id=None): SensorValue(
                device_key=DeviceKey(key="temperature_probe_3", device_id=None),
                native_value=26.0,
            ),
            DeviceKey(key="temperature_probe_4", device_id=None): SensorValue(
                device_key=DeviceKey(key="temperature_probe_4", device_id=None),
                native_value=25.0,
            ),
        },
    )
