"""The tests for the Xiaomi ble parser."""
import logging
from unittest.mock import patch

import pytest
from home_assistant_bluetooth import BluetoothServiceInfo
from sensor_state_data import (
    BinarySensorDescription,
    BinarySensorDeviceClass,
    BinarySensorValue,
    DeviceClass,
    DeviceKey,
    Event,
    SensorDescription,
    SensorDeviceInfo,
    SensorUpdate,
    SensorValue,
    Units,
)

from xiaomi_ble.const import SERVICE_HHCCJCY10, SERVICE_SCALE1, SERVICE_SCALE2
from xiaomi_ble.parser import (
    EncryptionScheme,
    ExtendedBinarySensorDeviceClass,
    ExtendedSensorDeviceClass,
    XiaomiBluetoothDeviceData,
)

KEY_BATTERY = DeviceKey(key="battery", device_id=None)
KEY_BINARY_DOOR = DeviceKey(key="door", device_id=None)
KEY_BINARY_FINGERPRINT = DeviceKey(key="fingerprint", device_id=None)
KEY_BINARY_MOTION = DeviceKey(key="motion", device_id=None)
KEY_BINARY_LIGHT = DeviceKey(key="light", device_id=None)
KEY_BINARY_LOCK = DeviceKey(key="lock", device_id=None)
KEY_BINARY_OPENING = DeviceKey(key="opening", device_id=None)
KEY_BINARY_DOOR_LEFT_OPEN = DeviceKey(key="door_left_open", device_id=None)
KEY_BINARY_DEVICE_FORCIBLY_REMOVED = DeviceKey(
    key="device_forcibly_removed", device_id=None
)
KEY_BINARY_PRY_THE_DOOR = DeviceKey(key="pry_the_door", device_id=None)
KEY_BINARY_TOOTHBRUSH = DeviceKey(key="toothbrush", device_id=None)
KEY_CONDUCTIVITY = DeviceKey(key="conductivity", device_id=None)
KEY_COUNTER = DeviceKey(key="counter", device_id=None)
KEY_EVENT_BUTTON = DeviceKey(key="button", device_id=None)
KEY_EVENT_CUBE = DeviceKey(key="cube", device_id=None)
KEY_EVENT_DIMMER = DeviceKey(key="dimmer", device_id=None)
KEY_EVENT_FINGERPRINT = DeviceKey(key="fingerprint", device_id=None)
KEY_EVENT_MOTION = DeviceKey(key="motion", device_id=None)
KEY_HUMIDITY = DeviceKey(key="humidity", device_id=None)
KEY_ILLUMINANCE = DeviceKey(key="illuminance", device_id=None)
KEY_IMPEDANCE = DeviceKey(key="impedance", device_id=None)
KEY_KEY_ID = DeviceKey(key="key_id", device_id=None)
KEY_LOCK_METHOD = DeviceKey(key="lock_method", device_id=None)
KEY_MASS_NON_STABILIZED = DeviceKey(key="mass_non_stabilized", device_id=None)
KEY_MASS = DeviceKey(key="mass", device_id=None)
KEY_MOISTURE = DeviceKey(key="moisture", device_id=None)
KEY_POWER = DeviceKey(key="power", device_id=None)
KEY_SCORE = DeviceKey(key="score", device_id=None)
KEY_SIGNAL_STRENGTH = DeviceKey(key="signal_strength", device_id=None)
KEY_SMOKE = DeviceKey(key="smoke", device_id=None)
KEY_TEMPERATURE = DeviceKey(key="temperature", device_id=None)


@pytest.fixture(autouse=True)
def logging_config(caplog):
    caplog.set_level(logging.DEBUG)


@pytest.fixture(autouse=True)
def mock_platform():
    with patch("sys.platform") as p:
        p.return_value = "linux"
        yield p


def bytes_to_service_info(
    payload: bytes, address: str = "00:00:00:00:00:00"
) -> BluetoothServiceInfo:
    return BluetoothServiceInfo(
        name="Test",
        address=address,
        rssi=-60,
        manufacturer_data={},
        service_data={"0000fe95-0000-1000-8000-00805f9b34fb": payload},
        service_uuids=["0000fe95-0000-1000-8000-00805f9b34fb"],
        source="",
    )


def test_blank_advertisements_then_encrypted():
    """Test that we can reject empty payloads."""
    device = XiaomiBluetoothDeviceData()

    # First advertisement has a header but no payload, so we can't tell
    # if it has encryption
    data_string = b"0X[\x05\x02H<\xd48\xc1\xa4\x08"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:D4:3C:48")
    assert device.supported(advertisement)

    assert device.encryption_scheme == EncryptionScheme.NONE
    assert device.pending is True
    assert device.last_service_info is None

    # Second advertisement has encryption
    data_string = b"XX[\x05\x01H<\xd48\xc1\xa4\x9c\xf2U\xcf\xdd\x00\x00\x00/\xae/\xf2"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:D4:3C:48")
    device.update(advertisement)

    assert device.encryption_scheme == EncryptionScheme.MIBEACON_4_5
    assert device.pending is False  # type: ignore


def test_blank_advertisements_then_unencrypted():
    """Test that we can reject empty payloads."""

    # NOTE: THIS IS SYNTHETIC TEST DATA - i took a known unencrypted device and flipped
    # frctrl_object_include, then truncated it to not include the data payload

    device = XiaomiBluetoothDeviceData()

    # First advertisement has a header but no payload, so we can't tell
    # if it has encryption
    data_string = b"1 \x98\x00\x12\xf3Ok\x8d|\xc4\r"
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:6B:4F:F3")
    assert device.supported(advertisement)

    assert device.encryption_scheme == EncryptionScheme.NONE
    assert device.pending is True

    # Second advertisement has encryption
    data_string = b"q \x98\x00\x12\xf3Ok\x8d|\xc4\r\x04\x10\x02\xc4\x00"
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:6B:4F:F3")
    device.update(advertisement)

    assert device.encryption_scheme == EncryptionScheme.NONE
    assert device.pending is False


def test_blank_advertisements_then_encrypted_last_service_info():
    """Test that we can capture valid service info records"""
    device = XiaomiBluetoothDeviceData()

    # First advertisement has a header but no payload, so we can't tell
    # if it has encryption
    data_string = b"0X[\x05\x02H<\xd48\xc1\xa4\x08"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:D4:3C:48")
    assert device.supported(advertisement)

    assert device.last_service_info is None

    # Second advertisement has encryption
    data_string = b"XX[\x05\x01H<\xd48\xc1\xa4\x9c\xf2U\xcf\xdd\x00\x00\x00/\xae/\xf2"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:D4:3C:48")
    device.update(advertisement)

    assert device.last_service_info == advertisement


def test_blank_advertisements_then_unencrypted_last_service_info():
    """Test that we can capture valid service info records."""

    # NOTE: THIS IS SYNTHETIC TEST DATA - i took a known unencrypted device and flipped
    # frctrl_object_include, then truncated it to not include the data payload

    device = XiaomiBluetoothDeviceData()

    # First advertisement has a header but no payload, so we can't tell
    # if it has encryption
    data_string = b"1 \x98\x00\x12\xf3Ok\x8d|\xc4\r"
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:6B:4F:F3")
    assert device.supported(advertisement)

    assert device.last_service_info is None

    # Second advertisement has encryption
    data_string = b"q \x98\x00\x12\xf3Ok\x8d|\xc4\r\x04\x10\x02\xc4\x00"
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:6B:4F:F3")
    device.update(advertisement)

    assert device.last_service_info == advertisement


def test_encryption_needs_v2():
    """Test that we can detect what kind of encryption key a device needs."""
    data_string = b"X0\xb6\x03\xd2\x8b\x98\xc5A$\xf8\xc3I\x14vu~\x00\x00\x00\x99"
    advertisement = bytes_to_service_info(data_string, address="F8:24:41:C5:98:8B")

    device = XiaomiBluetoothDeviceData()

    assert device.supported(advertisement)
    assert device.encryption_scheme == EncryptionScheme.MIBEACON_LEGACY
    assert not device.bindkey_verified


def test_encryption_needs_v5():
    """Test that we can detect what kind of encryption key a device needs."""
    data_string = b"XXH\x0bh_\x124-XZ\x0b\x18A\xe2\xaa\x00\x0e\x00\xa4\x96O\xb5"
    advertisement = bytes_to_service_info(data_string, address="5A:58:2D:34:12:5F")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert device.encryption_scheme == EncryptionScheme.MIBEACON_4_5
    assert not device.bindkey_verified


def test_bindkey_wrong():
    """Test Xiaomi parser for RTCGQ02LM with wrong encryption key."""
    bindkey = "814aac74c4f17b6c1581e1ab87816b99"
    data_string = (
        b"XY\x8d\n\x17\x0f\xc4\xe0D\xefT|" b"\xc2z\\\x03\xa1\x00\x00\x00y\r\xf2X"
    )
    advertisement = bytes_to_service_info(data_string, address="54:EF:44:E0:C4:0F")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor C40F (RTCGQ02LM)",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor C40F",
                manufacturer="Xiaomi",
                model="RTCGQ02LM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_bindkey_verified_can_be_unset_v4():
    """Test Xiaomi parser for RTCGQ02LM with wrong encryption key."""
    bindkey = "814aac74c4f17b6c1581e1ab87816b99"
    data_string = (
        b"XY\x8d\n\x17\x0f\xc4\xe0D\xefT|" b"\xc2z\\\x03\xa1\x00\x00\x00y\r\xf2X"
    )
    advertisement = bytes_to_service_info(data_string, address="54:EF:44:E0:C4:0F")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    device.bindkey_verified = True

    assert device.supported(advertisement)
    assert not device.bindkey_verified


def test_bindkey_wrong_legacy():
    """Test Xiaomi parser for YLKG07YL with wrong encryption key."""
    bindkey = "b853075158487aa39a5b5ea9"
    data_string = b"X0\xb6\x03\xd2\x8b\x98\xc5A$\xf8\xc3I\x14vu~\x00\x00\x00\x99"
    advertisement = bytes_to_service_info(data_string, address="F8:24:41:C5:98:8B")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Dimmer Switch 988B (YLKG07YL/YLKG08YL)",
        devices={
            None: SensorDeviceInfo(
                name="Dimmer Switch 988B",
                manufacturer="Xiaomi",
                model="YLKG07YL/YLKG08YL",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V3 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )

    assert device.unhandled == {}


def test_bindkey_verified_can_be_unset_legacy():
    """Test Xiaomi parser for YLKG07YL with wrong encryption key."""
    bindkey = "b853075158487aa39a5b5ea9"
    data_string = b"X0\xb6\x03\xd2\x8b\x98\xc5A$\xf8\xc3I\x14vu~\x00\x00\x00\x99"
    advertisement = bytes_to_service_info(data_string, address="F8:24:41:C5:98:8B")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    device.bindkey_verified = True

    assert device.supported(advertisement)
    assert not device.bindkey_verified


def test_Xiaomi_LYWSDCGQ(caplog):
    """Test Xiaomi parser for LYWSDCGQ."""
    data_string = b"P \xaa\x01\xda!\x9354-X\r\x10\x04\xfe\x00H\x02"
    advertisement = bytes_to_service_info(data_string, address="58:2D:34:35:93:21")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert not device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 9321 (LYWSDCGQ)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 9321",
                manufacturer="Xiaomi",
                model="LYWSDCGQ",
                sw_version="Xiaomi (MiBeacon V2)",
                hw_version=None,
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            KEY_HUMIDITY: SensorDescription(
                device_key=KEY_HUMIDITY,
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                device_key=KEY_TEMPERATURE, name="Temperature", native_value=25.4
            ),
            KEY_HUMIDITY: SensorValue(
                device_key=KEY_HUMIDITY, name="Humidity", native_value=58.4
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_CGG1():
    """Test Xiaomi parser for CGG1."""
    bindkey = "814aac74c4f17b6c1581e1ab87816b99"
    data_string = b"XXH\x0bh_\x124-XZ\x0b\x18A\xe2\xaa\x00\x0e\x00\xa4\x96O\xb5"
    advertisement = bytes_to_service_info(data_string, address="5A:58:2D:34:12:5F")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 125F (CGG1-ENCRYPTED)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 125F",
                manufacturer="Xiaomi",
                model="CGG1-ENCRYPTED",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_HUMIDITY: SensorDescription(
                device_key=KEY_HUMIDITY,
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_HUMIDITY: SensorValue(
                name="Humidity", device_key=KEY_HUMIDITY, native_value=59.6
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_CGDK2():
    """Test Xiaomi parser for CGDK2."""
    data_string = b"XXo\x06\x07\x89 \x124-X_\x17m\xd5O\x02\x00\x00/\xa4S\xfa"
    bindkey = "a3bfe9853dd85a620debe3620caaa351"

    advertisement = bytes_to_service_info(data_string, address="58:2D:34:12:20:89")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 2089 (CGDK2)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 2089",
                manufacturer="Xiaomi",
                model="CGDK2",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=22.6
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_LYWSD02():
    """Test Xiaomi parser for LYWSD02."""


def test_Xiaomi_LYWSD03MMC():
    """Test Xiaomi parser for LYWSD03MMC without encryption."""
    data_string = b"P0[\x05\x03L\x94\xb48\xc1\xa4\r\x10\x04\x10\x01\xea\x01"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:B4:94:4C")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 944C (LYWSD03MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 944C",
                manufacturer="Xiaomi",
                model="LYWSD03MMC",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V3)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            KEY_HUMIDITY: SensorDescription(
                device_key=KEY_HUMIDITY,
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=27.2
            ),
            KEY_HUMIDITY: SensorValue(
                name="Humidity", device_key=KEY_HUMIDITY, native_value=49.0
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_LYWSD02MMC():
    """Test Xiaomi parser for LYWSD02MMC."""
    bindkey = "a115210eed7a88e50ad52662e732a9fb"
    data_string = b"XX\xe4\x16,\x84SV8\xc1\xa4+n\xf2\xe9\x12\x00\x00l\x88M\x9e"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:56:53:84")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 5384 (LYWSD02MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 5384",
                manufacturer="Xiaomi",
                model="LYWSD02MMC",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_HUMIDITY: SensorDescription(
                device_key=KEY_HUMIDITY,
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_HUMIDITY: SensorValue(
                name="Humidity", device_key=KEY_HUMIDITY, native_value=58
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_LYWSD02MMC_v2_temperature():
    """Test Xiaomi parser for LYWSD02MMC updated version temperature."""
    bindkey = "19b1c678ab0a8bc3dc77765f059188d4"
    data_string = b'HXB%) -\x8czv\xb7V\xa8*\x00x\xb8"N'
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:0E:FD:78")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor FD78 (LYWSD02MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor FD78",
                manufacturer="Xiaomi",
                model="LYWSD02MMC",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=26.10
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_LYWSD02MMC_v2_humidity():
    """Test Xiaomi parser for LYWSD02MMC updated version humidity."""
    bindkey = "19b1c678ab0a8bc3dc77765f059188d4"
    data_string = b"XXB%\x88x\xfd\x0e8\xc1\xa4\x05\xf6S\x8a\xa7*\x00b\xb1\xa9f"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:0E:FD:78")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor FD78 (LYWSD02MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor FD78",
                manufacturer="Xiaomi",
                model="LYWSD02MMC",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_HUMIDITY: SensorDescription(
                device_key=KEY_HUMIDITY,
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_HUMIDITY: SensorValue(
                name="Humidity", device_key=KEY_HUMIDITY, native_value=38
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_LYWSD03MMC_encrypted():
    """Test Xiaomi parser for LYWSD03MMC with encryption."""
    data_string = (
        b"XX[\x05P\xf4\x83\x028" b"\xc1\xa4\x95\xefXv<&\x00\x00\x97\xe2\xab\xb5"
    )
    bindkey = "e9ea895fac7cca6d30532432a516f3a8"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:02:83:F4")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 83F4 (LYWSD03MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 83F4",
                manufacturer="Xiaomi",
                model="LYWSD03MMC",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_HUMIDITY: SensorDescription(
                device_key=KEY_HUMIDITY,
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_HUMIDITY: SensorValue(
                name="Humidity", device_key=KEY_HUMIDITY, native_value=46
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_XMWSDJ04MMC():
    """Test Xiaomi parser for XMWSDJ04MMC with encryption."""
    bindkey = "b2cf9a553d53571b5657defd582d676e"
    data_string = b"HY\x03\x12\xa4\x1bwn|\x96\xad\xd7\x00\x00\x00\xf2\xbfT["
    advertisement = bytes_to_service_info(data_string, address="2C:11:65:25:70:04")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Thermometer 7004 (XMWSDJ04MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Thermometer 7004",
                manufacturer="Xiaomi",
                model="XMWSDJ04MMC",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_HUMIDITY: SensorDescription(
                device_key=KEY_HUMIDITY,
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_HUMIDITY: SensorValue(
                name="Humidity", device_key=KEY_HUMIDITY, native_value=45.0
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_XMMF01JQD():
    """Test Xiaomi parser for XMMF01JQD."""
    data_string = b"P0\xe1\x04\x8eT\xd3\xe60S\xe2\x01\x10\x03\x01\x00\x00"
    advertisement = bytes_to_service_info(data_string, address="E2:53:30:E6:D3:54")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Magic Cube D354 (XMMF01JQD)",
        devices={
            None: SensorDeviceInfo(
                name="Magic Cube D354",
                manufacturer="Xiaomi",
                model="XMMF01JQD",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V3)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            KEY_EVENT_CUBE: Event(
                device_key=KEY_EVENT_CUBE,
                name="Cube",
                event_type="rotate_left",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_CGC1():
    """Test Xiaomi parser for CGC1."""


def test_Xiaomi_CGD1():
    """Test Xiaomi parser for CGD1."""


def test_Xiaomi_CGP1W():
    """Test Xiaomi parser for CGP1W."""


def test_Xiaomi_MHO_C303():
    """Test Xiaomi parser for MHO-C303."""


def test_Xiaomi_MHO_C401():
    """Test Xiaomi parser for MHO-C401."""


def test_Xiaomi_JQJCY01YM1():
    """Test Xiaomi parser for JQJCY01YM."""


def test_Xiaomi_JTYJGD03MI_smoke():
    """Test Xiaomi parser for JTYJGD03MI."""
    bindkey = "5b51a7c91cde6707c9ef18dfda143a58"
    data_string = (
        b"XY\x97\tf\xbc\x9c\xe3D\xefT\x01" b"\x08\x12\x05\x00\x00\x00q^\xbe\x90"
    )
    advertisement = bytes_to_service_info(data_string, address="54:EF:44:E3:9C:BC")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Smoke Detector 9CBC (JTYJGD03MI)",
        devices={
            None: SensorDeviceInfo(
                name="Smoke Detector 9CBC",
                manufacturer="Xiaomi",
                model="JTYJGD03MI",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_SMOKE: BinarySensorDescription(
                device_key=KEY_SMOKE,
                device_class=BinarySensorDeviceClass.SMOKE,
            ),
        },
        binary_entity_values={
            KEY_SMOKE: BinarySensorValue(
                name="Smoke", device_key=KEY_SMOKE, native_value=True
            ),
        },
    )


def test_Xiaomi_JTYJGD03MI_press():
    """Test Xiaomi parser for JTYJGD03MI."""
    bindkey = "5b51a7c91cde6707c9ef18dfda143a58"
    data_string = (
        b'XY\x97\td\xbc\x9c\xe3D\xefT" `' b"\x88\xfd\x00\x00\x00\x00:\x14\x8f\xb3"
    )
    advertisement = bytes_to_service_info(data_string, address="54:EF:44:E3:9C:BC")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Smoke Detector 9CBC (JTYJGD03MI)",
        devices={
            None: SensorDeviceInfo(
                name="Smoke Detector 9CBC",
                manufacturer="Xiaomi",
                model="JTYJGD03MI",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            KEY_EVENT_BUTTON: Event(
                device_key=KEY_EVENT_BUTTON,
                name="Button",
                event_type="press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_HHCCJCY01():
    """Test Xiaomi parser for HHCCJCY01."""
    data_string = b"q \x98\x00\x12\xf3Ok\x8d|\xc4\r\x04\x10\x02\xc4\x00"
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:6B:4F:F3")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Plant Sensor 4FF3 (HHCCJCY01)",
        devices={
            None: SensorDeviceInfo(
                name="Plant Sensor 4FF3",
                manufacturer="Xiaomi",
                model="HHCCJCY01",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=19.6
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_HHCCJCY01_all_values():
    """Test Xiaomi parser for HHCCJCY01."""

    device = XiaomiBluetoothDeviceData()
    device.update(
        bytes_to_service_info(
            b"q \x98\x00fz>j\x8d|\xc4\r\x07\x10\x03\x00\x00\x00",
            address="C4:7C:8D:6A:3E:7A",
        )
    )
    device.update(
        bytes_to_service_info(
            b"q \x98\x00hz>j\x8d|\xc4\r\t\x10\x02W\x02", address="C4:7C:8D:6A:3E:7A"
        )
    )
    device.update(
        bytes_to_service_info(
            b"q \x98\x00Gz>j\x8d|\xc4\r\x08\x10\x01@", address="C4:7C:8D:6A:3E:7A"
        )
    )
    assert device.update(
        bytes_to_service_info(
            b"q \x98\x00iz>j\x8d|\xc4\r\x04\x10\x02\xf4\x00",
            address="C4:7C:8D:6A:3E:7A",
        )
    ) == SensorUpdate(
        title="Plant Sensor 3E7A (HHCCJCY01)",
        devices={
            None: SensorDeviceInfo(
                name="Plant Sensor 3E7A",
                manufacturer="Xiaomi",
                model="HHCCJCY01",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement=Units.TEMP_CELSIUS,
            ),
            KEY_ILLUMINANCE: SensorDescription(
                device_key=KEY_ILLUMINANCE,
                device_class=DeviceClass.ILLUMINANCE,
                native_unit_of_measurement=Units.LIGHT_LUX,
            ),
            KEY_CONDUCTIVITY: SensorDescription(
                device_key=KEY_CONDUCTIVITY,
                device_class=DeviceClass.CONDUCTIVITY,
                native_unit_of_measurement=Units.CONDUCTIVITY,
            ),
            KEY_MOISTURE: SensorDescription(
                device_key=KEY_MOISTURE,
                device_class=DeviceClass.MOISTURE,
                native_unit_of_measurement=Units.PERCENTAGE,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=24.4
            ),
            KEY_ILLUMINANCE: SensorValue(
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=0
            ),
            KEY_CONDUCTIVITY: SensorValue(
                name="Conductivity", device_key=KEY_CONDUCTIVITY, native_value=599
            ),
            KEY_MOISTURE: SensorValue(
                name="Moisture", device_key=KEY_MOISTURE, native_value=64
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_HHCCJCY10():
    """Test Xiaomi parser for HHCCJCY10."""

    device = XiaomiBluetoothDeviceData()
    assert device.update(
        BluetoothServiceInfo(
            name="Test",
            address="DC:23:4D:E5:5B:FC",
            rssi=-60,
            manufacturer_data={},
            service_data={SERVICE_HHCCJCY10: b"\x0e\x00n\x014\xa4(\x00["},
            service_uuids=[SERVICE_HHCCJCY10],
            source="",
        )
    ) == SensorUpdate(
        title="Plant Sensor 5BFC (HHCCJCY10)",
        devices={
            None: SensorDeviceInfo(
                name="Plant Sensor 5BFC",
                manufacturer="HHCC Plant Technology Co. Ltd",
                model="HHCCJCY10",
                hw_version=None,
                sw_version=None,
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement=Units.TEMP_CELSIUS,
            ),
            KEY_ILLUMINANCE: SensorDescription(
                device_key=KEY_ILLUMINANCE,
                device_class=DeviceClass.ILLUMINANCE,
                native_unit_of_measurement=Units.LIGHT_LUX,
            ),
            KEY_CONDUCTIVITY: SensorDescription(
                device_key=KEY_CONDUCTIVITY,
                device_class=DeviceClass.CONDUCTIVITY,
                native_unit_of_measurement=Units.CONDUCTIVITY,
            ),
            KEY_MOISTURE: SensorDescription(
                device_key=KEY_MOISTURE,
                device_class=DeviceClass.MOISTURE,
                native_unit_of_measurement=Units.PERCENTAGE,
            ),
            KEY_BATTERY: SensorDescription(
                device_key=KEY_BATTERY,
                device_class=DeviceClass.BATTERY,
                native_unit_of_measurement=Units.PERCENTAGE,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=11.0
            ),
            KEY_ILLUMINANCE: SensorValue(
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=79012
            ),
            KEY_CONDUCTIVITY: SensorValue(
                name="Conductivity", device_key=KEY_CONDUCTIVITY, native_value=91
            ),
            KEY_MOISTURE: SensorValue(
                name="Moisture", device_key=KEY_MOISTURE, native_value=14
            ),
            KEY_BATTERY: SensorValue(
                name="Battery", device_key=KEY_BATTERY, native_value=40
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_Scale1():
    """Test Xiaomi parser for Mi Smart Scale (MiScale V1)"""
    data_string = b"\x22\x9e\x43\xe5\x07\x04\x0b\x10\x13\x01"

    device = XiaomiBluetoothDeviceData()
    assert device.update(
        BluetoothServiceInfo(
            name="MISCA",
            address="50:FB:19:1B:B5:DC",
            rssi=-60,
            manufacturer_data={},
            service_data={SERVICE_SCALE1: data_string},
            service_uuids=[SERVICE_SCALE1],
            source="",
        )
    ) == SensorUpdate(
        title="Mi Smart Scale (B5DC)",
        devices={
            None: SensorDeviceInfo(
                name="Mi Smart Scale (B5DC)",
                manufacturer="Xiaomi",
                model="XMTZC01HM/XMTZC04HM",
                hw_version=None,
                sw_version=None,
            )
        },
        entity_descriptions={
            KEY_MASS_NON_STABILIZED: SensorDescription(
                device_key=KEY_MASS_NON_STABILIZED,
                device_class=DeviceClass.MASS_NON_STABILIZED,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_MASS: SensorDescription(
                device_key=KEY_MASS,
                device_class=DeviceClass.MASS,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_MASS_NON_STABILIZED: SensorValue(
                name="Mass Non Stabilized",
                device_key=KEY_MASS_NON_STABILIZED,
                native_value=86.55,
            ),
            KEY_MASS: SensorValue(
                name="Mass",
                device_key=KEY_MASS,
                native_value=86.55,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_Scale1_mass_removed():
    """Test Xiaomi parser for Mi Smart Scale (MiScale V1) mass removed"""
    data_string = b"\xa2 D\xb2\x07\x01\x01\n\x1a\x15"

    device = XiaomiBluetoothDeviceData()
    assert device.update(
        BluetoothServiceInfo(
            name="MISCA",
            address="50:FB:19:1B:B5:DC",
            rssi=-60,
            manufacturer_data={},
            service_data={SERVICE_SCALE1: data_string},
            service_uuids=[SERVICE_SCALE1],
            source="",
        )
    ) == SensorUpdate(
        title="Mi Smart Scale (B5DC)",
        devices={
            None: SensorDeviceInfo(
                name="Mi Smart Scale (B5DC)",
                manufacturer="Xiaomi",
                model="XMTZC01HM/XMTZC04HM",
                hw_version=None,
                sw_version=None,
            )
        },
        entity_descriptions={
            KEY_MASS_NON_STABILIZED: SensorDescription(
                device_key=KEY_MASS_NON_STABILIZED,
                device_class=DeviceClass.MASS_NON_STABILIZED,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_MASS_NON_STABILIZED: SensorValue(
                name="Mass Non Stabilized",
                device_key=KEY_MASS_NON_STABILIZED,
                native_value=87.2,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_Scale1_non_stabilized():
    """Test Xiaomi parser for Mi Smart Scale (MiScale V1) non stabilized"""
    data_string = b"\x82\x14\x00\xe5\x07\x04\x0b\x10\x17\x08"

    device = XiaomiBluetoothDeviceData()
    assert device.update(
        BluetoothServiceInfo(
            name="MISCA",
            address="50:FB:19:1B:B5:DC",
            rssi=-60,
            manufacturer_data={},
            service_data={SERVICE_SCALE1: data_string},
            service_uuids=[SERVICE_SCALE1],
            source="",
        )
    ) == SensorUpdate(
        title="Mi Smart Scale (B5DC)",
        devices={
            None: SensorDeviceInfo(
                name="Mi Smart Scale (B5DC)",
                manufacturer="Xiaomi",
                model="XMTZC01HM/XMTZC04HM",
                hw_version=None,
                sw_version=None,
            )
        },
        entity_descriptions={
            KEY_MASS_NON_STABILIZED: SensorDescription(
                device_key=KEY_MASS_NON_STABILIZED,
                device_class=DeviceClass.MASS_NON_STABILIZED,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_MASS_NON_STABILIZED: SensorValue(
                name="Mass Non Stabilized",
                device_key=KEY_MASS_NON_STABILIZED,
                native_value=0.1,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_Scale2():
    """Test Xiaomi parser for Mi Body Composition Scale (MiScale V2)"""
    data_string = b"\x02&\xb2\x07\x05\x04\x0f\x02\x01\xac\x01\x86B"

    device = XiaomiBluetoothDeviceData()
    assert device.update(
        BluetoothServiceInfo(
            name="MIBFS",
            address="50:FB:19:1B:B5:DC",
            rssi=-60,
            manufacturer_data={},
            service_data={SERVICE_SCALE2: data_string},
            service_uuids=[SERVICE_SCALE2],
            source="",
        )
    ) == SensorUpdate(
        title="Mi Body Composition Scale (B5DC)",
        devices={
            None: SensorDeviceInfo(
                name="Mi Body Composition Scale (B5DC)",
                manufacturer="Xiaomi",
                model="XMTZC02HM/XMTZC05HM/NUN4049CN",
                hw_version=None,
                sw_version=None,
            )
        },
        entity_descriptions={
            KEY_MASS_NON_STABILIZED: SensorDescription(
                device_key=KEY_MASS_NON_STABILIZED,
                device_class=DeviceClass.MASS_NON_STABILIZED,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_MASS: SensorDescription(
                device_key=KEY_MASS,
                device_class=DeviceClass.MASS,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_IMPEDANCE: SensorDescription(
                device_key=KEY_IMPEDANCE,
                device_class=DeviceClass.IMPEDANCE,
                native_unit_of_measurement=Units.OHM,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_MASS_NON_STABILIZED: SensorValue(
                name="Mass Non Stabilized",
                device_key=KEY_MASS_NON_STABILIZED,
                native_value=85.15,
            ),
            KEY_MASS: SensorValue(
                name="Mass",
                device_key=KEY_MASS,
                native_value=85.15,
            ),
            KEY_IMPEDANCE: SensorValue(
                name="Impedance", device_key=KEY_IMPEDANCE, native_value=428
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_Scale2_non_stabilized():
    """Test Xiaomi parser for Mi Body Composition Scale (MiScale v2) (non stabilized)"""
    data_string = b"\x02\x04\xb2\x07\x01\x01\x12\x10\x1a\x00\x00\xa8R"

    device = XiaomiBluetoothDeviceData()
    assert device.update(
        BluetoothServiceInfo(
            name="MIBFS",
            address="50:FB:19:1B:B5:DC",
            rssi=-60,
            manufacturer_data={},
            service_data={SERVICE_SCALE2: data_string},
            service_uuids=[SERVICE_SCALE2],
            source="",
        )
    ) == SensorUpdate(
        title="Mi Body Composition Scale (B5DC)",
        devices={
            None: SensorDeviceInfo(
                name="Mi Body Composition Scale (B5DC)",
                manufacturer="Xiaomi",
                model="XMTZC02HM/XMTZC05HM/NUN4049CN",
                hw_version=None,
                sw_version=None,
            )
        },
        entity_descriptions={
            KEY_MASS_NON_STABILIZED: SensorDescription(
                device_key=KEY_MASS_NON_STABILIZED,
                device_class=DeviceClass.MASS_NON_STABILIZED,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_MASS_NON_STABILIZED: SensorValue(
                name="Mass Non Stabilized",
                device_key=KEY_MASS_NON_STABILIZED,
                native_value=105.8,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_GCLS002():
    """Test Xiaomi parser for GCLS002 / HHCCJCY09."""
    data_string = b"q \xbc\x03\xcd>Ym\x8d|\xc4\r\x04\x10\x02<\x01"
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:6D:59:3E")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Grow Care Garden 593E (GCLS002)",
        devices={
            None: SensorDeviceInfo(
                name="Grow Care Garden 593E",
                manufacturer="Xiaomi",
                model="GCLS002",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=31.6
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_HHCCPOT002():
    """Test Xiaomi parser for HHCCPOT002."""


def test_Xiaomi_WX08ZM():
    """Test Xiaomi parser for WX08ZM."""


def test_Xiaomi_MCCGQ02HL():
    """Test Xiaomi parser for MCCGQ02HL."""
    data_string = b"XX\x8b\t\xa3\xae!\x81\xec\xaa\xe4\x0e,U<\x04\x00\x00\xd2\x8aP\x0c"
    advertisement = bytes_to_service_info(data_string, address="E4:AA:EC:81:21:AE")
    bindkey = "017e52d2684779298709b117c0a75a7b"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor 21AE (MCCGQ02HL)",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor 21AE",
                manufacturer="Xiaomi",
                model="MCCGQ02HL",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_OPENING: BinarySensorDescription(
                device_key=KEY_BINARY_OPENING,
                device_class=BinarySensorDeviceClass.OPENING,
            ),
            KEY_BINARY_DOOR_LEFT_OPEN: BinarySensorDescription(
                device_key=KEY_BINARY_DOOR_LEFT_OPEN,
                device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OPENING: BinarySensorValue(
                device_key=KEY_BINARY_OPENING, name="Opening", native_value=True
            ),
            KEY_BINARY_DOOR_LEFT_OPEN: BinarySensorValue(
                device_key=KEY_BINARY_DOOR_LEFT_OPEN,
                name="Door left open",
                native_value=True,
            ),
        },
    )


def test_Xiaomi_CGH1():
    """Test Xiaomi parser for CGH1."""


def test_Xiaomi_YM_K1501():
    """Test Xiaomi parser for YM-K1501."""


def test_Xiaomi_V_SK152():
    """Test Xiaomi parser for V-SK152."""


def test_Xiaomi_SJWS01LM():
    """Test Xiaomi parser for SJWS01LM."""


def test_Xiaomi_MJYD02YL():
    """Test Xiaomi parser for MJYD02YL."""


def test_Xiaomi_MUE4094RT():
    """Test Xiaomi parser for MUE4094RT."""
    # MUE4094RT only sends motion detected as an event.
    data_string = b"@0\xdd\x03$\x03\x00\x01\x01"
    advertisement = bytes_to_service_info(data_string, address="DE:70:E8:B2:39:0C")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Nightlight 390C (MUE4094RT)",
        devices={
            None: SensorDeviceInfo(
                name="Nightlight 390C",
                manufacturer="Xiaomi",
                model="MUE4094RT",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V3)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            KEY_EVENT_MOTION: Event(
                device_key=KEY_EVENT_MOTION,
                name="Motion",
                event_type="motion_detected",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_CGPR1():
    """Test Xiaomi parser for CGPR1."""


def test_Xiaomi_MMC_T201_1():
    """Test Xiaomi parser for MMC-T201-1."""
    data_string = b'p"\xdb\x00o\xc1o\xdd\xf9\x81\x00\t\x00 \x05\xc6\rc\rQ'
    advertisement = bytes_to_service_info(data_string, address="00:81:F9:DD:6F:C1")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Baby Thermometer 6FC1 (MMC-T201-1)",
        devices={
            None: SensorDeviceInfo(
                name="Baby Thermometer 6FC1",
                manufacturer="Xiaomi",
                model="MMC-T201-1",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            KEY_BATTERY: SensorDescription(
                device_key=KEY_BATTERY,
                device_class=DeviceClass.BATTERY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_BATTERY: SensorValue(
                name="Battery", device_key=KEY_BATTERY, native_value=81
            ),
            KEY_TEMPERATURE: SensorValue(
                name="Temperature",
                device_key=KEY_TEMPERATURE,
                native_value=36.87199806168224,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_MMC_W505():
    """Test Xiaomi parser for MMC-W505."""
    data_string = b'p"\x91\x03\x0f\xdb\xabS\x18$\xd0\t\n\x00\x02u\r\x07'
    advertisement = bytes_to_service_info(data_string, address="D0:24:18:53:AB:DB")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Body Thermometer ABDB (MMC-W505)",
        devices={
            None: SensorDeviceInfo(
                name="Body Thermometer ABDB",
                manufacturer="Xiaomi",
                model="MMC-W505",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement="°C",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature",
                device_key=KEY_TEMPERATURE,
                native_value=34.45,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_M1S_T500():
    """Test Xiaomi parser for M1S-T500."""
    data_string = b"q0\x89\x047\x11[\x17Cq\xe6\t\x10\x00\x02\x00\x03"
    advertisement = bytes_to_service_info(data_string, address="E6:71:43:17:5B:11")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Smart Toothbrush 5B11 (M1S-T500)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Toothbrush 5B11",
                manufacturer="Xiaomi",
                model="M1S-T500",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V3)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
            KEY_COUNTER: SensorDescription(
                device_key=KEY_COUNTER,
                device_class=ExtendedSensorDeviceClass.COUNTER,
                native_unit_of_measurement="s",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
            KEY_COUNTER: SensorValue(
                name="Counter", device_key=KEY_COUNTER, native_value=3
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_TOOTHBRUSH: BinarySensorDescription(
                device_key=KEY_BINARY_TOOTHBRUSH,
                device_class=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            ),
        },
        binary_entity_values={
            KEY_BINARY_TOOTHBRUSH: BinarySensorValue(
                device_key=KEY_BINARY_TOOTHBRUSH, name="Toothbrush", native_value=True
            ),
        },
    )


def test_Xiaomi_T700():
    """Test Xiaomi parser for T700."""
    bindkey = "1330b99cded13258acc391627e9771f7"
    data_string = (
        b"\x48\x58\x06\x08\xc9H\x0e\xf1\x12\x81\x07\x973\xfc\x14\x00\x00VD\xdbA"
    )
    advertisement = bytes_to_service_info(data_string, address="ED:DE:34:3F:48:0C")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Smart Toothbrush 480C (T700)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Toothbrush 480C",
                manufacturer="Xiaomi",
                model="T700",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
            KEY_SCORE: SensorDescription(
                device_key=KEY_SCORE,
                device_class=ExtendedSensorDeviceClass.SCORE,
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
            KEY_SCORE: SensorValue(name="Score", device_key=KEY_SCORE, native_value=83),
        },
        binary_entity_descriptions={
            KEY_BINARY_TOOTHBRUSH: BinarySensorDescription(
                device_key=KEY_BINARY_TOOTHBRUSH,
                device_class=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            ),
        },
        binary_entity_values={
            KEY_BINARY_TOOTHBRUSH: BinarySensorValue(
                device_key=KEY_BINARY_TOOTHBRUSH, name="Toothbrush", native_value=False
            ),
        },
    )


def test_Xiaomi_ZNMS16LM_fingerprint():
    """Test Xiaomi parser for ZNMS16LM."""
    data_string = (
        b"PD\x9e\x06B\x91\x8a\xebD\x1f\xd7" b"\x06\x00\x05\xff\xff\xff\xff\x00"
    )
    advertisement = bytes_to_service_info(data_string, address="D7:1F:44:EB:8A:91")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door Lock 8A91 (ZNMS16LM)",
        devices={
            None: SensorDeviceInfo(
                name="Door Lock 8A91",
                manufacturer="Xiaomi",
                model="ZNMS16LM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
            KEY_KEY_ID: SensorDescription(
                device_key=KEY_KEY_ID,
                device_class=ExtendedSensorDeviceClass.KEY_ID,
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
            KEY_KEY_ID: SensorValue(
                name="Key id", device_key=KEY_KEY_ID, native_value="unknown operator"
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_FINGERPRINT: BinarySensorDescription(
                device_key=KEY_BINARY_FINGERPRINT,
                device_class=ExtendedBinarySensorDeviceClass.FINGERPRINT,
            ),
        },
        binary_entity_values={
            KEY_BINARY_FINGERPRINT: BinarySensorValue(
                device_key=KEY_BINARY_FINGERPRINT, name="Fingerprint", native_value=True
            ),
        },
        events={
            KEY_EVENT_FINGERPRINT: Event(
                device_key=KEY_EVENT_FINGERPRINT,
                name="Fingerprint",
                event_type="match_successful",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_ZNMS16LM_lock():
    """Test Xiaomi parser for ZNMS16LM."""
    data_string = b"PD\x9e\x06C\x91\x8a\xebD\x1f\xd7\x0b\x00\t" b" \x02\x00\x01\x80|D/a"
    advertisement = bytes_to_service_info(data_string, address="D7:1F:44:EB:8A:91")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified

    assert device.update(advertisement) == SensorUpdate(
        title="Door Lock 8A91 (ZNMS16LM)",
        devices={
            None: SensorDeviceInfo(
                name="Door Lock 8A91",
                manufacturer="Xiaomi",
                model="ZNMS16LM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
            KEY_LOCK_METHOD: SensorDescription(
                device_key=KEY_LOCK_METHOD,
                device_class=ExtendedSensorDeviceClass.LOCK_METHOD,
            ),
            KEY_KEY_ID: SensorDescription(
                device_key=KEY_KEY_ID,
                device_class=ExtendedSensorDeviceClass.KEY_ID,
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
            KEY_LOCK_METHOD: SensorValue(
                name="Lock method",
                device_key=KEY_LOCK_METHOD,
                native_value="biometrics",
            ),
            KEY_KEY_ID: SensorValue(
                name="Key id",
                device_key=KEY_KEY_ID,
                native_value="Fingerprint key id 2",
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_LOCK: BinarySensorDescription(
                device_key=KEY_BINARY_LOCK,
                device_class=BinarySensorDeviceClass.LOCK,
            ),
        },
        binary_entity_values={
            KEY_BINARY_LOCK: BinarySensorValue(
                device_key=KEY_BINARY_LOCK, name="Lock", native_value=True
            ),
        },
        events={
            DeviceKey(key="lock", device_id=None): Event(
                device_key=DeviceKey(key="lock", device_id=None),
                name="Lock",
                event_type="unlock_outside_the_door",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_Lockin_SV40_lock():
    """Test Xiaomi parser for Locking SV40."""
    bindkey = "54d84797cb77f9538b224b305c877d1e"
    data_string = (
        b"\x48\x55\xc2\x11\x16\x50\x68\xb6\xfe\x3c\x87"
        b"\x80\x95\xc8\xa5\x83\x4f\x00\x00\x00\x46\x32\x21\xc6"
    )
    advertisement = bytes_to_service_info(data_string, address="98:0C:33:A3:04:3D")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door Lock 043D (Lockin-SV40)",
        devices={
            None: SensorDeviceInfo(
                name="Door Lock 043D",
                manufacturer="Xiaomi",
                model="Lockin-SV40",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
            KEY_LOCK_METHOD: SensorDescription(
                device_key=KEY_LOCK_METHOD,
                device_class=ExtendedSensorDeviceClass.LOCK_METHOD,
            ),
            KEY_KEY_ID: SensorDescription(
                device_key=KEY_KEY_ID,
                device_class=ExtendedSensorDeviceClass.KEY_ID,
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
            KEY_LOCK_METHOD: SensorValue(
                name="Lock method", device_key=KEY_LOCK_METHOD, native_value="automatic"
            ),
            KEY_KEY_ID: SensorValue(
                name="Key id", device_key=KEY_KEY_ID, native_value="administrator"
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_LOCK: BinarySensorDescription(
                device_key=KEY_BINARY_LOCK,
                device_class=BinarySensorDeviceClass.LOCK,
            ),
        },
        binary_entity_values={
            KEY_BINARY_LOCK: BinarySensorValue(
                device_key=KEY_BINARY_LOCK, name="Lock", native_value=True
            ),
        },
        events={
            DeviceKey(key="lock", device_id=None): Event(
                device_key=DeviceKey(key="lock", device_id=None),
                name="Lock",
                event_type="unlock_inside_the_door",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_Lockin_SV40_door():
    """Test Xiaomi parser for Locking SV40."""
    bindkey = "54d84797cb77f9538b224b305c877d1e"
    data_string = (
        b"\x48\x55\xc2\x11\x14\x4e\x28\x70\x32"
        b"\x76\xfc\xcd\x3d\x00\x00\x00\x80\xe7\x22\x80"
    )
    advertisement = bytes_to_service_info(data_string, address="98:0C:33:A3:04:3D")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door Lock 043D (Lockin-SV40)",
        devices={
            None: SensorDeviceInfo(
                name="Door Lock 043D",
                manufacturer="Xiaomi",
                model="Lockin-SV40",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_DOOR: BinarySensorDescription(
                device_key=KEY_BINARY_DOOR,
                device_class=BinarySensorDeviceClass.DOOR,
            ),
            KEY_BINARY_DOOR_LEFT_OPEN: BinarySensorDescription(
                device_key=KEY_BINARY_DOOR_LEFT_OPEN,
                device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            ),
            KEY_BINARY_PRY_THE_DOOR: BinarySensorDescription(
                device_key=KEY_BINARY_PRY_THE_DOOR,
                device_class=ExtendedBinarySensorDeviceClass.PRY_THE_DOOR,
            ),
        },
        binary_entity_values={
            KEY_BINARY_DOOR: BinarySensorValue(
                device_key=KEY_BINARY_DOOR, name="Door", native_value=False
            ),
            KEY_BINARY_DOOR_LEFT_OPEN: BinarySensorValue(
                device_key=KEY_BINARY_DOOR_LEFT_OPEN,
                name="Door left open",
                native_value=False,
            ),
            KEY_BINARY_PRY_THE_DOOR: BinarySensorValue(
                device_key=KEY_BINARY_PRY_THE_DOOR,
                name="Pry the door",
                native_value=False,
            ),
        },
    )


def test_Xiaomi_YLAI003():
    """Test Xiaomi parser for YLAI003."""


def test_Xiaomi_YLYK01YL():
    """Test Xiaomi parser for YLYK01YL."""
    data_string = b"P0S\x01?tP\xe9A$\xf8\x01\x10\x03\x00\x00\x00"
    advertisement = bytes_to_service_info(data_string, address="F8:24:41:E9:50:74")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Remote Control 5074 (YLYK01YL)",
        devices={
            None: SensorDeviceInfo(
                name="Remote Control 5074",
                manufacturer="Xiaomi",
                model="YLYK01YL",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V3)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_POWER: BinarySensorDescription(
                device_key=KEY_POWER,
                device_class=BinarySensorDeviceClass.POWER,
            ),
        },
        binary_entity_values={
            KEY_POWER: BinarySensorValue(
                name="Power", device_key=KEY_POWER, native_value=True
            ),
        },
        events={
            DeviceKey(key="button_on", device_id=None): Event(
                device_key=DeviceKey(key="button_on", device_id=None),
                name="Button On",
                event_type="press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_YLYK01YL_FANCL():
    """Test Xiaomi parser for YLYK01YL-FANCL."""


def test_Xiaomi_YLYK01YL_VENFAN():
    """Test Xiaomi parser for YLYK01YL-VENFAN."""


def test_Xiaomi_YLYB01YL_BHFRC():
    """Test Xiaomi parser for YLYB01YL-BHFRC."""


def test_Xiaomi_YLKG07YL_press():
    """Test Xiaomi parser for YLKG07YL, YLKG08YL while pressing dimmer (no rotation)."""
    bindkey = "b853075158487ca39a5b5ea9"
    data_string = b"X0\xb6\x03\xd2\x8b\x98\xc5A$\xf8\xc3I\x14vu~\x00\x00\x00\x99"
    advertisement = bytes_to_service_info(data_string, address="F8:24:41:C5:98:8B")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Dimmer Switch 988B (YLKG07YL/YLKG08YL)",
        devices={
            None: SensorDeviceInfo(
                name="Dimmer Switch 988B",
                manufacturer="Xiaomi",
                model="YLKG07YL/YLKG08YL",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V3 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            KEY_EVENT_DIMMER: Event(
                device_key=KEY_EVENT_DIMMER,
                name="Dimmer",
                event_type="press",
                event_properties={"number_of_presses": 1},
            ),
        },
    )


def test_Xiaomi_YLKG07YL_rotate():
    """Test Xiaomi parser for YLKG07YL, YLKG08YL while rotating dimmer."""
    data_string = b"X0\xb6\x036\x8b\x98\xc5A$\xf8\x8b\xb8\xf2f" b"\x13Q\x00\x00\x00\xd6"
    advertisement = bytes_to_service_info(data_string, address="F8:24:41:C5:98:8B")
    bindkey = "b853075158487ca39a5b5ea9"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Dimmer Switch 988B (YLKG07YL/YLKG08YL)",
        devices={
            None: SensorDeviceInfo(
                name="Dimmer Switch 988B",
                manufacturer="Xiaomi",
                model="YLKG07YL/YLKG08YL",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V3 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            KEY_EVENT_DIMMER: Event(
                device_key=KEY_EVENT_DIMMER,
                name="Dimmer",
                event_type="rotate_left",
                event_properties={"steps": 1},
            ),
        },
    )


def test_Xiaomi_K9B():
    """Test Xiaomi parser for K9B."""


def test_Xiaomi_HS1BB_MI_obj4803():
    """Test Xiaomi parser for Linptech HS1BB(MI) battery (4803)."""
    data_string = b"XY\xeb*\x9e\xe9\x8e\x058\xc1\xa4\xd0z\xd3\xe38\x00\x003c]\x10"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:05:8E:E9")
    bindkey = "7475a4a77584401780ffc3ee62dd353c"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor 8EE9 (HS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor 8EE9",
                manufacturer="Xiaomi",
                model="HS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_BATTERY: SensorDescription(
                device_key=KEY_BATTERY,
                device_class=DeviceClass.BATTERY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_BATTERY: SensorValue(
                name="Battery", device_key=KEY_BATTERY, native_value=100
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_HS1BB_MI_obj4818():
    """Test Xiaomi parser for Linptech HS1BB(MI) no motion time (4818)."""
    data_string = b"XY\xeb*\xc1\xe9\x8e\x058\xc1\xa4\x07YS\x0f\x8d8\x00\x00\xb7zp\xf8"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:05:8E:E9")
    bindkey = "7475a4a77584401780ffc3ee62dd353c"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor 8EE9 (HS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor 8EE9",
                manufacturer="Xiaomi",
                model="HS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_MOTION: BinarySensorDescription(
                device_key=KEY_BINARY_MOTION,
                device_class=BinarySensorDeviceClass.MOTION,
            ),
        },
        binary_entity_values={
            KEY_BINARY_MOTION: BinarySensorValue(
                device_key=KEY_BINARY_MOTION, name="Motion", native_value=False
            ),
        },
    )


def test_Xiaomi_MS1BB_MI_obj4a08():
    """Test Xiaomi parser for Linptech HS1BB(MI) motion + illuminance (4a08)."""
    data_string = b"HY\xeb*\xc2\xfc\xe0,\xa0\xb4:\xf28\x00\x00\xa2\xd9\xf0_"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:05:8E:E9")
    bindkey = "7475a4a77584401780ffc3ee62dd353c"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor 8EE9 (HS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor 8EE9",
                manufacturer="Xiaomi",
                model="HS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_ILLUMINANCE: SensorDescription(
                device_key=KEY_ILLUMINANCE,
                device_class=DeviceClass.ILLUMINANCE,
                native_unit_of_measurement=Units.LIGHT_LUX,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_ILLUMINANCE: SensorValue(
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=228
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_MOTION: BinarySensorDescription(
                device_key=KEY_BINARY_MOTION,
                device_class=BinarySensorDeviceClass.MOTION,
            ),
        },
        binary_entity_values={
            KEY_BINARY_MOTION: BinarySensorValue(
                device_key=KEY_BINARY_MOTION, name="Motion", native_value=True
            ),
        },
    )


def test_Xiaomi_MS1BB_MI_obj4804():
    """Test Xiaomi parser for Linptech MS1BB(MI) with obj4804."""
    data_string = b"XY\x89\x18\x9ag\xe5f8\xc1\xa4\x9d\xd9z\xf3&\x00\x00\xc8\xa6\x0b\xd5"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:66:E5:67")
    bindkey = "0fdcc30fe9289254876b5ef7c11ef1f0"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor E567 (MS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor E567",
                manufacturer="Xiaomi",
                model="MS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_OPENING: BinarySensorDescription(
                device_key=KEY_BINARY_OPENING,
                device_class=BinarySensorDeviceClass.OPENING,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OPENING: BinarySensorValue(
                device_key=KEY_BINARY_OPENING, name="Opening", native_value=True
            ),
        },
    )


def test_Xiaomi_MS1BB_MI_obj4a12():
    """Test Xiaomi parser for Linptech MS1BB(MI) with obj4a12."""
    data_string = b"XY\x89\x18ug\xe5f8\xc1\xa4i\xdd\xf3\xa1&\x00\x00\xa2J\x1bE"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:66:E5:67")
    bindkey = "0fdcc30fe9289254876b5ef7c11ef1f0"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor E567 (MS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor E567",
                manufacturer="Xiaomi",
                model="MS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_OPENING: BinarySensorDescription(
                device_key=KEY_BINARY_OPENING,
                device_class=BinarySensorDeviceClass.OPENING,
            ),
            KEY_BINARY_DOOR_LEFT_OPEN: BinarySensorDescription(
                device_key=KEY_BINARY_DOOR_LEFT_OPEN,
                device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            ),
            KEY_BINARY_DEVICE_FORCIBLY_REMOVED: BinarySensorDescription(
                device_key=KEY_BINARY_DEVICE_FORCIBLY_REMOVED,
                device_class=ExtendedBinarySensorDeviceClass.DEVICE_FORCIBLY_REMOVED,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OPENING: BinarySensorValue(
                device_key=KEY_BINARY_OPENING, name="Opening", native_value=False
            ),
            KEY_BINARY_DOOR_LEFT_OPEN: BinarySensorValue(
                device_key=KEY_BINARY_DOOR_LEFT_OPEN,
                name="Door left open",
                native_value=False,
            ),
            KEY_BINARY_DEVICE_FORCIBLY_REMOVED: BinarySensorValue(
                device_key=KEY_BINARY_DEVICE_FORCIBLY_REMOVED,
                name="Device forcibly removed",
                native_value=False,
            ),
        },
    )


def test_Xiaomi_MS1BB_MI_obj4a13():
    """Test Xiaomi parser for Linptech MS1BB(MI) with obj4a13."""
    data_string = b"XY\x89\x18\x91g\xe5f8\xc1\xa4\xd6\x12\rm&\x00\x00o\xbc\x0c\xb4"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:66:E5:67")
    bindkey = "0fdcc30fe9289254876b5ef7c11ef1f0"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor E567 (MS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor E567",
                manufacturer="Xiaomi",
                model="MS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            KEY_EVENT_BUTTON: Event(
                device_key=KEY_EVENT_BUTTON,
                name="Button",
                event_type="press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_XMWXKG01YL():
    """Test Xiaomi parser for XMWXKG01YL Switch (double button)."""
    data_string = b"XYI\x19Os\x12\x87\x83\xed\xdc\x0b48\n\x02\x00\x00\x8dI\xae("
    advertisement = bytes_to_service_info(data_string, address="DC:ED:83:87:12:73")
    bindkey = "b93eb3787eabda352edd94b667f5d5a9"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (double button) 1273 (XMWXKG01YL)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (double button) 1273",
                manufacturer="Xiaomi",
                model="XMWXKG01YL",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            DeviceKey(key="button_right", device_id=None): Event(
                device_key=DeviceKey(key="button_right", device_id=None),
                name="Button Right",
                event_type="press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_XMZNMS08LM_door():
    """Test Xiaomi parser for XMZNMS08LM."""
    bindkey = "2c3795afa33019a8afdc17ba99e6f217"
    data_string = b"HU9\x0e3\x9cq\xc0$\x1f\xff\xee\x80S\x00\x00\x02\xb4\xc59"
    advertisement = bytes_to_service_info(data_string, address="EE:89:73:44:BE:98")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door Lock BE98 (XMZNMS08LM)",
        devices={
            None: SensorDeviceInfo(
                name="Door Lock BE98",
                manufacturer="Xiaomi",
                model="XMZNMS08LM",
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
                hw_version=None,
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_DOOR: BinarySensorDescription(
                device_key=KEY_BINARY_DOOR,
                device_class=BinarySensorDeviceClass.DOOR,
            ),
            KEY_BINARY_DOOR_LEFT_OPEN: BinarySensorDescription(
                device_key=KEY_BINARY_DOOR_LEFT_OPEN,
                device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            ),
            KEY_BINARY_PRY_THE_DOOR: BinarySensorDescription(
                device_key=KEY_BINARY_PRY_THE_DOOR,
                device_class=ExtendedBinarySensorDeviceClass.PRY_THE_DOOR,
            ),
        },
        binary_entity_values={
            KEY_BINARY_DOOR: BinarySensorValue(
                device_key=KEY_BINARY_DOOR, name="Door", native_value=False
            ),
            KEY_BINARY_DOOR_LEFT_OPEN: BinarySensorValue(
                device_key=KEY_BINARY_DOOR_LEFT_OPEN,
                name="Door left open",
                native_value=False,
            ),
            KEY_BINARY_PRY_THE_DOOR: BinarySensorValue(
                device_key=KEY_BINARY_PRY_THE_DOOR,
                name="Pry the door",
                native_value=False,
            ),
        },
    )


def test_Xiaomi_XMZNMS08LM_lock():
    """Test Xiaomi parser for XMZNMS08LM."""
    bindkey = "2c3795afa33019a8afdc17ba99e6f217"
    data_string = (
        b"\x48\x55\x39\x0E\x2F\xDF\x9D\x3F\xDD\x9A\x66\x37"
        b"\x13\x15\x29\xF8\x7B\x53\x00\x00\xBC\xC3\x40\x21"
    )
    advertisement = bytes_to_service_info(data_string, address="EE:89:73:44:BE:98")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door Lock BE98 (XMZNMS08LM)",
        devices={
            None: SensorDeviceInfo(
                name="Door Lock BE98",
                manufacturer="Xiaomi",
                model="XMZNMS08LM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
            KEY_LOCK_METHOD: SensorDescription(
                device_key=KEY_LOCK_METHOD,
                device_class=ExtendedSensorDeviceClass.LOCK_METHOD,
            ),
            KEY_KEY_ID: SensorDescription(
                device_key=KEY_KEY_ID,
                device_class=ExtendedSensorDeviceClass.KEY_ID,
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
            KEY_LOCK_METHOD: SensorValue(
                name="Lock method", device_key=KEY_LOCK_METHOD, native_value="manual"
            ),
            KEY_KEY_ID: SensorValue(
                name="Key id", device_key=KEY_KEY_ID, native_value="administrator"
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_LOCK: BinarySensorDescription(
                device_key=KEY_BINARY_LOCK,
                device_class=BinarySensorDeviceClass.LOCK,
            ),
        },
        binary_entity_values={
            KEY_BINARY_LOCK: BinarySensorValue(
                device_key=KEY_BINARY_LOCK, name="Lock", native_value=True
            ),
        },
        events={
            DeviceKey(key="lock", device_id=None): Event(
                device_key=DeviceKey(key="lock", device_id=None),
                name="Lock",
                event_type="unlock_inside_the_door",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_HS1BB_battery():
    """Test Xiaomi parser for HS1BB battery."""
    data_string = b"XY\xeb*\x9e\xe9\x8e\x058\xc1\xa4\xd0z\xd3\xe38\x00\x003c]\x10"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:05:8E:E9")
    bindkey = "7475a4a77584401780ffc3ee62dd353c"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor 8EE9 (HS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor 8EE9",
                manufacturer="Xiaomi",
                model="HS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_BATTERY: SensorDescription(
                device_key=KEY_BATTERY,
                device_class=DeviceClass.BATTERY,
                native_unit_of_measurement="%",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_BATTERY: SensorValue(
                name="Battery", device_key=KEY_BATTERY, native_value=100
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_HS1BB_no_motion():
    """Test Xiaomi parser for HS1BB."""
    data_string = b"XY\xeb*\xc1\xe9\x8e\x058\xc1\xa4\x07YS\x0f\x8d8\x00\x00\xb7zp\xf8"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:05:8E:E9")
    bindkey = "7475a4a77584401780ffc3ee62dd353c"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor 8EE9 (HS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor 8EE9",
                manufacturer="Xiaomi",
                model="HS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_MOTION: BinarySensorDescription(
                device_key=KEY_BINARY_MOTION,
                device_class=BinarySensorDeviceClass.MOTION,
            ),
        },
        binary_entity_values={
            KEY_BINARY_MOTION: BinarySensorValue(
                device_key=KEY_BINARY_MOTION, name="Motion", native_value=False
            ),
        },
    )


def test_Xiaomi_HS1BB_illuminanca_and_motion():
    """Test Xiaomi parser for HS1BB illuminance and motion."""
    data_string = b"HY\xeb*\xc2\xfc\xe0,\xa0\xb4:\xf28\x00\x00\xa2\xd9\xf0_"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:05:8E:E9")
    bindkey = "7475a4a77584401780ffc3ee62dd353c"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor 8EE9 (HS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor 8EE9",
                manufacturer="Xiaomi",
                model="HS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_ILLUMINANCE: SensorDescription(
                device_key=KEY_ILLUMINANCE,
                device_class=DeviceClass.ILLUMINANCE,
                native_unit_of_measurement="lx",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_ILLUMINANCE: SensorValue(
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=228
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_MOTION: BinarySensorDescription(
                device_key=KEY_BINARY_MOTION,
                device_class=BinarySensorDeviceClass.MOTION,
            ),
        },
        binary_entity_values={
            KEY_BINARY_MOTION: BinarySensorValue(
                device_key=KEY_BINARY_MOTION, name="Motion", native_value=True
            ),
        },
    )


def test_Xiaomi_DSL_C08():
    """Test Xiaomi parser for DSL-C08."""


def test_Xiaomi_RTCGQ02LM_light_and_motion():
    """Test Xiaomi parser for RTCGQ02LM."""
    data_string = b"XY\x8d\n\x8cw\x8e <\xc2\x18Z'6(\xec2\x06\x00\x00\xc4&@\x15"
    advertisement = bytes_to_service_info(data_string, address="18:C2:3C:20:8E:77")
    bindkey = "4960bb9f8711b4ffd7df1756d11427ae"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor 8E77 (RTCGQ02LM)",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor 8E77",
                manufacturer="Xiaomi",
                model="RTCGQ02LM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_MOTION: BinarySensorDescription(
                device_key=KEY_BINARY_MOTION,
                device_class=BinarySensorDeviceClass.MOTION,
            ),
            KEY_BINARY_LIGHT: BinarySensorDescription(
                device_key=KEY_BINARY_LIGHT,
                device_class=BinarySensorDeviceClass.LIGHT,
            ),
        },
        binary_entity_values={
            KEY_BINARY_MOTION: BinarySensorValue(
                device_key=KEY_BINARY_MOTION, name="Motion", native_value=True
            ),
            KEY_BINARY_LIGHT: BinarySensorValue(
                device_key=KEY_BINARY_LIGHT, name="Light", native_value=True
            ),
        },
    )


def test_Xiaomi_RTCGQ02LM_timeout_motion():
    """Test Xiaomi parser for RTCGQ02LM."""
    data_string = b"HY\x8d\n\x92ySu\x0f\xed\x0f\x99\x06\x00\x00\\\xad,)"
    advertisement = bytes_to_service_info(data_string, address="18:C2:3C:20:8E:77")
    bindkey = "4960bb9f8711b4ffd7df1756d11427ae"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor 8E77 (RTCGQ02LM)",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor 8E77",
                manufacturer="Xiaomi",
                model="RTCGQ02LM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_MOTION: BinarySensorDescription(
                device_key=KEY_BINARY_MOTION,
                device_class=BinarySensorDeviceClass.MOTION,
            ),
        },
        binary_entity_values={
            KEY_BINARY_MOTION: BinarySensorValue(
                device_key=KEY_BINARY_MOTION, name="Motion", native_value=False
            ),
        },
    )


def test_Xiaomi_XMPIRO2SXS():
    """Test Xiaomi parser for Xiaomi Human Body Sensor 2S XMPIRO2SXS."""
    data_string = b"HY15\x0bdy\x91\x173\x1e\xf4\x02\x00\x00\xc5\xd2\xf6\xac"
    advertisement = bytes_to_service_info(data_string, address="DC:8E:95:2D:EA:43")
    bindkey = "685d647dc5e7bc9bcfcf5a1357bd2114"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion Sensor EA43 (XMPIRO2SXS)",
        devices={
            None: SensorDeviceInfo(
                name="Motion Sensor EA43",
                manufacturer="Xiaomi",
                model="XMPIRO2SXS",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_ILLUMINANCE: SensorDescription(
                device_key=KEY_ILLUMINANCE,
                device_class=DeviceClass.ILLUMINANCE,
                native_unit_of_measurement=Units.LIGHT_LUX,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_ILLUMINANCE: SensorValue(
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=51
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_MOTION: BinarySensorDescription(
                device_key=KEY_BINARY_MOTION,
                device_class=BinarySensorDeviceClass.MOTION,
            ),
        },
        binary_entity_values={
            KEY_BINARY_MOTION: BinarySensorValue(
                device_key=KEY_BINARY_MOTION, name="Motion", native_value=True
            ),
        },
    )


def test_Xiaomi_PTX_press():
    """Test Xiaomi parser for Xiaomi PTX YK1 QMIMB."""
    bindkey = "a74510b40386d35ae6227a7451efc76e"
    data_string = b"XY\xbb8\x04\xad\xb9\xa58\xc1\xa4\xdc\x10\xb5\x04\x00\x00,\x12/\xb6"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A5:B9:AD")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Wireless Switch B9AD (PTX_YK1_QMIMB)",
        devices={
            None: SensorDeviceInfo(
                name="Wireless Switch B9AD",
                manufacturer="Xiaomi",
                model="PTX_YK1_QMIMB",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            KEY_EVENT_BUTTON: Event(
                device_key=KEY_EVENT_BUTTON,
                name="Button",
                event_type="press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_XMWXKG01LM_press():
    """Test Xiaomi parser for Xiaomi XMWXKG01LM ."""
    bindkey = "7202a2d4201bbf82ea5bb3705657c32a"
    data_string = b"XY\x87#5\x057$<\xc2\x18\xd6w\x94\x02\x00\x00\xcb-\xe3\t"
    advertisement = bytes_to_service_info(data_string, address="18:C2:3C:24:37:05")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Button 3705 (XMWXKG01LM)",
        devices={
            None: SensorDeviceInfo(
                name="Button 3705",
                manufacturer="Xiaomi",
                model="XMWXKG01LM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        events={
            KEY_EVENT_BUTTON: Event(
                device_key=KEY_EVENT_BUTTON,
                name="Button",
                event_type="press",
                event_properties=None,
            ),
        },
    )


def test_can_create():
    XiaomiBluetoothDeviceData()
