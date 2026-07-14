"""The tests for the Xiaomi ble parser."""

import logging
import struct
from unittest.mock import Mock, patch

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
    obj4a08,
)

KEY_BATTERY = DeviceKey(key="battery", device_id=None)
KEY_BINARY_DOOR = DeviceKey(key="door", device_id=None)
KEY_BINARY_FINGERPRINT = DeviceKey(key="fingerprint", device_id=None)
KEY_BINARY_MOTION = DeviceKey(key="motion", device_id=None)
KEY_BINARY_OCCUPANCY = DeviceKey(key="occupancy", device_id=None)
KEY_BINARY_OCCUPANCY_CLOSE_RANGE = DeviceKey(
    key="occupancy_close_range", device_id=None
)
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
KEY_CONSUMABLE = DeviceKey(key=ExtendedSensorDeviceClass.CONSUMABLE, device_id=None)
KEY_COUNTER = DeviceKey(key="counter", device_id=None)
KEY_EVENT_BUTTON = DeviceKey(key="button", device_id=None)
KEY_EVENT_BUTTON_LEFT = DeviceKey(key="button_left", device_id=None)
KEY_EVENT_CUBE = DeviceKey(key="cube", device_id=None)
KEY_EVENT_DIMMER = DeviceKey(key="dimmer", device_id=None)
KEY_EVENT_FINGERPRINT = DeviceKey(key="fingerprint", device_id=None)
KEY_FORMALDEHYDE = DeviceKey(key="formaldehyde", device_id=None)
UNIT_FORMALDEHYDE = Units.CONCENTRATION_MILLIGRAMS_PER_CUBIC_METER
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
KEY_IMPEDANCE_LOW = DeviceKey(key="impedance_low", device_id=None)
KEY_IMPEDANCE_HIGH = DeviceKey(key="impedance_high", device_id=None)
KEY_HEART_RATE = DeviceKey(key="heart_rate", device_id=None)
KEY_PROFILE_ID = DeviceKey(key="profile_id", device_id=None)
KEY_STABILIZED = DeviceKey(key="stabilized", device_id=None)
KEY_TIMESTAMP = DeviceKey(key="timestamp", device_id=None)
KEY_VOLTAGE = DeviceKey(key="voltage", device_id=None)
KEY_CHARGING_STATE = DeviceKey(key="charging_state", device_id=None)
KEY_ASLEEP = DeviceKey(key="asleep", device_id=None)
KEY_WEARING = DeviceKey(key="wearing", device_id=None)
KEY_DURATION_DETECTED = DeviceKey(key="duration_detected", device_id=None)
KEY_DURATION_CLEARED = DeviceKey(key="duration_cleared", device_id=None)
KEY_PRESSURE_PRESENT_DURATION = DeviceKey(
    key="pressure_present_duration", device_id=None
)
KEY_PRESSURE_NOT_PRESENT_DURATION = DeviceKey(
    key="pressure_not_present_duration", device_id=None
)


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
    assert device.decryption_failed
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
    device.decryption_failed = False

    assert device.supported(advertisement)
    # the first advertisement will fail decryption, but we don't ask to reauth yet
    assert device.bindkey_verified
    assert device.decryption_failed

    data_string = b"XY\x8d\n\x18\x0f\xc4\xe0D\xefT|\xc2z\\\x03\xa1\x00\x00\x00y"
    advertisement = bytes_to_service_info(data_string, address="54:EF:44:E0:C4:0F")
    assert device.supported(advertisement)
    # the second advertisement will fail decryption again, but now we ask to reauth
    assert device.decryption_failed
    assert not device.bindkey_verified


def test_bindkey_wrong_legacy():
    """Test Xiaomi parser for YLKG07YL with wrong encryption key."""
    bindkey = "b853075158487aa39a5b5ea9"
    data_string = b"X0\xb6\x03\xd2\x8b\x98\xc5A$\xf8\xc3I\x14vu~\x00\x00\x00\x99"
    advertisement = bytes_to_service_info(data_string, address="F8:24:41:C5:98:8B")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.decryption_failed
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
    device.decryption_failed = False

    assert device.supported(advertisement)
    # the first advertisement will fail decryption, but we don't ask to reauth yet
    assert device.bindkey_verified
    assert device.decryption_failed

    data_string = b"X0\xb6\x03\xd3\x8b\x98\xc5A$\xf8\xc3I\x14vu~\x00\x00\x00\x99"
    advertisement = bytes_to_service_info(data_string, address="F8:24:41:C5:98:8B")
    assert device.supported(advertisement)
    # the second advertisement will fail decryption again, but now we ask to reauth
    assert device.decryption_failed
    assert not device.bindkey_verified


def test_Xiaomi_unknown_device_logs_product_id(caplog):
    """An UNKNOWN Xiaomi device logs its decoded product_id and a readable MAC.

    This is the single datum maintainers need to add support for a new device,
    so it must appear in the INFO log rather than only being buried in the raw
    advertisement bytes.
    """
    # A valid MiBeacon V2 frame (the LYWSDCGQ advert) with the product_id bytes
    # (data[2:4], little-endian) replaced by 0xFFFF, which is not registered.
    data_string = b"P \xff\xff\xa3\xbf.;4-X\r\x10\x04\xb4\x00\x95\x02\n\x10\x01;"
    advertisement = bytes_to_service_info(data_string, address="58:2D:34:3B:2E:BF")

    device = XiaomiBluetoothDeviceData()
    with caplog.at_level(logging.INFO):
        assert not device.supported(advertisement)

    assert "product_id: 0xffff" in caplog.text
    # MAC is rendered human-readable, not as a raw bytes repr.
    assert "58:2D:34:3B:2E:BF" in caplog.text


def test_Xiaomi_LYWSDCGQ(caplog):
    """Test Xiaomi parser for LYWSDCGQ."""
    data_string = b"P \xaa\x01\xa3\xbf.;4-X\r\x10\x04\xb4\x00\x95\x02\n\x10\x01;"
    advertisement = bytes_to_service_info(data_string, address="58:2D:34:3B:2E:BF")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert not device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 2EBF (LYWSDCGQ)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 2EBF",
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
            KEY_VOLTAGE: SensorDescription(
                device_key=KEY_VOLTAGE,
                device_class=DeviceClass.VOLTAGE,
                native_unit_of_measurement="V",
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
            KEY_TEMPERATURE: SensorValue(
                device_key=KEY_TEMPERATURE, name="Temperature", native_value=18.0
            ),
            KEY_HUMIDITY: SensorValue(
                device_key=KEY_HUMIDITY, name="Humidity", native_value=66.1
            ),
            KEY_VOLTAGE: SensorValue(
                device_key=KEY_VOLTAGE, name="Voltage", native_value=1.272
            ),
            KEY_BATTERY: SensorValue(
                device_key=KEY_BATTERY, name="Battery", native_value=59.0
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


def test_Xiaomi_CGDK3():
    """Test Xiaomi parser for CGDK3."""
    data_string = b"HXYO\xefTo\x0etPr\x93!\x01\x008\xd7C3"
    bindkey = "872ea1bb02ba9713e885cb054c537368"

    advertisement = bytes_to_service_info(data_string, address="58:2D:34:87:94:0C")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 940C (CGDK3)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 940C",
                manufacturer="Xiaomi",
                model="CGDK3",
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
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=23.8
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def _assert_temp_humidity_v3(data_string, address, name, model):
    """Assert an unencrypted MiBeacon V3 obj100d temp/humidity decode.

    Shared by the alarm-clock / temp-humidity variants (LYWSD02, CGC1, CGD1,
    MHO-C303, MHO-C401) that all reuse the same obj100d combined decoder.
    """
    advertisement = bytes_to_service_info(data_string, address=address)

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title=f"{name} ({model})",
        devices={
            None: SensorDeviceInfo(
                name=name,
                manufacturer="Xiaomi",
                model=model,
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


def test_Xiaomi_LYWSD02():
    """Test Xiaomi parser for LYWSD02."""
    _assert_temp_humidity_v3(
        b"P0[\x04\x03L\x94\xb48\xc1\xa4\r\x10\x04\x10\x01\xea\x01",
        address="A4:C1:38:B4:94:4C",
        name="Temperature/Humidity Sensor 944C",
        model="LYWSD02",
    )


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
    _assert_temp_humidity_v3(
        b"P0<\x0c\x03L\x94\xb48\xc1\xa4\r\x10\x04\x10\x01\xea\x01",
        address="A4:C1:38:B4:94:4C",
        name="Alarm Clock 944C",
        model="CGC1",
    )


def test_Xiaomi_CGD1():
    """Test Xiaomi parser for CGD1."""
    _assert_temp_humidity_v3(
        b"P0v\x05\x03L\x94\xb48\xc1\xa4\r\x10\x04\x10\x01\xea\x01",
        address="A4:C1:38:B4:94:4C",
        name="3-in-1 Alarm Clock 944C",
        model="CGD1",
    )


def test_Xiaomi_CGP1W():
    """Test Xiaomi parser for CGP1W."""


def test_Xiaomi_MHO_C303():
    """Test Xiaomi parser for MHO-C303."""
    _assert_temp_humidity_v3(
        b"P0\xd3\x06\x03L\x94\xb48\xc1\xa4\r\x10\x04\x10\x01\xea\x01",
        address="A4:C1:38:B4:94:4C",
        name="Alarm Clock 944C",
        model="MHO-C303",
    )


def test_Xiaomi_MHO_C401():
    """Test Xiaomi parser for MHO-C401."""
    _assert_temp_humidity_v3(
        b"P0\x87\x03\x03L\x94\xb48\xc1\xa4\r\x10\x04\x10\x01\xea\x01",
        address="A4:C1:38:B4:94:4C",
        name="Temperature/Humidity Sensor 944C",
        model="MHO-C401",
    )


def test_Xiaomi_JQJCY01YM1():
    """Test Xiaomi parser for JQJCY01YM (formaldehyde sensor)."""
    # Synthesized unencrypted MiBeacon V4 (frctrl 0x4050) for product_id 0x02DF
    # carrying obj1010 formaldehyde raw=125 -> 1.25 mg/m³.
    data_string = bytes.fromhex("5040df0201df02008d7cc41010027d00")
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:00:02:DF")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Formaldehyde Sensor 02DF (JQJCY01YM)",
        devices={
            None: SensorDeviceInfo(
                name="Formaldehyde Sensor 02DF",
                manufacturer="Xiaomi",
                model="JQJCY01YM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
            )
        },
        entity_descriptions={
            KEY_FORMALDEHYDE: SensorDescription(
                device_key=KEY_FORMALDEHYDE,
                device_class=DeviceClass.FORMALDEHYDE,
                native_unit_of_measurement=UNIT_FORMALDEHYDE,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_FORMALDEHYDE: SensorValue(
                name="Formaldehyde", device_key=KEY_FORMALDEHYDE, native_value=1.25
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


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
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=True
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
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=False
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
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=False
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
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=True
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
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=False
            ),
        },
    )


def test_Xiaomi_Scale1_reset():
    """Test Xiaomi parser for Mi Smart Scale (MiScale V1) — person stepped off scale."""
    # control_byte=0x80 (mass_removed=True), mass=0
    data_string = b"\x80\x00\x00\xe5\x07\x04\x0b\x10\x13\x01"

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
                native_value=0.0,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=False
            ),
        },
    )


def test_Xiaomi_Scale2_reset():
    """Test Xiaomi parser for Mi Body Composition Scale (MiScale V2).

    Person stepped off scale.
    """
    # control_bytes: mass_removed=True, mass_stabilized=False, mass=0
    data_string = b"\x02\x82\xb2\x07\x05\x04\x0f\x02\x01\x00\x00\x00\x00"

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
                native_value=0.0,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=False
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
    """Test Xiaomi parser for HHCCPOT002 (moisture + conductivity)."""
    # Synthesized unencrypted MiBeacon V2 (frctrl 0x2071, capability byte 0x0D)
    # for product_id 0x015D carrying obj1008 moisture=64% and obj1009
    # conductivity=599 µS/cm.
    data_string = bytes.fromhex("71205d01015d01008d7cc40d081001400910025702")
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:00:01:5D")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Smart Flower Pot 015D (HHCCPOT002)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Flower Pot 015D",
                manufacturer="Xiaomi",
                model="HHCCPOT002",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
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
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
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


def test_Xiaomi_WX08ZM():
    """Test Xiaomi parser for WX08ZM (mosquito repellent consumable)."""
    # Synthesized unencrypted MiBeacon V4 (frctrl 0x4050) for product_id 0x040A
    # carrying obj1013 consumable (tablet) = 90%.
    data_string = bytes.fromhex("50400a04010a04008d7cc41310015a")
    advertisement = bytes_to_service_info(data_string, address="C4:7C:8D:00:04:0A")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Mosquito Repellent 040A (WX08ZM)",
        devices={
            None: SensorDeviceInfo(
                name="Mosquito Repellent 040A",
                manufacturer="Xiaomi",
                model="WX08ZM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
            )
        },
        entity_descriptions={
            KEY_CONSUMABLE: SensorDescription(
                device_key=KEY_CONSUMABLE,
                device_class=ExtendedSensorDeviceClass.CONSUMABLE,
                native_unit_of_measurement=Units.PERCENTAGE,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_CONSUMABLE: SensorValue(
                name="Consumable", device_key=KEY_CONSUMABLE, native_value=90
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


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
    """Test Xiaomi parser for CGH1 (door/window sensor via obj1019)."""
    # Unencrypted MiBeacon V4: product_id 0x03D6, obj1019 = 0x00 (opened).
    data_string = b"P@\xd6\x03\x01\xd6\x03\n8\xc1\xa4\x19\x10\x01\x00"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:0A:03:D6")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor 03D6 (CGH1)",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor 03D6",
                manufacturer="Xiaomi",
                model="CGH1",
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


def test_Xiaomi_YM_K1501():
    """Test Xiaomi parser for YM-K1501."""


def test_Xiaomi_V_SK152():
    """Test Xiaomi parser for V-SK152."""


def test_Xiaomi_SJWS01LM():
    """Test Xiaomi parser for SJWS01LM (flood detector button press)."""
    # Unencrypted MiBeacon V4: product_id 0x0863, obj1001 button (press).
    # SJWS01LM takes the shared press-only branch (obj1001) and fires a
    # generic BUTTON event.
    data_string = b"P@c\x08\x01\x01c\x088\xc1\xa4\x01\x10\x03\x00\x00\x00"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:08:63:01")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Flood Detector 6301 (SJWS01LM)",
        devices={
            None: SensorDeviceInfo(
                name="Flood Detector 6301",
                manufacturer="Xiaomi",
                model="SJWS01LM",
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


def test_Xiaomi_MJWSD06MMC_temperature():
    """Test Xiaomi parser for MJWSD06MMC without encryption."""
    data_string = b"HY\xb5U:\x86\x99\xbd\xa0SD\x8f\x12\x00\x00[\x04mj"
    bindkey = "4d8f1373fb4d3bab557d0ebd1c78f8c4"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:80:15:07")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 1507 (MJWSD06MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 1507",
                manufacturer="Xiaomi",
                model="MJWSD06MMC",
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
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=25.2
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_MJWSD06MMC_humidity():
    """Test Xiaomi parser for MJWSD06MMC with encryption."""
    data_string = b"XY\xb5U4\x07\x15\x808\xc1\xa4\xbc\xc72\x98\x0e\x00\x00f\x96\x0f\x10"
    bindkey = "4d8f1373fb4d3bab557d0ebd1c78f8c4"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:80:15:07")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 1507 (MJWSD06MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 1507",
                manufacturer="Xiaomi",
                model="MJWSD06MMC",
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
                name="Humidity", device_key=KEY_HUMIDITY, native_value=39
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_MJWSD06MMC_new_hw_revision():
    """Test MJWSD06MMC new hw revision (product_id 0x5BEA, July 2025 batch).

    Same model as 0x55B5 but Xiaomi shipped units broadcasting product_id
    0x5BEA, which left them undiscovered. See GH #277. The advert below is
    the 0x55B5 temperature payload re-encrypted under the new product_id, so
    it must decode identically.
    """
    data_string = b"HY\xea[:\xe4\xda\x12\xe2\xb1\xfb\xf5\x12\x00\x00B\xb2\x9fP"
    bindkey = "4d8f1373fb4d3bab557d0ebd1c78f8c4"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:80:15:07")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor 1507 (MJWSD06MMC)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor 1507",
                manufacturer="Xiaomi",
                model="MJWSD06MMC",
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
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=25.2
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_ESM787_discovery():
    """Test Xiaomi parser for the Yanmi ESM787 (product_id 0x78DB).

    The raw advertisement reported in GH #295 is an unencrypted MiBeacon V5
    discovery beacon (object_include=0): it carries the MAC but no measurement
    object. Registering 0x78DB is enough to identify the device so Home
    Assistant can discover it; sensor values arrive on later object-bearing
    adverts (see test_Xiaomi_ESM787_temperature_humidity).
    """
    data_string = b"\x10Y\xdbx\r\xf4\xf8\x028\xc1\xa4"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:02:F8:F4")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor F8F4 (ESM787)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor F8F4",
                manufacturer="Yanmi",
                model="ESM787",
                hw_version=None,
                sw_version=None,
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


def test_Xiaomi_ESM787_temperature_humidity():
    """Test Xiaomi parser for the Yanmi ESM787 temperature + humidity.

    Synthesized unencrypted MiBeacon V5 advert for product_id 0x78DB carrying a
    standard combined temperature/humidity object (obj100d). Built from the real
    MAC/product_id reported in GH #295 with the object_include frame-control bit
    set, so it exercises the registered device through the established obj100d
    decoder (temp=23.5 °C, humidity=48.7 %).
    """
    data_string = b"PY\xdbx\r\xf4\xf8\x028\xc1\xa4\r\x10\x04\xeb\x00\xe7\x01"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:02:F8:F4")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor F8F4 (ESM787)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor F8F4",
                manufacturer="Yanmi",
                model="ESM787",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5)",
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
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=23.5
            ),
            KEY_HUMIDITY: SensorValue(
                name="Humidity", device_key=KEY_HUMIDITY, native_value=48.7
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )


def test_Xiaomi_MJYD02YL():
    """Test Xiaomi parser for MJYD02YL (motion + light binary sensor)."""
    # Unencrypted MiBeacon V4: product_id 0x07F6, obj000f carrying 100.
    # MJYD02YL takes the device-specific obj000f branch: motion=True plus a
    # light *binary* sensor (True when the raw value >= 100), distinct from the
    # CGPR1 lux path.
    data_string = b"P@\xf6\x07\x01\x01\xf6\x078\xc1\xa4\x0f\x00\x03d\x00\x00"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:07:F6:01")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Nightlight F601 (MJYD02YL)",
        devices={
            None: SensorDeviceInfo(
                name="Nightlight F601",
                manufacturer="Xiaomi",
                model="MJYD02YL",
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
    """Test Xiaomi parser for CGPR1 (motion + illuminance in lux)."""
    # Unencrypted MiBeacon V4: product_id 0x0A83, obj000f carrying 100 lux.
    # CGPR1 takes the device-specific obj000f branch that reports the raw
    # illuminance value as lux (distinct from the MJYD02YL/RTCGQ02LM
    # light *binary* sensor path).
    data_string = b"P@\x83\n\x01\x83\x00\n8\xc1\xa4\x0f\x00\x03d\x00\x00"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:0A:00:83")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Motion/Light Sensor 0083 (CGPR1)",
        devices={
            None: SensorDeviceInfo(
                name="Motion/Light Sensor 0083",
                manufacturer="Xiaomi",
                model="CGPR1",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
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
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=100
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
                native_unit_of_measurement=None,
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


def test_Xiaomi_ZNMS16LM_fingerprint_low_quality():
    """Test ZNMS16LM low-quality fingerprint result (match_byte 0x03)."""
    data_string = (
        b"PD\x9e\x06B\x91\x8a\xebD\x1f\xd7" b"\x06\x00\x05\x00\x00\x00\x00\x03"
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
                name="Key id", device_key=KEY_KEY_ID, native_value="administrator"
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
                device_key=KEY_BINARY_FINGERPRINT,
                name="Fingerprint",
                native_value=False,
            ),
        },
        events={
            KEY_EVENT_FINGERPRINT: Event(
                device_key=KEY_EVENT_FINGERPRINT,
                name="Fingerprint",
                event_type="low_quality_too_light_fuzzy",
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
    """Test Xiaomi parser for YLAI003 (wireless switch press)."""
    # Unencrypted MiBeacon V4: product_id 0x07BF, obj1001 button (press).
    # YLAI003 supports press/double_press/long_press; press_type 0 -> press.
    data_string = b"P@\xbf\x07\x01\x01\xbf\x078\xc1\xa4\x01\x10\x03\x00\x00\x00"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:07:BF:01")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Wireless Switch BF01 (YLAI003)",
        devices={
            None: SensorDeviceInfo(
                name="Wireless Switch BF01",
                manufacturer="Xiaomi",
                model="YLAI003",
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
    """Test Xiaomi parser for K9B 1/2/3-button switches (obj1001)."""
    # Unencrypted MiBeacon V4, obj1001 button. The K9B branches map the raw
    # press_type to press/double_press/long_press and fan the event out to the
    # left/middle/right buttons the pressed button_type touches.
    signal = {
        KEY_SIGNAL_STRENGTH: SensorDescription(
            device_key=KEY_SIGNAL_STRENGTH,
            device_class=DeviceClass.SIGNAL_STRENGTH,
            native_unit_of_measurement="dBm",
        ),
    }
    signal_val = {
        KEY_SIGNAL_STRENGTH: SensorValue(
            name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
        ),
    }
    key_button_middle = DeviceKey(key="button_middle", device_id=None)
    key_button_right = DeviceKey(key="button_right", device_id=None)

    # K9B-1BTN (0x1568): single button, press.
    data_string = b"P@h\x15\x01\x01h\x158\xc1\xa4\x01\x10\x03\x00\x00\x00"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:15:68:01")
    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (single button) 6801 (K9B-1BTN)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (single button) 6801",
                manufacturer="Xiaomi",
                model="K9B-1BTN",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
            )
        },
        entity_descriptions=signal,
        entity_values=signal_val,
        events={
            KEY_EVENT_BUTTON: Event(
                device_key=KEY_EVENT_BUTTON,
                name="Button",
                event_type="press",
                event_properties=None,
            ),
        },
    )

    # K9B-2BTN (0x1569): button_type 2 presses both left and right.
    data_string = b"P@i\x15\x01\x01i\x158\xc1\xa4\x01\x10\x03\x02\x00\x00"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:15:69:01")
    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (double button) 6901 (K9B-2BTN)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (double button) 6901",
                manufacturer="Xiaomi",
                model="K9B-2BTN",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
            )
        },
        entity_descriptions=signal,
        entity_values=signal_val,
        events={
            KEY_EVENT_BUTTON_LEFT: Event(
                device_key=KEY_EVENT_BUTTON_LEFT,
                name="Button Left",
                event_type="press",
                event_properties=None,
            ),
            key_button_right: Event(
                device_key=key_button_right,
                name="Button Right",
                event_type="press",
                event_properties=None,
            ),
        },
    )

    # K9B-3BTN (0x0DFD): button_type 6 presses all three; press_type 1 = long_press.
    data_string = b"P@\xfd\r\x01\x01\xfd\r8\xc1\xa4\x01\x10\x03\x06\x00\x01"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:0D:FD:01")
    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (triple button) FD01 (K9B-3BTN)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (triple button) FD01",
                manufacturer="Xiaomi",
                model="K9B-3BTN",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
            )
        },
        entity_descriptions=signal,
        entity_values=signal_val,
        events={
            KEY_EVENT_BUTTON_LEFT: Event(
                device_key=KEY_EVENT_BUTTON_LEFT,
                name="Button Left",
                event_type="long_press",
                event_properties=None,
            ),
            key_button_middle: Event(
                device_key=key_button_middle,
                name="Button Middle",
                event_type="long_press",
                event_properties=None,
            ),
            key_button_right: Event(
                device_key=key_button_right,
                name="Button Right",
                event_type="long_press",
                event_properties=None,
            ),
        },
    )


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


def test_Xiaomi_MS1BB_MI_obj4a1a():
    """Test Xiaomi parser for Linptech MS1BB(MI) with obj4a1a."""
    data_string = b"PY\x89\x18\x01g\xe5f8\xc1\xa4\x1a\x4a\x01\x01"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:66:E5:67")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor E567 (MS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor E567",
                manufacturer="Xiaomi",
                model="MS1BB(MI)",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5)",
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


def test_Xiaomi_RS1BB_MI_obj4806():
    """Test Xiaomi parser for Linptech RS1BB(MI) with obj4806."""
    data_string = b"XY\x0f?JgL\xb98\xc1\xa4\xd6\xe5{\x83\x04\x00\x00\xd0\x1e\x0bK"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:B9:4C:67")
    bindkey = "33ede53321bc73c790a8daae4581f3d5"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Flood and Rain Sensor 4C67 (RS1BB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Flood and Rain Sensor 4C67",
                manufacturer="Xiaomi",
                model="RS1BB(MI)",
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
            KEY_MOISTURE: BinarySensorDescription(
                device_key=KEY_MOISTURE,
                device_class=BinarySensorDeviceClass.MOISTURE,
            ),
        },
        binary_entity_values={
            KEY_MOISTURE: BinarySensorValue(
                name="Moisture", device_key=KEY_MOISTURE, native_value=False
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


def _assert_xmwxkg01yl_events(data_hex: str, events: dict) -> None:
    """Assert XMWXKG01YL (double button) fires the expected button events.

    The advertisements are synthesized from the real ``test_Xiaomi_XMWXKG01YL``
    payload (obj4e0c right press) by re-encrypting a modified plaintext with the
    same bindkey/MAC, exercising the left/both fan-out and the double_press
    (obj4e0d) and long_press (obj4e0e) object handlers.
    """
    bindkey = "b93eb3787eabda352edd94b667f5d5a9"
    advertisement = bytes_to_service_info(
        bytes.fromhex(data_hex), address="DC:ED:83:87:12:73"
    )
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
        events=events,
    )


def _btn_event(side: str, event_type: str) -> tuple[DeviceKey, Event]:
    key = DeviceKey(key=f"button_{side}", device_id=None)
    return key, Event(
        device_key=key,
        name=f"Button {side.capitalize()}",
        event_type=event_type,
        event_properties=None,
    )


def test_Xiaomi_XMWXKG01YL_press_left():
    """Test XMWXKG01YL left button single press (obj4e0c)."""
    _assert_xmwxkg01yl_events(
        "585949190a73128783eddcd2087dbd010000236b5770",
        dict([_btn_event("left", "press")]),
    )


def test_Xiaomi_XMWXKG01YL_press_both():
    """Test XMWXKG01YL both buttons single press (obj4e0c)."""
    _assert_xmwxkg01yl_events(
        "585949190a73128783eddc2979abe902000023a2c169",
        dict([_btn_event("left", "press"), _btn_event("right", "press")]),
    )


def test_Xiaomi_XMWXKG01YL_double_left():
    """Test XMWXKG01YL left button double press (obj4e0d)."""
    _assert_xmwxkg01yl_events(
        "585949190a73128783eddc498da7ef030000eff0fa82",
        dict([_btn_event("left", "double_press")]),
    )


def test_Xiaomi_XMWXKG01YL_double_right():
    """Test XMWXKG01YL right button double press (obj4e0d)."""
    _assert_xmwxkg01yl_events(
        "585949190a73128783eddc7b46384b0400003e9a5be4",
        dict([_btn_event("right", "double_press")]),
    )


def test_Xiaomi_XMWXKG01YL_double_both():
    """Test XMWXKG01YL both buttons double press (obj4e0d)."""
    _assert_xmwxkg01yl_events(
        "585949190a73128783eddcc514a4ec050000b09cecda",
        dict([_btn_event("left", "double_press"), _btn_event("right", "double_press")]),
    )


def test_Xiaomi_XMWXKG01YL_long_left():
    """Test XMWXKG01YL left button long press (obj4e0e)."""
    _assert_xmwxkg01yl_events(
        "585949190a73128783eddc203262ea060000a37535ac",
        dict([_btn_event("left", "long_press")]),
    )


def test_Xiaomi_XMWXKG01YL_long_right():
    """Test XMWXKG01YL right button long press (obj4e0e)."""
    _assert_xmwxkg01yl_events(
        "585949190a73128783eddc6cbfb981070000ae9ff8c8",
        dict([_btn_event("right", "long_press")]),
    )


def test_Xiaomi_XMWXKG01YL_long_both():
    """Test XMWXKG01YL both buttons long press (obj4e0e)."""
    _assert_xmwxkg01yl_events(
        "585949190a73128783eddc3b07b319080000126a6cdc",
        dict([_btn_event("left", "long_press"), _btn_event("right", "long_press")]),
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
        b"\x48\x55\x39\x0e\x2f\xdf\x9d\x3f\xdd\x9a\x66\x37"
        b"\x13\x15\x29\xf8\x7b\x53\x00\x00\xbc\xc3\x40\x21"
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
    """Test Xiaomi parser for DSL-C08 (lift handle outside -> obj0008)."""
    # Unencrypted MiBeacon V4: product_id 0x0380, obj0008 = 0x00.
    # DSL-C08 takes the device-specific branch: armed sensor, lock binary
    # sensor, a lock_outside_the_door event and a "manual" lock-method sensor.
    KEY_BINARY_ARMED = DeviceKey(
        key=ExtendedBinarySensorDeviceClass.ARMED, device_id=None
    )
    KEY_EVENT_LOCK = DeviceKey(key="lock", device_id=None)
    data_string = b"P@\x80\x03\x01\x80\x03\n8\xc1\xa4\x08\x00\x01\x00"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:0A:03:80")

    device = XiaomiBluetoothDeviceData()
    assert device.supported(advertisement)
    assert not device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door Lock 0380 (DSL-C08)",
        devices={
            None: SensorDeviceInfo(
                name="Door Lock 0380",
                manufacturer="Xiaomi",
                model="DSL-C08",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V4)",
            )
        },
        entity_descriptions={
            KEY_LOCK_METHOD: SensorDescription(
                device_key=KEY_LOCK_METHOD,
                device_class=ExtendedSensorDeviceClass.LOCK_METHOD,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_LOCK_METHOD: SensorValue(
                name="Lock method",
                device_key=KEY_LOCK_METHOD,
                native_value="manual",
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_ARMED: BinarySensorDescription(
                device_key=KEY_BINARY_ARMED,
                device_class=ExtendedBinarySensorDeviceClass.ARMED,
            ),
            KEY_BINARY_LOCK: BinarySensorDescription(
                device_key=KEY_BINARY_LOCK,
                device_class=BinarySensorDeviceClass.LOCK,
            ),
        },
        binary_entity_values={
            KEY_BINARY_ARMED: BinarySensorValue(
                device_key=KEY_BINARY_ARMED, name="Armed", native_value=True
            ),
            KEY_BINARY_LOCK: BinarySensorValue(
                device_key=KEY_BINARY_LOCK, name="Lock", native_value=True
            ),
        },
        events={
            KEY_EVENT_LOCK: Event(
                device_key=KEY_EVENT_LOCK,
                name="Lock",
                event_type="lock_outside_the_door",
                event_properties=None,
            ),
        },
    )


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


def test_Xiaomi_XMOSB01XS_ILLUMINANCE():
    """Test Xiaomi parser for Xiaomi Occupancy(Human Presence) Sensor XMOSB01XS."""
    data_string = (
        b"\x48\x59\x83\x46\x0d\xdc\x21\x3c\xe9\x81\xda\x7a\xe2\x02\x00\x44\x41\xf8\x8c"
    )
    advertisement = bytes_to_service_info(data_string, address="0C:43:14:A1:41:1E")
    bindkey = "0a4552cb19a639b72b8ed09bde6d5bfa"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Occupancy Sensor 411E (XMOSB01XS)",
        devices={
            None: SensorDeviceInfo(
                name="Occupancy Sensor 411E",
                manufacturer="Xiaomi",
                model="XMOSB01XS",
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
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=38
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={},
        binary_entity_values={},
    )


def test_Xiaomi_XMOSB01XS_OCCUPANCY():
    """Test Xiaomi parser for Xiaomi Occupancy(Human Presence) Sensor XMOSB01XS."""
    data_string = (
        b"\x58\x59\x83\x46\x1f\xbd\xb1\xc4\x67\x48\xd4"
        b"\x9d\x1e\xfd\x8c\x04\x00\x00\xe5\x7e\x87\x3a"
    )
    advertisement = bytes_to_service_info(data_string, address="D4:48:67:C4:B1:BD")
    bindkey = "920ce119b34410d38251ccea54c0f915"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Occupancy Sensor B1BD (XMOSB01XS)",
        devices={
            None: SensorDeviceInfo(
                name="Occupancy Sensor B1BD",
                manufacturer="Xiaomi",
                model="XMOSB01XS",
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
            KEY_BINARY_OCCUPANCY: BinarySensorDescription(
                device_key=KEY_BINARY_OCCUPANCY,
                device_class=BinarySensorDeviceClass.OCCUPANCY,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OCCUPANCY: BinarySensorValue(
                device_key=KEY_BINARY_OCCUPANCY, name="Occupancy", native_value=False
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


def test_Xiaomi_Scale_S200_MJTZC02YM():
    """Test Xiaomi parser for Xiaomi Smart Scale S200 MJTZC02YM."""
    data_string = (
        b"HY\x04L\x01\x9a\x80\xa2u\x93\x90\x10\xf0\xab\xc4\xfa\xdc\x06\x00\x00=)\xc0D"
    )
    advertisement = bytes_to_service_info(data_string, address="D0:7B:6F:27:D7:29")
    bindkey = "653b1b10e1cb35e4ac5e60fa45f3bf29"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    #    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Smart Scale S200 D729 (MJTZC02YM)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Scale S200 D729",
                manufacturer="Xiaomi",
                model="MJTZC02YM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_MASS: SensorDescription(
                device_key=KEY_MASS,
                device_class=DeviceClass.MASS,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_PROFILE_ID: SensorDescription(
                device_key=KEY_PROFILE_ID,
                device_class=ExtendedSensorDeviceClass.PROFILE_ID,
                native_unit_of_measurement=None,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_MASS: SensorValue(
                name="Mass",
                device_key=KEY_MASS,
                native_value=62.25,
            ),
            KEY_PROFILE_ID: SensorValue(
                name="Profile ID",
                device_key=KEY_PROFILE_ID,
                native_value=1,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={},
        binary_entity_values={},
    )


def test_Xiaomi_Scale_S400_MJTZC01YM():
    """Test Xiaomi parser for Xiaomi Body Composition Scale S400 MJTZC01YM."""
    data_string = b'HY\xd5;\n\xbc\x07\x8f\xf24\x8c\x84A8\xe90"\x00\x00\x00\x9eS\x85\x99'
    advertisement = bytes_to_service_info(data_string, address="8C:D0:B2:F6:BE:EF")
    bindkey = "0728974d657a4b60964c1b1677f35f7c"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Body Composition Scale BEEF (MJTZC01YM)",
        devices={
            None: SensorDeviceInfo(
                name="Body Composition Scale BEEF",
                manufacturer="Xiaomi",
                model="MJTZC01YM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_MASS: SensorDescription(
                device_key=KEY_MASS,
                device_class=DeviceClass.MASS,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_IMPEDANCE_LOW: SensorDescription(
                device_key=KEY_IMPEDANCE_LOW,
                device_class=ExtendedSensorDeviceClass.IMPEDANCE_LOW,
                native_unit_of_measurement=Units.OHM,
            ),
            KEY_HEART_RATE: SensorDescription(
                device_key=KEY_HEART_RATE,
                device_class=ExtendedSensorDeviceClass.HEART_RATE,
                native_unit_of_measurement="bpm",
            ),
            KEY_PROFILE_ID: SensorDescription(
                device_key=KEY_PROFILE_ID,
                device_class=ExtendedSensorDeviceClass.PROFILE_ID,
                native_unit_of_measurement=None,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_MASS: SensorValue(
                name="Mass",
                device_key=KEY_MASS,
                native_value=69.9,
            ),
            KEY_IMPEDANCE_LOW: SensorValue(
                name="Impedance Low",
                device_key=KEY_IMPEDANCE_LOW,
                native_value=543.2,
            ),
            KEY_HEART_RATE: SensorValue(
                name="Heart Rate",
                device_key=KEY_HEART_RATE,
                native_value=92,
            ),
            KEY_PROFILE_ID: SensorValue(
                name="Profile ID",
                device_key=KEY_PROFILE_ID,
                native_value=1,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized",
                device_key=KEY_STABILIZED,
                native_value=False,
            ),
        },
    )


def test_Xiaomi_Scale_S400_MJTZC01YM_packet_2():
    """Test Xiaomi parser for Xiaomi Body Composition Scale S400 MJTZC01YM
    (second packet with only high frequency impedance).
    """
    data_string = b"HY\xd5;\x0b\xd6\xef\x0b%\xdbrx^~/F\xd6\x00\x00\x00\xd8d-\xf6"
    advertisement = bytes_to_service_info(data_string, address="8C:D0:B2:F6:BE:EF")
    bindkey = "0728974d657a4b60964c1b1677f35f7c"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Body Composition Scale BEEF (MJTZC01YM)",
        devices={
            None: SensorDeviceInfo(
                name="Body Composition Scale BEEF",
                manufacturer="Xiaomi",
                model="MJTZC01YM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_IMPEDANCE_HIGH: SensorDescription(
                device_key=KEY_IMPEDANCE_HIGH,
                device_class=ExtendedSensorDeviceClass.IMPEDANCE_HIGH,
                native_unit_of_measurement=Units.OHM,
            ),
            KEY_PROFILE_ID: SensorDescription(
                device_key=KEY_PROFILE_ID,
                device_class=ExtendedSensorDeviceClass.PROFILE_ID,
                native_unit_of_measurement=None,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_IMPEDANCE_HIGH: SensorValue(
                name="Impedance High",
                device_key=KEY_IMPEDANCE_HIGH,
                native_value=497.6,
            ),
            KEY_PROFILE_ID: SensorValue(
                name="Profile ID",
                device_key=KEY_PROFILE_ID,
                native_value=1,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized",
                device_key=KEY_STABILIZED,
                native_value=True,
            ),
        },
    )


def test_Xiaomi_XMWS01XS_press():
    """Test Xiaomi parser for XMWS01XS Switch (double button)."""
    data_string = b"XYhYR\x11n _\xb9\x080&T\x8d\x02\x00\x00\xce1\xcf\xc3"
    advertisement = bytes_to_service_info(data_string, address="08:B9:5F:20:6E:11")
    bindkey = "59ba8eef0f5351bb09d6896762d5afa5"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (double button) 6E11 (XMWS01XS)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (double button) 6E11",
                manufacturer="Xiaomi",
                model="XMWS01XS",
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
            DeviceKey(key="button_left", device_id=None): Event(
                device_key=DeviceKey(key="button_left", device_id=None),
                name="Button Left",
                event_type="press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_Scale_S400_MJTZC01YM_socks():
    """Test Xiaomi parser for S400 — measurement with socks (no impedance)."""
    data_string = (
        b"HY\xd5;\x71\x53\x04\x38\xb5\x89\x4b"
        b"\x24\x2c\x20\x99\x08\xda\x00\x00\x00\x47\x9e\xcd\xa3"
    )
    advertisement = bytes_to_service_info(data_string, address="04:AE:47:67:C6:7C")
    bindkey = "02d2900363ef629c736a4549677acbee"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Body Composition Scale C67C (MJTZC01YM)",
        devices={
            None: SensorDeviceInfo(
                name="Body Composition Scale C67C",
                manufacturer="Xiaomi",
                model="MJTZC01YM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_MASS: SensorDescription(
                device_key=KEY_MASS,
                device_class=DeviceClass.MASS,
                native_unit_of_measurement=Units.MASS_KILOGRAMS,
            ),
            KEY_PROFILE_ID: SensorDescription(
                device_key=KEY_PROFILE_ID,
                device_class=ExtendedSensorDeviceClass.PROFILE_ID,
                native_unit_of_measurement=None,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_MASS: SensorValue(name="Mass", device_key=KEY_MASS, native_value=74.7),
            KEY_PROFILE_ID: SensorValue(
                name="Profile ID", device_key=KEY_PROFILE_ID, native_value=1
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=True
            ),
        },
    )


def test_Xiaomi_Scale_S400_MJTZC01YM_reset():
    """Test Xiaomi parser for S400 — person stepped off scale."""
    data_string = (
        b"HY\xd5;\x72\x03\x6c\x67\x94\x35\x5a"
        b"\x19\xdb\xc8\x64\xbf\xb3\x00\x00\x00\xe4\x15\x1d\xc8"
    )
    advertisement = bytes_to_service_info(data_string, address="04:AE:47:67:C6:7C")
    bindkey = "02d2900363ef629c736a4549677acbee"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Body Composition Scale C67C (MJTZC01YM)",
        devices={
            None: SensorDeviceInfo(
                name="Body Composition Scale C67C",
                manufacturer="Xiaomi",
                model="MJTZC01YM",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_PROFILE_ID: SensorDescription(
                device_key=KEY_PROFILE_ID,
                device_class=ExtendedSensorDeviceClass.PROFILE_ID,
                native_unit_of_measurement=None,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_PROFILE_ID: SensorValue(
                name="Profile ID", device_key=KEY_PROFILE_ID, native_value=1
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={
            KEY_STABILIZED: BinarySensorDescription(
                device_key=KEY_STABILIZED,
                device_class=ExtendedBinarySensorDeviceClass.STABILIZED,
            ),
        },
        binary_entity_values={
            KEY_STABILIZED: BinarySensorValue(
                name="Stabilized", device_key=KEY_STABILIZED, native_value=False
            ),
        },
    )


def test_Xiaomi_XMWS01XS_double_press():
    """Test Xiaomi parser for XMWS01XS Switch (double button)."""
    data_string = b"XYhYQ\x11n _\xb9\x08\xd9\x1b\xd5\x85\x02\x00\x00\x07\xcc\xa8I"
    advertisement = bytes_to_service_info(data_string, address="08:B9:5F:20:6E:11")
    bindkey = "59ba8eef0f5351bb09d6896762d5afa5"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (double button) 6E11 (XMWS01XS)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (double button) 6E11",
                manufacturer="Xiaomi",
                model="XMWS01XS",
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
                event_type="double_press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_XMWS01XS_long_press():
    """Test Xiaomi parser for XMWS01XS Switch (double button)."""
    data_string = b"XYhYS\x11n _\xb9\x08\xf3xQ\x81\x02\x00\x00\xea\xc1\x83\xf4"
    advertisement = bytes_to_service_info(data_string, address="08:B9:5F:20:6E:11")
    bindkey = "59ba8eef0f5351bb09d6896762d5afa5"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (double button) 6E11 (XMWS01XS)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (double button) 6E11",
                manufacturer="Xiaomi",
                model="XMWS01XS",
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
                event_type="long_press",
                event_properties=None,
            ),
        },
    )


def test_can_create():
    XiaomiBluetoothDeviceData()


def test_Xiaomi_ES3_illuminance():
    """Test Xiaomi parser for Linptech ES3 illuminance."""
    data_string = b"HY\xfbP\xd9\x86\xd2~\x8fS\x13\xe9\x00\x00\x000\xadm\xa8"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:C7:C3:76")
    bindkey = "b26295a7a08fbac306c8706ade7f0fe4"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Human Presence Sensor C376 (ES3)",
        devices={
            None: SensorDeviceInfo(
                name="Human Presence Sensor C376",
                manufacturer="Linptech",
                model="ES3",
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
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=173
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={},
        binary_entity_values={},
    )


def test_Xiaomi_ES3_occupancy_on():
    """Test Xiaomi parser for Linptech ES3 occupancy detected."""
    data_string = b"XY\xfbP\xdav\xc3\xc78\xc1\xa4\xaa\xbcL\x16\x00\x00\x00\xc6\x0c\x16F"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:C7:C3:76")
    bindkey = "b26295a7a08fbac306c8706ade7f0fe4"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Human Presence Sensor C376 (ES3)",
        devices={
            None: SensorDeviceInfo(
                name="Human Presence Sensor C376",
                manufacturer="Linptech",
                model="ES3",
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
            KEY_BINARY_OCCUPANCY: BinarySensorDescription(
                device_key=KEY_BINARY_OCCUPANCY,
                device_class=BinarySensorDeviceClass.OCCUPANCY,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OCCUPANCY: BinarySensorValue(
                device_key=KEY_BINARY_OCCUPANCY, name="Occupancy", native_value=True
            ),
        },
    )


def test_Xiaomi_ES3_occupancy_off():
    """Test Xiaomi parser for Linptech ES3 occupancy cleared."""
    data_string = b"XY\xfbP2\x8a\x88\xa48\xc1\xa4E\x8a\x85\xb7\x96\x00\x00H\xfe\x13\xba"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A4:88:8A")
    bindkey = "fb352ea2139ab095877a9e2ae600c912"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Human Presence Sensor 888A (ES3)",
        devices={
            None: SensorDeviceInfo(
                name="Human Presence Sensor 888A",
                manufacturer="Linptech",
                model="ES3",
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
            KEY_BINARY_OCCUPANCY: BinarySensorDescription(
                device_key=KEY_BINARY_OCCUPANCY,
                device_class=BinarySensorDeviceClass.OCCUPANCY,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OCCUPANCY: BinarySensorValue(
                device_key=KEY_BINARY_OCCUPANCY, name="Occupancy", native_value=False
            ),
        },
    )


def test_Xiaomi_KS1_double_press():
    """Test Xiaomi parser for KS1 quadruple-button double press (left button)."""
    bindkey = "8bdff7d0f70fa7f5c68f42157b5fd65b"
    data_string = bytes.fromhex("5859613ab4e6fea138c1a45905b5b90900006b8211cd")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A1:FE:E6")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (quadruple button) FEE6 (KS1)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (quadruple button) FEE6",
                manufacturer="Xiaomi",
                model="KS1",
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
        binary_entity_descriptions={},
        binary_entity_values={},
        events={
            KEY_EVENT_BUTTON_LEFT: Event(
                device_key=KEY_EVENT_BUTTON_LEFT,
                name="Button Left",
                event_type="double_press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_KS1_long_press():
    """Test Xiaomi parser for KS1 quadruple-button long press (left button)."""
    bindkey = "8bdff7d0f70fa7f5c68f42157b5fd65b"
    data_string = bytes.fromhex("5859613ab4e6fea138c1a45a05b5b9090000b43ff116")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A1:FE:E6")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Switch (quadruple button) FEE6 (KS1)",
        devices={
            None: SensorDeviceInfo(
                name="Switch (quadruple button) FEE6",
                manufacturer="Xiaomi",
                model="KS1",
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
        binary_entity_descriptions={},
        binary_entity_values={},
        events={
            KEY_EVENT_BUTTON_LEFT: Event(
                device_key=KEY_EVENT_BUTTON_LEFT,
                name="Button Left",
                event_type="long_press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_button_object_ignored_for_non_button_device():
    """A non-button device carrying a stray button object fires no event.

    Exercises the device-type guard in obj560d/obj560e: any device that is not
    KS1/KS1BP/KS2BB must ignore a 0x560d/0x560e object rather than emit a button
    event. Here a LYWSDCGQ advert carries both obj560d and obj560e payloads; no
    event results.
    """
    bindkey = "8bdff7d0f70fa7f5c68f42157b5fd65b"
    data_string = bytes.fromhex("5859aa01b4e6fea138c1a4ff47a4daba202c2f090000e761ffec")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A1:FE:E6")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    update = device.update(advertisement)
    assert update.events == {}


def test_Xiaomi_KS2_button_press():
    """Test Xiaomi parser for Linptech KS2 button press."""
    bindkey = "8bdff7d0f70fa7f5c68f42157b5fd65b"
    data_string = (
        b"XY\x0bR\xb4\xe6\xfe\xa1\x38\xc1\xa40\x8f\xa8\t\x00\x00\r\xe1\xeb\xdb"
    )
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A1:FE:E6")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor with Button FEE6 (KS2BB)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor with Button FEE6",
                manufacturer="Linptech",
                model="KS2BB",
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
        binary_entity_descriptions={},
        binary_entity_values={},
        events={
            KEY_EVENT_BUTTON: Event(
                device_key=KEY_EVENT_BUTTON,
                name="Button",
                event_type="press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_KS2_double_press():
    """Test Xiaomi parser for Linptech KS2 double button press."""
    bindkey = "8bdff7d0f70fa7f5c68f42157b5fd65b"
    data_string = bytes.fromhex("58590b52b4e6fea138c1a4318fa8090000ff75594b")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A1:FE:E6")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor with Button FEE6 (KS2BB)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor with Button FEE6",
                manufacturer="Linptech",
                model="KS2BB",
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
        binary_entity_descriptions={},
        binary_entity_values={},
        events={
            KEY_EVENT_BUTTON: Event(
                device_key=KEY_EVENT_BUTTON,
                name="Button",
                event_type="double_press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_KS2_long_press():
    """Test Xiaomi parser for Linptech KS2 long button press."""
    bindkey = "8bdff7d0f70fa7f5c68f42157b5fd65b"
    data_string = bytes.fromhex("58590b52b4e6fea138c1a4328fa8090000856f02bf")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A1:FE:E6")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor with Button FEE6 (KS2BB)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor with Button FEE6",
                manufacturer="Linptech",
                model="KS2BB",
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
        binary_entity_descriptions={},
        binary_entity_values={},
        events={
            KEY_EVENT_BUTTON: Event(
                device_key=KEY_EVENT_BUTTON,
                name="Button",
                event_type="long_press",
                event_properties=None,
            ),
        },
    )


def test_Xiaomi_KS2_temperature():
    """Test Xiaomi parser for Linptech KS2 with temperature reading."""
    bindkey = "8bdff7d0f70fa7f5c68f42157b5fd65b"
    data_string = b"HY\x0bR\xb3\xc1\xb8\\P\xf3\\W\t\x00\x00J\x9e\xd6\xb8"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A1:FE:E6")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor with Button FEE6 (KS2BB)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor with Button FEE6",
                manufacturer="Linptech",
                model="KS2BB",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_TEMPERATURE: SensorDescription(
                device_key=KEY_TEMPERATURE,
                device_class=DeviceClass.TEMPERATURE,
                native_unit_of_measurement=Units.TEMP_CELSIUS,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_TEMPERATURE: SensorValue(
                name="Temperature", device_key=KEY_TEMPERATURE, native_value=26.2
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={},
        binary_entity_values={},
        events={},
    )


def test_Xiaomi_KS2_humidity():
    """Test Xiaomi parser for Linptech KS2 with humidity reading."""
    bindkey = "8bdff7d0f70fa7f5c68f42157b5fd65b"
    data_string = b"XY\x0bRl\xe6\xfe\xa1\x38\xc1\xa4C\x05@g\x0b\x00\x00LDE\xf1"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:A1:FE:E6")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Temperature/Humidity Sensor with Button FEE6 (KS2BB)",
        devices={
            None: SensorDeviceInfo(
                name="Temperature/Humidity Sensor with Button FEE6",
                manufacturer="Linptech",
                model="KS2BB",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            )
        },
        entity_descriptions={
            KEY_HUMIDITY: SensorDescription(
                device_key=KEY_HUMIDITY,
                device_class=DeviceClass.HUMIDITY,
                native_unit_of_measurement=Units.PERCENTAGE,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement=Units.SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
            ),
        },
        entity_values={
            KEY_HUMIDITY: SensorValue(
                name="Humidity", device_key=KEY_HUMIDITY, native_value=71
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={},
        binary_entity_values={},
        events={},
    )


def test_Xiaomi_M1S_T500_score_and_counter():
    """Test Xiaomi parser for M1S-T500 toothbrush."""
    # Battery - e1 09 0a 10 01 3e is the data. Mibeacon header is needed.
    # 50 20 means V2, NO MAC, YES OBJECT (0x2050 -> 0010 0000 0101 0000).
    # wait: let's use a standard V2 header that works.
    # "P \xaa\x01\xda!" -> 50 20 aa 01 da 21
    # 50 20 aa 01 da 21 (MAC) -> wait, if no MAC include, just 50 20
    # Let's use 50 20 89 04 + Payload
    # Actually, 0x0489 is Device ID for T500!
    data_string_battery = bytes.fromhex("5020890401ffeeddccbbaa0a10013e")
    advertisement_battery = bytes_to_service_info(
        data_string_battery, address="AA:BB:CC:DD:EE:FF"
    )

    device1 = XiaomiBluetoothDeviceData()
    assert device1.supported(advertisement_battery)
    assert not device1.bindkey_verified
    assert device1.update(advertisement_battery) == SensorUpdate(
        title="Smart Toothbrush EEFF (M1S-T500)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Toothbrush EEFF",
                manufacturer="Xiaomi",
                model="M1S-T500",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
            KEY_BATTERY: SensorDescription(
                device_key=KEY_BATTERY,
                device_class=DeviceClass.BATTERY,
                native_unit_of_measurement="%",
            ),
            DeviceKey(key="voltage", device_id=None): SensorDescription(
                device_key=DeviceKey(key="voltage", device_id=None),
                device_class=DeviceClass.VOLTAGE,
                native_unit_of_measurement="V",
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_BATTERY: SensorValue(
                name="Battery", device_key=KEY_BATTERY, native_value=62
            ),
            DeviceKey(key="voltage", device_id=None): SensorValue(
                name="Voltage",
                device_key=DeviceKey(key="voltage", device_id=None),
                native_value=2.758,
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={},
        binary_entity_values={},
        events={},
    )

    data_string_score = bytes.fromhex("5020890401ffeeddccbbaa1000020146")
    advertisement_score = bytes_to_service_info(
        data_string_score, address="AA:BB:CC:DD:EE:FF"
    )

    device2 = XiaomiBluetoothDeviceData()
    assert device2.supported(advertisement_score)
    assert not device2.bindkey_verified
    assert device2.update(advertisement_score) == SensorUpdate(
        title="Smart Toothbrush EEFF (M1S-T500)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Toothbrush EEFF",
                manufacturer="Xiaomi",
                model="M1S-T500",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
            KEY_SCORE: SensorDescription(
                device_key=KEY_SCORE,
                device_class=ExtendedSensorDeviceClass.SCORE,
                native_unit_of_measurement=None,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_SCORE: SensorValue(name="Score", device_key=KEY_SCORE, native_value=70),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
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
                name="Toothbrush", device_key=KEY_BINARY_TOOTHBRUSH, native_value=False
            ),
        },
        events={},
    )

    data_string_counter = bytes.fromhex("5020890401ffeeddccbbaa1000020059")
    advertisement_counter = bytes_to_service_info(
        data_string_counter, address="AA:BB:CC:DD:EE:FF"
    )

    device3 = XiaomiBluetoothDeviceData()
    assert device3.supported(advertisement_counter)
    assert not device3.bindkey_verified
    assert device3.update(advertisement_counter) == SensorUpdate(
        title="Smart Toothbrush EEFF (M1S-T500)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Toothbrush EEFF",
                manufacturer="Xiaomi",
                model="M1S-T500",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
            )
        },
        entity_descriptions={
            KEY_COUNTER: SensorDescription(
                device_key=KEY_COUNTER,
                device_class=ExtendedSensorDeviceClass.COUNTER,
                native_unit_of_measurement=None,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_COUNTER: SensorValue(
                name="Counter", device_key=KEY_COUNTER, native_value=89
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
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
                name="Toothbrush", device_key=KEY_BINARY_TOOTHBRUSH, native_value=True
            ),
        },
        events={},
    )


def test_Xiaomi_M1S_T500_state_only():
    """Test Xiaomi parser for M1S-T500 toothbrush state only (no score/counter)."""

    # Toothbrush off (no score)
    data_string_off = bytes.fromhex("5020890401ffeeddccbbaa10000101")
    advertisement_off = bytes_to_service_info(
        data_string_off, address="AA:BB:CC:DD:EE:FF"
    )

    device1 = XiaomiBluetoothDeviceData()
    assert device1.supported(advertisement_off)
    assert not device1.bindkey_verified
    assert device1.update(advertisement_off) == SensorUpdate(
        title="Smart Toothbrush EEFF (M1S-T500)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Toothbrush EEFF",
                manufacturer="Xiaomi",
                model="M1S-T500",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
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
            KEY_BINARY_TOOTHBRUSH: BinarySensorDescription(
                device_key=KEY_BINARY_TOOTHBRUSH,
                device_class=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            ),
        },
        binary_entity_values={
            KEY_BINARY_TOOTHBRUSH: BinarySensorValue(
                name="Toothbrush", device_key=KEY_BINARY_TOOTHBRUSH, native_value=False
            ),
        },
        events={},
    )

    # Toothbrush on (no counter)
    data_string_on = bytes.fromhex("5020890401ffeeddccbbaa10000100")
    advertisement_on = bytes_to_service_info(
        data_string_on, address="AA:BB:CC:DD:EE:FF"
    )

    device2 = XiaomiBluetoothDeviceData()
    assert device2.supported(advertisement_on)
    assert not device2.bindkey_verified
    assert device2.update(advertisement_on) == SensorUpdate(
        title="Smart Toothbrush EEFF (M1S-T500)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Toothbrush EEFF",
                manufacturer="Xiaomi",
                model="M1S-T500",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V2)",
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
            KEY_BINARY_TOOTHBRUSH: BinarySensorDescription(
                device_key=KEY_BINARY_TOOTHBRUSH,
                device_class=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            ),
        },
        binary_entity_values={
            KEY_BINARY_TOOTHBRUSH: BinarySensorValue(
                name="Toothbrush", device_key=KEY_BINARY_TOOTHBRUSH, native_value=True
            ),
        },
        events={},
    )


def test_Xiaomi_M2456B1_charging_state():
    """Test Xiaomi parser for M2456B1 Charging State."""
    data_string = bytes.fromhex("4859fc59c32705ff45020000d6d291b3")
    bindkey = "05eecf799ee981b3b73664e114b9373b"
    advertisement = bytes_to_service_info(data_string, address="04:34:C3:75:6F:6D")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Smart Band 10 Ceramic Edition 6F6D (M2456B1)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Band 10 Ceramic Edition 6F6D",
                manufacturer="Xiaomi",
                model="M2456B1",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            ),
        },
        entity_descriptions={
            KEY_CHARGING_STATE: SensorDescription(
                device_key=KEY_CHARGING_STATE,
                device_class=ExtendedSensorDeviceClass.CHARGING_STATE,
                native_unit_of_measurement=None,
            ),
            KEY_SIGNAL_STRENGTH: SensorDescription(
                device_key=KEY_SIGNAL_STRENGTH,
                device_class=DeviceClass.SIGNAL_STRENGTH,
                native_unit_of_measurement="dBm",
            ),
        },
        entity_values={
            KEY_CHARGING_STATE: SensorValue(
                device_key=KEY_CHARGING_STATE,
                name="Charging State",
                native_value="Full",
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                device_key=KEY_SIGNAL_STRENGTH,
                name="Signal Strength",
                native_value=-60,
            ),
        },
        binary_entity_descriptions={},
        binary_entity_values={},
        events={},
    )


def test_Xiaomi_M2456B1_sleep_state():
    """Test Xiaomi parser for M2456B1 Sleep State."""
    data_string = bytes.fromhex("4859fc59da28bc61b4020000d935d001")
    bindkey = "05eecf799ee981b3b73664e114b9373b"
    advertisement = bytes_to_service_info(data_string, address="04:34:C3:75:6F:6D")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Smart Band 10 Ceramic Edition 6F6D (M2456B1)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Band 10 Ceramic Edition 6F6D",
                manufacturer="Xiaomi",
                model="M2456B1",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            ),
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
                device_key=KEY_SIGNAL_STRENGTH,
                name="Signal Strength",
                native_value=-60,
            ),
        },
        binary_entity_descriptions={
            KEY_ASLEEP: BinarySensorDescription(
                device_key=KEY_ASLEEP,
                device_class=ExtendedBinarySensorDeviceClass.ASLEEP,
            ),
        },
        binary_entity_values={
            KEY_ASLEEP: BinarySensorValue(
                device_key=KEY_ASLEEP,
                name="Asleep",
                native_value=False,
            ),
        },
        events={},
    )


def test_Xiaomi_M2456B1_device_wearing_status():
    """Test Xiaomi parser for M2456B1 Device Wearing Status."""
    data_string = bytes.fromhex("4859fc59bf1c9fd59b020000084a4740")
    bindkey = "05eecf799ee981b3b73664e114b9373b"
    advertisement = bytes_to_service_info(data_string, address="04:34:C3:75:6F:6D")

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Smart Band 10 Ceramic Edition 6F6D (M2456B1)",
        devices={
            None: SensorDeviceInfo(
                name="Smart Band 10 Ceramic Edition 6F6D",
                manufacturer="Xiaomi",
                model="M2456B1",
                hw_version=None,
                sw_version="Xiaomi (MiBeacon V5 encrypted)",
            ),
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
                device_key=KEY_SIGNAL_STRENGTH,
                name="Signal Strength",
                native_value=-60,
            ),
        },
        binary_entity_descriptions={
            KEY_WEARING: BinarySensorDescription(
                device_key=KEY_WEARING,
                device_class=ExtendedBinarySensorDeviceClass.WEARING,
            ),
        },
        binary_entity_values={
            KEY_WEARING: BinarySensorValue(
                device_key=KEY_WEARING,
                name="Wearing",
                native_value=False,
            ),
        },
        events={},
    )


def test_Xiaomi_ES5BB_illuminance():
    """Test Xiaomi parser for Linptech ES5 Illuminance."""
    data_string = bytes.fromhex("48590f6abc7a1f20cfb0b0971c00009dad6cca")
    advertisement = bytes_to_service_info(data_string, address="E8:B5:27:74:91:EE")
    bindkey = "068a081b4e5aa7295ebf263585adf4f1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Human Presence Sensor 91EE (ES5BB)",
        devices={
            None: SensorDeviceInfo(
                name="Human Presence Sensor 91EE",
                manufacturer="Linptech",
                model="ES5BB",
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
                name="Illuminance", device_key=KEY_ILLUMINANCE, native_value=8.0
            ),
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
        binary_entity_descriptions={},
        binary_entity_values={},
    )


def test_Xiaomi_ES5BB_occupancy():
    """Test Xiaomi parser for Linptech ES5 Occupancy."""
    data_string = bytes.fromhex("58590f6a11ee917427b5e83567ac0e1c0000f681b610")
    advertisement = bytes_to_service_info(data_string, address="E8:B5:27:74:91:EE")
    bindkey = "068a081b4e5aa7295ebf263585adf4f1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Human Presence Sensor 91EE (ES5BB)",
        devices={
            None: SensorDeviceInfo(
                name="Human Presence Sensor 91EE",
                manufacturer="Linptech",
                model="ES5BB",
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
            KEY_BINARY_OCCUPANCY: BinarySensorDescription(
                device_key=KEY_BINARY_OCCUPANCY,
                device_class=BinarySensorDeviceClass.OCCUPANCY,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OCCUPANCY: BinarySensorValue(
                device_key=KEY_BINARY_OCCUPANCY, name="Occupancy", native_value=True
            ),
        },
    )


def test_Xiaomi_ES5BB_occupancy_close_range():
    """Test Xiaomi parser for Linptech ES5 Occupancy close range."""
    data_string = bytes.fromhex("58590f6a14ee917427b5e8f139cdae1c00001bd88863")
    advertisement = bytes_to_service_info(data_string, address="E8:B5:27:74:91:EE")
    bindkey = "068a081b4e5aa7295ebf263585adf4f1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Human Presence Sensor 91EE (ES5BB)",
        devices={
            None: SensorDeviceInfo(
                name="Human Presence Sensor 91EE",
                manufacturer="Linptech",
                model="ES5BB",
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
            KEY_BINARY_OCCUPANCY_CLOSE_RANGE: BinarySensorDescription(
                device_key=KEY_BINARY_OCCUPANCY_CLOSE_RANGE,
                device_class=BinarySensorDeviceClass.OCCUPANCY,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OCCUPANCY_CLOSE_RANGE: BinarySensorValue(
                device_key=KEY_BINARY_OCCUPANCY_CLOSE_RANGE,
                name="Occupancy close range",
                native_value=True,
            ),
        },
    )


def test_Xiaomi_ES5BB_duration_detected():
    """Test Xiaomi parser for Linptech ES5 Duration detected."""
    data_string = bytes.fromhex("58590f6abdee917427b5e885884d061c0000c263fbd0")
    advertisement = bytes_to_service_info(data_string, address="E8:B5:27:74:91:EE")
    bindkey = "068a081b4e5aa7295ebf263585adf4f1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Human Presence Sensor 91EE (ES5BB)",
        devices={
            None: SensorDeviceInfo(
                name="Human Presence Sensor 91EE",
                manufacturer="Linptech",
                model="ES5BB",
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
            KEY_DURATION_DETECTED: SensorDescription(
                device_key=KEY_DURATION_DETECTED,
                device_class=ExtendedSensorDeviceClass.DURATION_DETECTED,
                native_unit_of_measurement="min",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
            KEY_DURATION_DETECTED: SensorValue(
                device_key=KEY_DURATION_DETECTED,
                name="Duration detected",
                native_value=1,
            ),
        },
    )


def test_Xiaomi_ES5BB_duration_cleared():
    """Test Xiaomi parser for Linptech ES5 duration cleared."""
    data_string = bytes.fromhex("58590f6ac1ee917427b5e8bb7b2c201c0000f252a862")
    advertisement = bytes_to_service_info(data_string, address="E8:B5:27:74:91:EE")
    bindkey = "068a081b4e5aa7295ebf263585adf4f1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Human Presence Sensor 91EE (ES5BB)",
        devices={
            None: SensorDeviceInfo(
                name="Human Presence Sensor 91EE",
                manufacturer="Linptech",
                model="ES5BB",
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
            KEY_DURATION_CLEARED: SensorDescription(
                device_key=KEY_DURATION_CLEARED,
                device_class=ExtendedSensorDeviceClass.DURATION_CLEARED,
                native_unit_of_measurement="min",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
            KEY_DURATION_CLEARED: SensorValue(
                device_key=KEY_DURATION_CLEARED,
                name="Duration cleared",
                native_value=1,
            ),
        },
    )


def test_Xiaomi_PS1BB_pressure_present_duration():
    """Test Xiaomi parser for Linptech PS1BB Pressure Present Duration."""
    data_string = bytes.fromhex("59584c3f2012efbe38c1a4bbacc927535b030000004cdc48fd")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:BE:EF:12")
    bindkey = "8b72476b60fe2a0b63bf58d588fe4ea1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Seat Pressure Sensor EF12 (PS1BB)",
        devices={
            None: SensorDeviceInfo(
                name="Seat Pressure Sensor EF12",
                manufacturer="Linptech",
                model="PS1BB",
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
            KEY_PRESSURE_PRESENT_DURATION: SensorDescription(
                device_key=KEY_PRESSURE_PRESENT_DURATION,
                device_class=ExtendedSensorDeviceClass.PRESSURE_PRESENT_DURATION,
                native_unit_of_measurement="s",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength",
                device_key=KEY_SIGNAL_STRENGTH,
                native_value=-60,
            ),
            KEY_PRESSURE_PRESENT_DURATION: SensorValue(
                device_key=KEY_PRESSURE_PRESENT_DURATION,
                name="Pressure present duration",
                native_value=7800,
            ),
        },
    )


def test_Xiaomi_PS1BB_pressure_state_occupied():
    """Test Xiaomi parser for Linptech PS1BB pressure state occupied."""
    data_string = bytes.fromhex("58594c3f1012efbe38c1a47f7b3e9500000035019b75")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:BE:EF:12")
    bindkey = "8b72476b60fe2a0b63bf58d588fe4ea1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Seat Pressure Sensor EF12 (PS1BB)",
        devices={
            None: SensorDeviceInfo(
                name="Seat Pressure Sensor EF12",
                manufacturer="Linptech",
                model="PS1BB",
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
                name="Signal Strength",
                device_key=KEY_SIGNAL_STRENGTH,
                native_value=-60,
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_OCCUPANCY: BinarySensorDescription(
                device_key=KEY_BINARY_OCCUPANCY,
                device_class=BinarySensorDeviceClass.OCCUPANCY,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OCCUPANCY: BinarySensorValue(
                device_key=KEY_BINARY_OCCUPANCY,
                name="Occupancy",
                native_value=True,
            ),
        },
    )


def test_Xiaomi_PS1BB_pressure_state_clear():
    """Test Xiaomi parser for Linptech PS1BB pressure state clear."""
    data_string = bytes.fromhex("58594c3f1312efbe38c1a418e36bcb000000e6fab951")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:BE:EF:12")
    bindkey = "8b72476b60fe2a0b63bf58d588fe4ea1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Seat Pressure Sensor EF12 (PS1BB)",
        devices={
            None: SensorDeviceInfo(
                name="Seat Pressure Sensor EF12",
                manufacturer="Linptech",
                model="PS1BB",
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
                name="Signal Strength",
                device_key=KEY_SIGNAL_STRENGTH,
                native_value=-60,
            ),
        },
        binary_entity_descriptions={
            KEY_BINARY_OCCUPANCY: BinarySensorDescription(
                device_key=KEY_BINARY_OCCUPANCY,
                device_class=BinarySensorDeviceClass.OCCUPANCY,
            ),
        },
        binary_entity_values={
            KEY_BINARY_OCCUPANCY: BinarySensorValue(
                device_key=KEY_BINARY_OCCUPANCY,
                name="Occupancy",
                native_value=False,
            ),
        },
    )


def test_Xiaomi_PS1BB_pressure_not_present_duration():
    """Test Xiaomi parser for Linptech PS1BB pressure not present duration."""
    data_string = bytes.fromhex("59584c3f2112efbe38c1a4558db5277810330000001906bc63")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:BE:EF:12")
    bindkey = "8b72476b60fe2a0b63bf58d588fe4ea1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Seat Pressure Sensor EF12 (PS1BB)",
        devices={
            None: SensorDeviceInfo(
                name="Seat Pressure Sensor EF12",
                manufacturer="Linptech",
                model="PS1BB",
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
            KEY_PRESSURE_NOT_PRESENT_DURATION: SensorDescription(
                device_key=KEY_PRESSURE_NOT_PRESENT_DURATION,
                device_class=ExtendedSensorDeviceClass.PRESSURE_NOT_PRESENT_DURATION,
                native_unit_of_measurement="s",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength",
                device_key=KEY_SIGNAL_STRENGTH,
                native_value=-60,
            ),
            KEY_PRESSURE_NOT_PRESENT_DURATION: SensorValue(
                device_key=KEY_PRESSURE_NOT_PRESENT_DURATION,
                name="Pressure not present duration",
                native_value=120,
            ),
        },
    )


def test_Xiaomi_PS1BB_battery():
    """Test Xiaomi parser for Linptech PS1BB battery."""
    data_string = bytes.fromhex("59584c3f2212efbe38c1a4da2cec2100000029c7c0c7")
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:BE:EF:12")
    bindkey = "8b72476b60fe2a0b63bf58d588fe4ea1"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.sleepy_device
    assert device.update(advertisement) == SensorUpdate(
        title="Seat Pressure Sensor EF12 (PS1BB)",
        devices={
            None: SensorDeviceInfo(
                name="Seat Pressure Sensor EF12",
                manufacturer="Linptech",
                model="PS1BB",
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
            KEY_BATTERY: SensorDescription(
                device_key=KEY_BATTERY,
                device_class=DeviceClass.BATTERY,
                native_unit_of_measurement="%",
            ),
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength",
                device_key=KEY_SIGNAL_STRENGTH,
                native_value=-60,
            ),
            KEY_BATTERY: SensorValue(
                device_key=KEY_BATTERY,
                name="Battery",
                native_value=100,
            ),
        },
    )


def test_obj4a08_illuminance_is_little_endian():
    """obj4a08 must decode the lux float as little-endian, host-independent.

    The advert encodes illuminance as a little-endian IEEE-754 float. A native
    `struct.unpack("f", ...)` byte-reverses the value on big-endian hosts,
    yielding garbage lux readings. This locks in little-endian decoding so the
    regression cannot reappear regardless of the host's byte order.
    """
    device = Mock()
    # 228.0 lux packed little-endian (distinct from its big-endian layout).
    obj4a08(struct.pack("<f", 228.0), device, "HS1BB(MI)")
    (_, value), _ = device.update_predefined_sensor.call_args
    assert value == 228.0
