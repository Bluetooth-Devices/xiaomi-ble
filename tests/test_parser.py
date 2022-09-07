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
    SensorDescription,
    SensorDeviceInfo,
    SensorUpdate,
    SensorValue,
    Units,
)

from xiaomi_ble.parser import EncryptionScheme, XiaomiBluetoothDeviceData

KEY_TEMPERATURE = DeviceKey(key="temperature", device_id=None)
KEY_HUMIDITY = DeviceKey(key="humidity", device_id=None)
KEY_BATTERY = DeviceKey(key="battery", device_id=None)
KEY_SIGNAL_STRENGTH = DeviceKey(key="signal_strength", device_id=None)
KEY_ILLUMINANCE = DeviceKey(key="illuminance", device_id=None)
KEY_CONDUCTIVITY = DeviceKey(key="conductivity", device_id=None)
KEY_MOISTURE = DeviceKey(key="moisture", device_id=None)
KEY_SMOKE = DeviceKey(key="smoke", device_id=None)


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


def test_blank_advertisemnts_then_encrypted():
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
    assert device.pending is False


def test_blank_advertisemnts_then_unencrypted():
    """Test that we can reject empty payloads."""

    # NOTE: THIS IS SYNTHETIC TEST DATA - i took a known unecrypted device and flipped
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


def test_blank_advertisemnts_then_encrypted_last_service_info():
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


def test_blank_advertisemnts_then_unencrypted_last_service_info():
    """Test that we can capture valid service info records."""

    # NOTE: THIS IS SYNTHETIC TEST DATA - i took a known unecrypted device and flipped
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
                name="Humidity", device_key=KEY_HUMIDITY, native_value=46.7
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
    data_string = b"P0\xe1\x04\x8eT\xd3\xe60S\xe2\x01\x10\x03\x00\x00\x00"
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
    )

    # FIXME
    # assert sensor_msg["button"] == "left"


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
        title="Thermometer 9CBC (JTYJGD03MI)",
        devices={
            None: SensorDeviceInfo(
                name="Thermometer 9CBC",
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
        title="Thermometer 9CBC (JTYJGD03MI)",
        devices={
            None: SensorDeviceInfo(
                name="Thermometer 9CBC",
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
    )

    assert device.unhandled == {"button": "single press"}


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
                device_class=None,
                native_unit_of_measurement=Units.CONDUCTIVITY,
            ),
            KEY_MOISTURE: SensorDescription(
                device_key=KEY_MOISTURE,
                device_class=None,
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
    )

    assert device.unhandled == {
        "motion": 1,
        "motion timer": 1,
    }


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
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )

    device.unhandled == {
        "toothbrush": 1,
        "counter": 3,
    }


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
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )

    assert device.unhandled == {
        "fingerprint": 1,
        "result": "match successful",
        "key id": "unknown operator",
    }


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
        },
        entity_values={
            KEY_SIGNAL_STRENGTH: SensorValue(
                name="Signal Strength", device_key=KEY_SIGNAL_STRENGTH, native_value=-60
            ),
        },
    )

    assert device.unhandled == {
        "lock": 1,
        "action": "unlock outside the door",
        "method": "biometrics",
        "error": None,
        "key id": "0x2",
        "timestamp": "2021-09-01T09:14:36",
        "locktype": "lock",
    }


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
    )

    assert device.unhandled == {
        "remote": "on",
        "button": "single press",
        "remote single press": 1,
    }


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
    )

    assert device.unhandled == {"dimmer": 1, "button": "short press"}


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
    )

    assert device.unhandled == {"dimmer": 1, "button": "rotate left"}


def test_Xiaomi_K9B():
    """Test Xiaomi parser for K9B."""


def test_Xiaomi_M1SBB_MI_obj4804():
    """Test Xiaomi parser for Linptech M1SBB(MI) with obj4804."""
    data_string = b"XY\x89\x18\x9ag\xe5f8\xc1\xa4\x9d\xd9z\xf3&\x00\x00\xc8\xa6\x0b\xd5"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:66:E5:67")
    bindkey = "0fdcc30fe9289254876b5ef7c11ef1f0"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor E567 (M1SBB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor E567",
                manufacturer="Xiaomi",
                model="M1SBB(MI)",
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

    assert device.unhandled == {
        "opening": 1,
    }


def test_Xiaomi_M1SBB_MI_obj4a12():
    """Test Xiaomi parser for Linptech M1SBB(MI) with obj4a12."""
    data_string = b"XY\x89\x18vg\xe5f8\xc1\xa4\xaa\x89\x02\xba&\x00\x00#\xc3\xbc\xa8"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:66:E5:67")
    bindkey = "0fdcc30fe9289254876b5ef7c11ef1f0"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor E567 (M1SBB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor E567",
                manufacturer="Xiaomi",
                model="M1SBB(MI)",
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

    assert device.unhandled == {
        "opening": 1,
    }


def test_Xiaomi_M1SBB_MI_obj4a13():
    """Test Xiaomi parser for Linptech M1SBB(MI) with obj4a13."""
    data_string = b"XY\x89\x18\x91g\xe5f8\xc1\xa4\xd6\x12\rm&\x00\x00o\xbc\x0c\xb4"
    advertisement = bytes_to_service_info(data_string, address="A4:C1:38:66:E5:67")
    bindkey = "0fdcc30fe9289254876b5ef7c11ef1f0"

    device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex(bindkey))
    assert device.supported(advertisement)
    assert device.bindkey_verified
    assert device.update(advertisement) == SensorUpdate(
        title="Door/Window Sensor E567 (M1SBB(MI))",
        devices={
            None: SensorDeviceInfo(
                name="Door/Window Sensor E567",
                manufacturer="Xiaomi",
                model="M1SBB(MI)",
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

    assert device.unhandled == {
        "button": 1,
    }


def test_Xiaomi_XMWXKG01YL():
    """Test Xiaomi parser for XMWXKG01YL."""


def test_Xiaomi_DSL_C08():
    """Test Xiaomi parser for DSL-C08."""


def test_can_create():
    XiaomiBluetoothDeviceData()
