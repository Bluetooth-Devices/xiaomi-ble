"""Parser for Xiaomi BLE advertisements.
This file is shamlessly copied from the following repository:
https://github.com/Ernst79/bleparser/blob/c42ae922e1abed2720c7fac993777e1bd59c0c93/package/bleparser/xiaomi.py
MIT License applies.
"""
from __future__ import annotations

import datetime
import logging
import math
import struct
import sys
from enum import Enum
from typing import Any

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection
from bluetooth_sensor_state_data import BluetoothData
from Cryptodome.Cipher import AES
from home_assistant_bluetooth import BluetoothServiceInfo
from sensor_state_data import DeviceClass, SensorLibrary, SensorUpdate, Units

from xiaomi_ble.const import CHARACTERISTIC_BATTERY, TIMEOUT_1DAY

_LOGGER = logging.getLogger(__name__)


class EncryptionScheme(Enum):

    # No encryption is needed to use this device
    NONE = "none"

    # 12 byte encryption key expected
    MIBEACON_LEGACY = "mibeacon_legacy"

    # 16 byte encryption key expected
    MIBEACON_4_5 = "mibeacon_4_5"


def to_mac(addr: bytes) -> str:
    """Return formatted MAC address"""
    return ":".join(f"{i:02X}" for i in addr)


def to_unformatted_mac(addr: str) -> str:
    """Return unformatted MAC address"""
    return "".join(f"{i:02X}" for i in addr[:])


# Device type dictionary
# {device type code: device name}
XIAOMI_TYPE_DICT = {
    0x0C3C: "CGC1",
    0x0576: "CGD1",
    0x066F: "CGDK2",
    0x0347: "CGG1",
    0x0B48: "CGG1-ENCRYPTED",
    0x03D6: "CGH1",
    0x0A83: "CGPR1",
    0x03BC: "GCLS002",
    0x0098: "HHCCJCY01",
    0x015D: "HHCCPOT002",
    0x02DF: "JQJCY01YM",
    0x0997: "JTYJGD03MI",
    0x1568: "K9B-1BTN",
    0x1569: "K9B-2BTN",
    0x0DFD: "K9B-3BTN",
    0x01AA: "LYWSDCGQ",
    0x045B: "LYWSD02",
    0x16E4: "LYWSD02MMC",
    0x055B: "LYWSD03MMC",
    0x098B: "MCCGQ02HL",
    0x06D3: "MHO-C303",
    0x0387: "MHO-C401",
    0x07F6: "MJYD02YL",
    0x04E9: "MJZNMSQ01YD",
    0x00DB: "MMC-T201-1",
    0x03DD: "MUE4094RT",
    0x0489: "M1S-T500",
    0x0A8D: "RTCGQ02LM",
    0x0863: "SJWS01LM",
    0x045C: "V-SK152",
    0x040A: "WX08ZM",
    0x04E1: "XMMF01JQD",
    0x1203: "XMWSDJ04MMC",
    0x1949: "XMWXKG01YL",
    0x098C: "XMZNMST02YD",
    0x07BF: "YLAI003",
    0x0153: "YLYK01YL",
    0x068E: "YLYK01YL-FANCL",
    0x04E6: "YLYK01YL-VENFAN",
    0x03BF: "YLYB01YL-BHFRC",
    0x03B6: "YLKG07YL/YLKG08YL",
    0x0083: "YM-K1501",
    0x0113: "YM-K1501EU",
    0x069E: "ZNMS16LM",
    0x069F: "ZNMS17LM",
    0x0380: "DSL-C08",
    0x0DE7: "SU001-T",
    0x0784: "XMZNMSBMCN03",
}

# Structured objects for data conversions
TH_STRUCT = struct.Struct("<hH")
H_STRUCT = struct.Struct("<H")
T_STRUCT = struct.Struct("<h")
TTB_STRUCT = struct.Struct("<hhB")
CND_STRUCT = struct.Struct("<H")
ILL_STRUCT = struct.Struct("<I")
LIGHT_STRUCT = struct.Struct("<I")
FMDH_STRUCT = struct.Struct("<H")
M_STRUCT = struct.Struct("<L")
P_STRUCT = struct.Struct("<H")
BUTTON_STRUCT = struct.Struct("<BBB")
FLOAT_STRUCT = struct.Struct("<f")

# Definition of lock messages
BLE_LOCK_ERROR = {
    0xC0DE0000: "frequent unlocking with incorrect password",
    0xC0DE0001: "frequent unlocking with wrong fingerprints",
    0xC0DE0002: "operation timeout (password input timeout)",
    0xC0DE0003: "lock picking",
    0xC0DE0004: "reset button is pressed",
    0xC0DE0005: "the wrong key is frequently unlocked",
    0xC0DE0006: "foreign body in the keyhole",
    0xC0DE0007: "the key has not been taken out",
    0xC0DE0008: "error NFC frequently unlocks",
    0xC0DE0009: "timeout is not locked as required",
    0xC0DE000A: "failure to unlock frequently in multiple ways",
    0xC0DE000B: "unlocking the face frequently fails",
    0xC0DE000C: "failure to unlock the vein frequently",
    0xC0DE000D: "hijacking alarm",
    0xC0DE000E: "unlock inside the door after arming",
    0xC0DE000F: "palmprints frequently fail to unlock",
    0xC0DE0010: "the safe was moved",
    0xC0DE1000: "the battery level is less than 10%",
    0xC0DE1001: "the battery is less than 5%",
    0xC0DE1002: "the fingerprint sensor is abnormal",
    0xC0DE1003: "the accessory battery is low",
    0xC0DE1004: "mechanical failure",
    0xC0DE1005: "the lock sensor is faulty",
}

BLE_LOCK_ACTION: dict[int, tuple[int, str, str]] = {
    0b0000: (1, "lock", "unlock outside the door"),
    0b0001: (0, "lock", "lock"),
    0b0010: (0, "antilock", "turn on anti-lock"),
    0b0011: (1, "antilock", "turn off anti-lock"),
    0b0100: (1, "lock", "unlock inside the door"),
    0b0101: (0, "lock", "lock inside the door"),
    0b0110: (0, "childlock", "turn on child lock"),
    0b0111: (1, "childlock", "turn off child lock"),
    0b1000: (0, "lock", "lock outside the door"),
    0b1111: (1, "lock", "abnormal"),
}

BLE_LOCK_METHOD = {
    0b0000: "bluetooth",
    0b0001: "password",
    0b0010: "biometrics",
    0b0011: "key",
    0b0100: "turntable",
    0b0101: "nfc",
    0b0110: "one-time password",
    0b0111: "two-step verification",
    0b1001: "Homekit",
    0b1000: "coercion",
    0b1010: "manual",
    0b1011: "automatic",
    0b1111: "abnormal",
}


# Advertisement conversion of measurement data
# https://iot.mi.com/new/doc/embedded-development/ble/object-definition
def obj0003(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Motion"""
    return {"motion": xobj[0], "motion timer": xobj[0]}


def obj0006(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Fingerprint"""
    if len(xobj) == 5:
        key_id_bytes = xobj[0:4]
        match_byte = xobj[4]
        if key_id_bytes == b"\x00\x00\x00\x00":
            key_id = "administrator"
        elif key_id_bytes == b"\xff\xff\xff\xff":
            key_id = "unknown operator"
        else:
            key_id = str(int.from_bytes(key_id_bytes, "little"))
        if match_byte == 0x00:
            result = "match successful"
        elif match_byte == 0x01:
            result = "match failed"
        elif match_byte == 0x02:
            result = "timeout"
        elif match_byte == 0x033:
            result = "low quality (too light, fuzzy)"
        elif match_byte == 0x04:
            result = "insufficient area"
        elif match_byte == 0x05:
            result = "skin is too dry"
        elif match_byte == 0x06:
            result = "skin is too wet"
        else:
            result = None

        fingerprint = 1 if match_byte == 0x00 else 0

        return {
            "fingerprint": fingerprint,
            "result": result,
            "key id": key_id,
        }
    else:
        return {}


def obj0007(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Door"""
    door_byte = xobj[0]
    if door_byte == 0x00:
        action = "open the door"
        door = 1
    elif door_byte == 0x01:
        action = "close the door"
        door = 0
    elif door_byte == 0x02:
        action = "timeout, not closed"
        door = 1
    elif door_byte == 0x03:
        action = "knock on the door"
        door = 0
    elif door_byte == 0x04:
        action = "pry the door"
        door = 1
    elif door_byte == 0x05:
        action = "door stuck"
        door = 0
    else:
        return {}
    return {"door": door, "door action": action}


def obj0008(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """armed away"""
    returnData: dict[str, Any] = {}
    value = xobj[0] ^ 1
    returnData.update({"armed away": value})
    if len(xobj) == 5:
        timestamp = datetime.datetime.utcfromtimestamp(
            int.from_bytes(xobj[1:], "little")
        ).isoformat()
        returnData.update({"timestamp": timestamp})
    # Lift up door handle outside the door sends this event from DSL-C08.
    if device_type == "DSL-C08":
        return {
            "lock": value,
            "locktype": "lock",
            "action": "lock outside the door",
            "method": "manual",
            "error": None,
            "key id": None,
            "timestamp": None,
        }
    return returnData


def obj0010(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Toothbrush"""
    if xobj[0] == 0:
        if len(xobj) == 1:
            return {"toothbrush": 1}
        else:
            return {"toothbrush": 1, "counter": xobj[1]}
    else:
        if len(xobj) == 1:
            return {"toothbrush": 0}
        else:
            return {"toothbrush": 0, "score": xobj[1]}


def obj000b(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Lock"""
    if len(xobj) == 9:
        action_int = xobj[0] & 0x0F
        method_int = xobj[0] >> 4
        key_id = int.from_bytes(xobj[1:5], "little")

        timestamp = datetime.datetime.utcfromtimestamp(
            int.from_bytes(xobj[5:], "little")
        ).isoformat()

        # all keys except Bluetooth have only 65536 values
        error = BLE_LOCK_ERROR.get(key_id)
        if error is None and method_int > 0:
            key_id &= 0xFFFF

        if action_int not in BLE_LOCK_ACTION or method_int not in BLE_LOCK_METHOD:
            return {}

        lock = BLE_LOCK_ACTION[action_int][0]
        # Decouple lock by type on some devices
        lock_type = "lock"
        if device_type == "ZNMS17LM":
            lock_type = BLE_LOCK_ACTION[action_int][1]

        action = BLE_LOCK_ACTION[action_int][2]
        method = BLE_LOCK_METHOD[method_int]

        # Biometric unlock then disarm
        if device_type == "DSL-C08":
            if method == "password":
                if 5000 <= key_id < 6000:
                    method = "one-time password"

        return {
            lock_type: lock,
            "locktype": lock_type,
            "action": action,
            "method": method,
            "error": error,
            "key id": hex(key_id),
            "timestamp": timestamp,
        }
    else:
        return {}


def obj000f(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Moving with light"""
    if len(xobj) == 3:
        (illum,) = LIGHT_STRUCT.unpack(xobj + b"\x00")

        if device_type in ["MJYD02YL", "RTCGQ02LM"]:
            # MJYD02YL:  1 - moving no light, 100 - moving with light
            # RTCGQ02LM: 0 - moving no light, 256 - moving with light
            return {"motion": 1, "motion timer": 1, "light": int(illum >= 100)}
        elif device_type == "CGPR1":
            # CGPR1:     moving, value is illumination in lux
            device.update_predefined_sensor(SensorLibrary.LIGHT__LIGHT_LUX, illum)
            return {"motion": 1, "motion timer": 1}
        else:
            return {}
    else:
        return {}


def obj1001(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """button"""
    if len(xobj) == 3:
        (button_type, value, press) = BUTTON_STRUCT.unpack(xobj)

        # remote command and remote binary
        remote_command = None
        fan_remote_command = None
        ven_fan_remote_command = None
        bathroom_remote_command = None
        one_btn_switch = None
        two_btn_switch_left = None
        two_btn_switch_right = None
        three_btn_switch_left = None
        three_btn_switch_middle = None
        three_btn_switch_right = None
        cube_direction = None
        remote_binary = None

        if button_type == 0:
            remote_command = "on"
            fan_remote_command = "fan toggle"
            ven_fan_remote_command = "swing"
            bathroom_remote_command = "stop"
            one_btn_switch = "toggle"
            two_btn_switch_left = "toggle"
            three_btn_switch_left = "toggle"
            cube_direction = "right"
            remote_binary = 1
        elif button_type == 1:
            remote_command = "off"
            fan_remote_command = "light toggle"
            ven_fan_remote_command = "power toggle"
            bathroom_remote_command = "air exchange"
            two_btn_switch_right = "toggle"
            three_btn_switch_middle = "toggle"
            cube_direction = "left"
            remote_binary = 0
        elif button_type == 2:
            remote_command = "sun"
            fan_remote_command = "wind speed"
            ven_fan_remote_command = "timer 60 minutes"
            bathroom_remote_command = "fan"
            two_btn_switch_left = "toggle"
            two_btn_switch_right = "toggle"
            three_btn_switch_right = "toggle"
            remote_binary = None
        elif button_type == 3:
            remote_command = "+"
            fan_remote_command = "color temperature"
            ven_fan_remote_command = "strong wind speed"
            bathroom_remote_command = "speed +"
            three_btn_switch_left = "toggle"
            three_btn_switch_middle = "toggle"
            remote_binary = 1
        elif button_type == 4:
            remote_command = "m"
            fan_remote_command = "wind mode"
            ven_fan_remote_command = "timer 30 minutes"
            bathroom_remote_command = "speed -"
            three_btn_switch_middle = "toggle"
            three_btn_switch_right = "toggle"
            remote_binary = None
        elif button_type == 5:
            remote_command = "-"
            fan_remote_command = "brightness"
            ven_fan_remote_command = "low wind speed"
            bathroom_remote_command = "dry"
            three_btn_switch_left = "toggle"
            three_btn_switch_right = "toggle"
            remote_binary = 1
        elif button_type == 6:
            bathroom_remote_command = "light toggle"
            three_btn_switch_left = "toggle"
            three_btn_switch_middle = "toggle"
            three_btn_switch_right = "toggle"
        elif button_type == 7:
            bathroom_remote_command = "swing"
        elif button_type == 8:
            bathroom_remote_command = "heat"

        # press type and dimmer
        button_press_type = "no press"
        btn_switch_press_type = "no press"
        dimmer = None

        if press == 0:
            button_press_type = "single press"
            btn_switch_press_type = "single press"
        elif press == 1:
            button_press_type = "double press"
            btn_switch_press_type = "long press"
        elif press == 2:
            button_press_type = "long press"
            btn_switch_press_type = "double press"
        elif press == 3:
            if button_type == 0:
                button_press_type = "short press"
                dimmer = value
            if button_type == 1:
                button_press_type = "long press"
                dimmer = value
        elif press == 4:
            if button_type == 0:
                if value <= 127:
                    button_press_type = "rotate right"
                    dimmer = value
                else:
                    button_press_type = "rotate left"
                    dimmer = 256 - value
            elif button_type <= 127:
                button_press_type = "rotate right (pressed)"
                dimmer = button_type
            else:
                button_press_type = "rotate left (pressed)"
                dimmer = 256 - button_type
        elif press == 5:
            button_press_type = "short press"
        elif press == 6:
            button_press_type = "long press"

        # return device specific output
        result: dict[str, Any] = {}
        if device_type in ["RTCGQ02LM", "YLAI003", "JTYJGD03MI", "SJWS01LM"]:
            result["button"] = button_press_type
        elif device_type == "XMMF01JQD":
            result["button"] = cube_direction
        elif device_type == "YLYK01YL":
            result["remote"] = remote_command
            result["button"] = button_press_type
            if remote_binary is not None:
                if button_press_type == "single press":
                    result["remote single press"] = remote_binary
                else:
                    result["remote long press"] = remote_binary
        elif device_type == "YLYK01YL-FANRC":
            result["fan remote"] = fan_remote_command
            result["button"] = button_press_type
        elif device_type == "YLYK01YL-VENFAN":
            result["ventilator fan remote"] = ven_fan_remote_command
            result["button"] = button_press_type
        elif device_type == "YLYB01YL-BHFRC":
            result["bathroom heater remote"] = bathroom_remote_command
            result["button"] = button_press_type
        elif device_type == "YLKG07YL/YLKG08YL":
            result["dimmer"] = dimmer
            result["button"] = button_press_type
        elif device_type == "K9B-1BTN":
            result["button switch"] = btn_switch_press_type
            result["one btn switch"] = one_btn_switch
        elif device_type == "K9B-2BTN":
            result["button switch"] = btn_switch_press_type
            if two_btn_switch_left:
                result["two btn switch left"] = two_btn_switch_left
            if two_btn_switch_right:
                result["two btn switch right"] = two_btn_switch_right
        elif device_type == "K9B-3BTN":
            result["button switch"] = btn_switch_press_type
            if three_btn_switch_left:
                result["three btn switch left"] = three_btn_switch_left
            if three_btn_switch_middle:
                result["three btn switch middle"] = three_btn_switch_middle
            if three_btn_switch_right:
                result["three btn switch right"] = three_btn_switch_right

        return result

    else:
        return {}


def obj1004(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Temperature"""
    if len(xobj) == 2:
        (temp,) = T_STRUCT.unpack(xobj)
        device.update_predefined_sensor(SensorLibrary.TEMPERATURE__CELSIUS, temp / 10)
    return {}


def obj1005(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Switch and Temperature"""
    device.update_predefined_sensor(SensorLibrary.TEMPERATURE__CELSIUS, xobj[1])
    return {"switch": xobj[0]}


def obj1006(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Humidity"""
    if len(xobj) == 2:
        (humi,) = H_STRUCT.unpack(xobj)
        device.update_predefined_sensor(SensorLibrary.HUMIDITY__PERCENTAGE, humi / 10)
    return {}


def obj1007(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Illuminance"""
    if len(xobj) == 3:
        (illum,) = ILL_STRUCT.unpack(xobj + b"\x00")
        if device_type in ["MJYD02YL", "MCCGQ02HL"]:
            # 100 means light, else dark (0 or 1)
            # MCCGQ02HL might use obj1018 for light sensor, just added here to be sure.
            return {"light": 1 if illum == 100 else 0}
        elif device_type in ["HHCCJCY01", "GCLS002"]:
            # illumination in lux
            device.update_predefined_sensor(SensorLibrary.LIGHT__LIGHT_LUX, illum)
        else:
            return {}
    return {}


def obj1008(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Moisture"""
    device.update_sensor(
        key="moisture",
        name="Moisture",
        native_unit_of_measurement=Units.PERCENTAGE,
        native_value=xobj[0],
    )
    return {}


def obj1009(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Conductivity"""
    if len(xobj) == 2:
        (cond,) = CND_STRUCT.unpack(xobj)
        device.update_sensor(
            key="conductivity",
            name="Conductivity",
            native_unit_of_measurement=Units.CONDUCTIVITY,
            native_value=cond,
        )
    return {}


def obj1010(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Formaldehyde"""
    if len(xobj) == 2:
        (fmdh,) = FMDH_STRUCT.unpack(xobj)
        device.update_sensor(
            key="formaldehyde",
            name="Formaldehyde",
            native_unit_of_measurement=Units.CONCENTRATION_MILLIGRAMS_PER_CUBIC_METER,
            native_value=fmdh / 100,
        )
        return {}
    else:
        return {}


def obj1012(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Switch"""
    return {"switch": xobj[0]}


def obj1013(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Consumable (in percent)"""
    device.update_sensor(
        key="consumable",
        name="Consumable",
        native_unit_of_measurement=Units.PERCENTAGE,
        native_value=xobj[0],
    )
    return {}


def obj1014(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Moisture"""
    return {"moisture": xobj[0]}


def obj1015(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Smoke"""
    return {"smoke detector": xobj[0]}


def obj1017(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Motion"""
    if len(xobj) == 4:
        (motion,) = M_STRUCT.unpack(xobj)
        # seconds since last motion detected message (not used, we use motion
        # timer in obj000f)
        # 0 = motion detected
        return {"motion": 1 if motion == 0 else 0}
    else:
        return {}


def obj1018(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Light intensity"""
    return {"light": xobj[0]}


def obj1019(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Door/Window sensor"""
    open_obj = xobj[0]
    if open_obj == 0:
        opening = 1
        status = "opened"
    elif open_obj == 1:
        opening = 0
        status = "closed"
    elif open_obj == 2:
        opening = 1
        status = "closing timeout"
    elif open_obj == 3:
        opening = 1
        status = "device reset"
    else:
        opening = 0
        status = None
    return {"opening": opening, "status": status}


def obj100a(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Battery"""
    batt = xobj[0]
    volt = 2.2 + (3.1 - 2.2) * (batt / 100)
    device.update_predefined_sensor(SensorLibrary.BATTERY__PERCENTAGE, batt)
    device.update_sensor(
        key="voltage",
        name="Voltage",
        device_class=DeviceClass.VOLTAGE,
        native_unit_of_measurement=Units.ELECTRIC_POTENTIAL_VOLT,
        native_value=volt,
    )
    return {}


def obj100d(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Temperature and humidity"""
    if len(xobj) == 4:
        (temp, humi) = TH_STRUCT.unpack(xobj)
        device.update_predefined_sensor(SensorLibrary.TEMPERATURE__CELSIUS, temp / 10)
        device.update_predefined_sensor(SensorLibrary.HUMIDITY__PERCENTAGE, humi / 10)
    return {}


def obj100e(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Lock common attribute"""
    # https://iot.mi.com/new/doc/accesses/direct-access/embedded-development/ble/object-definition#%E9%94%81%E5%B1%9E%E6%80%A7
    if len(xobj) == 1:
        # Unlock by type on some devices
        if device_type == "DSL-C08":
            lock_attribute = int.from_bytes(xobj, "little")
            lock = lock_attribute & 0x01 ^ 1
            childlock = lock_attribute >> 3 ^ 1
            return {"childlock": childlock, "lock": lock}
    return {}


def obj2000(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Body temperature"""
    if len(xobj) == 5:
        (temp1, temp2, bat) = TTB_STRUCT.unpack(xobj)
        # Body temperature is calculated from the two measured temperatures.
        # Formula is based on approximation based on values in the app in
        # the range 36.5 - 37.8.
        body_temp = (
            3.71934 * pow(10, -11) * math.exp(0.69314 * temp1 / 100)
            - (1.02801 * pow(10, -8) * math.exp(0.53871 * temp2 / 100))
            + 36.413
        )
        device.update_predefined_sensor(SensorLibrary.TEMPERATURE__CELSIUS, body_temp)
        device.update_predefined_sensor(SensorLibrary.BATTERY__PERCENTAGE, bat)

    return {}


# The following data objects are device specific. For now only
#  added for LYWSD02MMC, XMWSDJ04MMC, XMWXKG01YL
# https://miot-spec.org/miot-spec-v2/instances?status=all
def obj4803(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Battery"""
    device.update_predefined_sensor(SensorLibrary.BATTERY__PERCENTAGE, xobj[0])
    return {}


def obj4a01(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Low Battery"""
    low_batt = xobj[0]
    return {"low battery": low_batt}


def obj4c02(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Humidity"""
    if len(xobj) == 1:
        humi = xobj[0]
        device.update_predefined_sensor(SensorLibrary.HUMIDITY__PERCENTAGE, humi)
    return {}


def obj4c01(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Temperature"""
    if len(xobj) == 4:
        temp = FLOAT_STRUCT.unpack(xobj)[0]
        device.update_predefined_sensor(SensorLibrary.TEMPERATURE__CELSIUS, temp)
    return {}


def obj4c08(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Humidity"""
    if len(xobj) == 4:
        humi = FLOAT_STRUCT.unpack(xobj)[0]
        device.update_predefined_sensor(SensorLibrary.HUMIDITY__PERCENTAGE, humi)
    return {}


def obj4c14(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Mode"""
    mode = xobj[0]
    return {"mode": mode}


def obj4e0c(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Click"""
    result: dict[str, Any] = {}

    click = xobj[0]

    if click == 1:
        result["two_btn_switch_left"] = "toggle"
    elif click == 2:
        result["two_btn_switch_right"] = "toggle"
    elif click == 3:
        result["two_btn_switch_left"] = "toggle"
        result["two_btn_switch_right"] = "toggle"

    return result


def obj4e0d(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Double Click"""
    click = xobj[0]
    btn_switch_press_type: str | None = "double press"
    two_btn_switch_left = None
    two_btn_switch_right = None
    if click == 1:
        two_btn_switch_left = "toggle"
    elif click == 2:
        two_btn_switch_right = "toggle"
    elif click == 3:
        two_btn_switch_left = "toggle"
        two_btn_switch_right = "toggle"
    else:
        btn_switch_press_type = None
    return {
        "two btn switch left": two_btn_switch_left,
        "two btn switch right": two_btn_switch_right,
        "button switch": btn_switch_press_type,
    }


def obj4e0e(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Long Press"""
    click = xobj[0]
    btn_switch_press_type: str | None = "long press"
    two_btn_switch_left = None
    two_btn_switch_right = None
    if click == 1:
        two_btn_switch_left = "toggle"
    elif click == 2:
        two_btn_switch_right = "toggle"
    elif click == 3:
        two_btn_switch_left = "toggle"
        two_btn_switch_right = "toggle"
    else:
        btn_switch_press_type = None
    return {
        "two btn switch left": two_btn_switch_left,
        "two btn switch right": two_btn_switch_right,
        "button switch": btn_switch_press_type,
    }


# Dataobject dictionary
# {dataObject_id: (converter}
xiaomi_dataobject_dict = {
    0x0003: obj0003,
    0x0006: obj0006,
    0x0007: obj0007,
    0x0008: obj0008,
    0x0010: obj0010,
    0x000B: obj000b,
    0x000F: obj000f,
    0x1001: obj1001,
    0x1004: obj1004,
    0x1005: obj1005,
    0x1006: obj1006,
    0x1007: obj1007,
    0x1008: obj1008,
    0x1009: obj1009,
    0x1010: obj1010,
    0x1012: obj1012,
    0x1013: obj1013,
    0x1014: obj1014,
    0x1015: obj1015,
    0x1017: obj1017,
    0x1018: obj1018,
    0x1019: obj1019,
    0x100A: obj100a,
    0x100D: obj100d,
    0x100E: obj100e,
    0x2000: obj2000,
    0x4803: obj4803,
    0x4A01: obj4a01,
    0x4C01: obj4c01,
    0x4C02: obj4c02,
    0x4C08: obj4c08,
    0x4C14: obj4c14,
    0x4E0C: obj4e0c,
    0x4E0D: obj4e0d,
    0x4E0E: obj4e0e,
}


def decode_temps(packet_value: int) -> float:
    """Decode potential negative temperatures."""
    # https://github.com/Thrilleratplay/XiaomiWatcher/issues/2
    if packet_value & 0x800000:
        return float((packet_value ^ 0x800000) / -10000)
    return float(packet_value / 10000)


def decode_temps_probes(packet_value: int) -> float:
    """Filter potential negative temperatures."""
    if packet_value < 0:
        return 0.0
    return float(packet_value / 100)


class XiaomiBluetoothDeviceData(BluetoothData):
    """Data for Xiaomi BLE sensors."""

    def __init__(self, bindkey: bytes | None = None) -> None:
        super().__init__()
        self.bindkey = bindkey

        # Data that we know how to parse but don't yet map to the SensorData model.
        self.unhandled: dict[str, Any] = {}

        # The type of encryption to expect, based on flags in the bluetooth
        # frame.
        self.encryption_scheme = EncryptionScheme.NONE

        # If true, then we know the actual MAC of the device.
        # On macOS, we don't unless the device includes it in the advertisement
        # (CoreBluetooth uses UUID's generated by CoreBluetooth instead of the MAC)
        self.mac_known = sys.platform != "darwin"

        # If true then we have used the provided encryption key to decrypt at least
        # one payload.
        # If false then we have either not seen an encrypted payload, the key is wrong
        # or encryption is not in use
        self.bindkey_verified = False

        # If this is True, then we have not seen an advertisement with a payload
        # Until we see a payload, we can't tell if this device is encrypted or not
        self.pending = True

        # The last service_info we saw that had a payload
        # We keep this to help in reauth flows where we want to reprocess and old
        # value with a new bindkey.
        self.last_service_info: BluetoothServiceInfo | None = None

    def supported(self, data: BluetoothServiceInfo) -> bool:
        if not super().supported(data):
            return False

        # Where a device uses encryption we need to known its actual MAC address.
        # As the encryption uses it as part of the nonce.
        # On macOS we instead only know its CoreBluetooth UUID.
        # It seems its impossible to automatically get that in the general case.
        # So devices do duplicate the MAC in the advertisement, we use that
        # when we can on macOS.
        # We may want to ask the user for the MAC address during config flow
        # For now, just hide these devices for macOS users.
        if self.encryption_scheme != EncryptionScheme.NONE:
            if not self.mac_known:
                return False

        return True

    def _start_update(self, service_info: BluetoothServiceInfo) -> None:
        """Update from BLE advertisement data."""
        _LOGGER.debug("Parsing Xiaomi BLE advertisement data: %s", service_info)
        self.set_device_manufacturer("Xiaomi")
        self.set_device_name(service_info.name)

        mac_readable = service_info.address
        if len(mac_readable) != 17 and mac_readable[2] != ":":
            # On macOS we get a UUID, which is useless for MiBeacons
            mac_readable = "00:00:00:00:00:00"

        mac = bytes.fromhex(mac_readable.replace(":", ""))

        for id, data in service_info.service_data.items():
            if self._parse_xiaomi(service_info.name, data, mac):
                self.last_service_info = service_info

    def _parse_xiaomi(self, name: str, data: bytes, source_mac: bytes) -> bool:
        """Parser for Xiaomi sensors"""
        # check for adstruc length
        i = 5  # till Frame Counter
        msg_length = len(data)
        if msg_length < i:
            _LOGGER.debug("Invalid data length (initial check), adv: %s", data.hex())
            return False

        # extract frame control bits
        frctrl = data[0] + (data[1] << 8)
        frctrl_mesh = (frctrl >> 7) & 1  # mesh device
        frctrl_version = frctrl >> 12  # version
        frctrl_auth_mode = (frctrl >> 10) & 3
        frctrl_solicited = (frctrl >> 9) & 1
        frctrl_registered = (frctrl >> 8) & 1
        frctrl_object_include = (frctrl >> 6) & 1
        frctrl_capability_include = (frctrl >> 5) & 1
        frctrl_mac_include = (frctrl >> 4) & 1  # check for MAC address in data
        frctrl_is_encrypted = (frctrl >> 3) & 1  # check for encryption being used
        frctrl_request_timing = frctrl & 1  # old version

        # Check that device is not of mesh type
        if frctrl_mesh != 0:
            _LOGGER.debug(
                "Device is a mesh type device, which is not supported. Data: %s",
                data.hex(),
            )
            return False

        # Check that version is 2 or higher
        if frctrl_version < 2:
            _LOGGER.debug(
                "Device is using old data format, which is not supported. Data: %s",
                data.hex(),
            )
            return False

        # Check that MAC in data is the same as the source MAC
        if frctrl_mac_include != 0:
            i += 6
            if msg_length < i:
                _LOGGER.debug("Invalid data length (in MAC check), adv: %s", data.hex())
                return False
            xiaomi_mac_reversed = data[5:11]
            xiaomi_mac = xiaomi_mac_reversed[::-1]
            if sys.platform != "darwin" and xiaomi_mac != source_mac:
                _LOGGER.debug(
                    "MAC address doesn't match data frame. Expected: %s, Got: %s)",
                    to_mac(xiaomi_mac),
                    to_mac(source_mac),
                )
                return False
            self.mac_known = True
        else:
            xiaomi_mac = source_mac

        # determine the device type
        device_id = data[2] + (data[3] << 8)
        try:
            device_type = XIAOMI_TYPE_DICT[device_id]
        except KeyError:
            _LOGGER.info(
                "BLE ADV from UNKNOWN Xiaomi device: MAC: %s, ADV: %s",
                source_mac,
                data.hex(),
            )
            _LOGGER.debug("Unknown Xiaomi device found. Data: %s", data.hex())
            return False

        self.set_device_type(device_type)

        self.device_id = device_id
        self.device_type = device_type

        packet_id = data[4]

        sinfo = "MiVer: " + str(frctrl_version)
        sinfo += ", DevID: " + hex(device_id) + " : " + device_type
        sinfo += ", FnCnt: " + str(packet_id)
        if frctrl_request_timing != 0:
            sinfo += ", Request timing"
        if frctrl_registered != 0:
            sinfo += ", Registered and bound"
        else:
            sinfo += ", Not bound"
        if frctrl_solicited != 0:
            sinfo += ", Request APP to register and bind"
        if frctrl_auth_mode == 0:
            sinfo += ", Old version certification"
        elif frctrl_auth_mode == 1:
            sinfo += ", Safety certification"
        elif frctrl_auth_mode == 2:
            sinfo += ", Standard certification"

        # check for capability byte present
        if frctrl_capability_include != 0:
            i += 1
            if msg_length < i:
                _LOGGER.debug(
                    "Invalid data length (in capability check), adv: %s", data.hex()
                )
                return False
            capability_types = data[i - 1]
            sinfo += ", Capability: " + hex(capability_types)
            if (capability_types & 0x20) != 0:
                i += 1
                if msg_length < i:
                    _LOGGER.debug(
                        "Invalid data length (in capability type check), adv: %s",
                        data.hex(),
                    )
                    return False
                capability_io = data[i - 1]
                sinfo += ", IO: " + hex(capability_io)

        # check that data contains object
        if frctrl_object_include == 0:
            # data does not contain Object
            _LOGGER.debug("Advertisement doesn't contain payload, adv: %s", data.hex())
            return False

        self.pending = False

        # check for encryption
        if frctrl_is_encrypted != 0:
            sinfo += ", Encryption"
            firmware = "Xiaomi (MiBeacon V" + str(frctrl_version) + " encrypted)"
            if frctrl_version <= 3:
                self.encryption_scheme = EncryptionScheme.MIBEACON_LEGACY
                payload = self._decrypt_mibeacon_legacy(data, i, xiaomi_mac)
            else:
                self.encryption_scheme = EncryptionScheme.MIBEACON_4_5
                payload = self._decrypt_mibeacon_v4_v5(data, i, xiaomi_mac)
        else:  # No encryption
            # check minimum advertisement length with data
            firmware = "Xiaomi (MiBeacon V" + str(frctrl_version) + ")"
            sinfo += ", No encryption"
            if msg_length < i + 3:
                _LOGGER.debug(
                    "Invalid data length (in non-encrypted data), adv: %s",
                    data.hex(),
                )
                return False
            payload = data[i:]

        self.set_device_type(device_type)
        self.set_device_sw_version(firmware)

        if payload is not None:
            sinfo += ", Object data: " + payload.hex()
            # loop through parse_xiaomi payload
            payload_start = 0
            payload_length = len(payload)
            # assume that the data may have several values of different types
            while payload_length >= payload_start + 3:
                obj_typecode = payload[payload_start] + (
                    payload[payload_start + 1] << 8
                )
                obj_length = payload[payload_start + 2]
                next_start = payload_start + 3 + obj_length
                if payload_length < next_start:
                    # The payload segments are corrupted - if this is legacy encryption
                    # then the key is probably just wrong
                    # V4 encryption has an authentication tag, so we don't apply the
                    # same restriction there.
                    if self.encryption_scheme == EncryptionScheme.MIBEACON_LEGACY:
                        self.bindkey_verified = False
                    _LOGGER.debug(
                        "Invalid payload data length, payload: %s", payload.hex()
                    )
                    break
                this_start = payload_start + 3
                dobject = payload[this_start:next_start]
                if obj_length != 0:
                    resfunc = xiaomi_dataobject_dict.get(obj_typecode, None)
                    if resfunc:
                        self.unhandled.update(resfunc(dobject, self, device_type))
                    else:
                        _LOGGER.info(
                            "%s, UNKNOWN dataobject in payload! Adv: %s",
                            sinfo,
                            data.hex(),
                        )
                payload_start = next_start

        return True

    def _decrypt_mibeacon_v4_v5(
        self, data: bytes, i: int, xiaomi_mac: bytes
    ) -> bytes | None:
        """decrypt MiBeacon v4/v5 encrypted advertisements"""
        # check for minimum length of encrypted advertisement
        if len(data) < i + 9:
            _LOGGER.debug("Invalid data length (for decryption), adv: %s", data.hex())
            return None

        if not self.bindkey:
            self.bindkey_verified = False
            _LOGGER.debug("Encryption key not set and adv is encrypted")
            return None

        if not self.bindkey or len(self.bindkey) != 16:
            self.bindkey_verified = False
            _LOGGER.error("Encryption key should be 16 bytes (32 characters) long")
            return None

        nonce = b"".join([xiaomi_mac[::-1], data[2:5], data[-7:-4]])
        aad = b"\x11"
        token = data[-4:]
        cipherpayload = data[i:-7]
        cipher = AES.new(self.bindkey, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(aad)

        try:
            decrypted_payload = cipher.decrypt_and_verify(cipherpayload, token)
        except ValueError as error:
            self.bindkey_verified = False
            _LOGGER.warning("Decryption failed: %s", error)
            _LOGGER.debug("token: %s", token.hex())
            _LOGGER.debug("nonce: %s", nonce.hex())
            _LOGGER.debug("cipherpayload: %s", cipherpayload.hex())
            return None
        if decrypted_payload is None:
            self.bindkey_verified = False
            _LOGGER.error(
                "Decryption failed for %s, decrypted payload is None",
                to_mac(xiaomi_mac),
            )
            return None
        self.bindkey_verified = True
        return decrypted_payload

    def _decrypt_mibeacon_legacy(
        self, data: bytes, i: int, xiaomi_mac: bytes
    ) -> bytes | None:
        """decrypt MiBeacon v2/v3 encrypted advertisements"""
        # check for minimum length of encrypted advertisement
        if len(data) < i + 7:
            _LOGGER.debug("Invalid data length (for decryption), adv: %s", data.hex())
            return None

        if not self.bindkey:
            self.bindkey_verified = False
            _LOGGER.debug("Encryption key not set and adv is encrypted")
            return None

        if len(self.bindkey) != 12:
            self.bindkey_verified = False
            _LOGGER.error("Encryption key should be 12 bytes (24 characters) long")
            return None

        key = b"".join([self.bindkey[0:6], bytes.fromhex("8d3d3c97"), self.bindkey[6:]])

        nonce = b"".join([data[0:5], data[-4:-1], xiaomi_mac[::-1][:-1]])
        aad = b"\x11"
        cipherpayload = data[i:-4]
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(aad)

        try:
            decrypted_payload = cipher.decrypt(cipherpayload)
        except ValueError as error:
            self.bindkey_verified = False
            _LOGGER.warning("Decryption failed: %s", error)
            _LOGGER.debug("nonce: %s", nonce.hex())
            _LOGGER.debug("cipherpayload: %s", cipherpayload.hex())
            return None
        if decrypted_payload is None:
            self.bindkey_verified = False
            _LOGGER.warning(
                "Decryption failed for %s, decrypted payload is None",
                to_mac(xiaomi_mac),
            )
            return None
        self.bindkey_verified = True
        return decrypted_payload

    def poll_needed(
        self, service_info: BluetoothServiceInfo, last_poll: float | None
    ) -> bool:
        """
        This is called every time we get a service_info for a device. It means the
        device is working and online. If 24 hours has passed, it may be a good
        time to poll the device.
        """
        if self.device_id != 0x0098:
            return False

        return not last_poll or last_poll > TIMEOUT_1DAY

    async def async_poll(self, ble_device: BLEDevice) -> SensorUpdate:
        """
        Poll the device to retrieve any values we can't get from passive listening.
        """
        if self.device_id == 0x0098:
            client = await establish_connection(
                BleakClient, ble_device, ble_device.address
            )
            try:
                battery_char = client.services.get_characteristic(
                    CHARACTERISTIC_BATTERY
                )
                payload = await client.read_gatt_char(battery_char)
            finally:
                await client.disconnect()

            self.set_device_sw_version(payload[2:].decode("utf-8"))
            self.update_predefined_sensor(SensorLibrary.BATTERY__PERCENTAGE, payload[0])

        return self._finish_update()
