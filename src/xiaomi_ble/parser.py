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
from typing import Any

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection
from bluetooth_data_tools import short_address
from bluetooth_sensor_state_data import BluetoothData
from Cryptodome.Cipher import AES
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from home_assistant_bluetooth import BluetoothServiceInfo
from sensor_state_data import (
    BinarySensorDeviceClass,
    SensorLibrary,
    SensorUpdate,
    Units,
)

from .const import (
    CHARACTERISTIC_BATTERY,
    SERVICE_HHCCJCY10,
    SERVICE_MIBEACON,
    SERVICE_SCALE1,
    SERVICE_SCALE2,
    TIMEOUT_1DAY,
    EncryptionScheme,
    ExtendedBinarySensorDeviceClass,
    ExtendedSensorDeviceClass,
)
from .devices import DEVICE_TYPES, SLEEPY_DEVICE_MODELS
from .events import EventDeviceKeys
from .locks import BLE_LOCK_ACTION, BLE_LOCK_ERROR, BLE_LOCK_METHOD

_LOGGER = logging.getLogger(__name__)


def to_mac(addr: bytes) -> str:
    """Return formatted MAC address"""
    return ":".join(f"{i:02X}" for i in addr)


def to_unformatted_mac(addr: str) -> str:
    """Return unformatted MAC address"""
    return "".join(f"{i:02X}" for i in addr[:])


def parse_event_properties(
    event_property: str | None, value: int
) -> dict[str, int | None] | None:
    """Convert event property and data to event properties."""
    if event_property:
        return {event_property: value}
    return None


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


# Advertisement conversion of measurement data
# https://iot.mi.com/new/doc/accesses/direct-access/embedded-development/ble/object-definition
def obj0003(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Motion"""
    # 0x0003 is only used by MUE4094RT, which does not send motion clear.
    # This object is therefore added as event (motion detected).
    device.fire_event(
        key=EventDeviceKeys.MOTION,
        event_type="motion_detected",
        event_properties=None,
    )
    return {}


def obj0006(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Fingerprint"""
    if len(xobj) == 5:
        key_id_bytes = xobj[0:4]
        match_byte = xobj[4]
        if key_id_bytes == b"\x00\x00\x00\x00":
            key_type = "administrator"
        elif key_id_bytes == b"\xff\xff\xff\xff":
            key_type = "unknown operator"
        elif key_id_bytes == b"\xde\xad\xbe\xef":
            key_type = "invalid operator"
        else:
            key_type = str(int.from_bytes(key_id_bytes, "little"))
        if match_byte == 0x00:
            result = "match_successful"
        elif match_byte == 0x01:
            result = "match_failed"
        elif match_byte == 0x02:
            result = "timeout"
        elif match_byte == 0x033:
            result = "low_quality_too_light_fuzzy"
        elif match_byte == 0x04:
            result = "insufficient_area"
        elif match_byte == 0x05:
            result = "skin_is_too_dry"
        elif match_byte == 0x06:
            result = "skin_is_too_wet"
        else:
            result = None

        fingerprint = True if match_byte == 0x00 else False

        # Update fingerprint binary sensor
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.FINGERPRINT,
            native_value=fingerprint,
            device_class=ExtendedBinarySensorDeviceClass.FINGERPRINT,
            name="Fingerprint",
        )
        # Update key_id sensor
        device.update_sensor(
            key=ExtendedSensorDeviceClass.KEY_ID,
            name="Key id",
            device_class=ExtendedSensorDeviceClass.KEY_ID,
            native_value=key_type,
            native_unit_of_measurement=None,
        )
        # Fire Fingerprint action event
        if result:
            device.fire_event(
                key=EventDeviceKeys.FINGERPRINT,
                event_type=result,
                event_properties=None,
            )
    return {}


def obj0007(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Door"""
    door_byte = xobj[0]
    if door_byte == 0x00:
        # open the door
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.DOOR, True)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_STUCK,
            native_value=False,  # reset door stuck
            device_class=ExtendedBinarySensorDeviceClass.DOOR_STUCK,
            name="Door stuck",
        )
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.KNOCK_ON_THE_DOOR,
            native_value=False,  # reset knock on the door
            device_class=ExtendedBinarySensorDeviceClass.KNOCK_ON_THE_DOOR,
            name="Knock on the door",
        )
    elif door_byte == 0x01:
        # close the door
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.DOOR, False)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            native_value=False,  # reset door left open
            device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            name="Door left open",
        )
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.PRY_THE_DOOR,
            native_value=False,  # reset pry the door
            device_class=ExtendedBinarySensorDeviceClass.PRY_THE_DOOR,
            name="Pry the door",
        )
    elif door_byte == 0x02:
        # timeout, not closed
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.DOOR, True)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            native_value=True,
            device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            name="Door left open",
        )
    elif door_byte == 0x03:
        # knock on the door
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.DOOR, False)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.KNOCK_ON_THE_DOOR,
            native_value=True,
            device_class=ExtendedBinarySensorDeviceClass.KNOCK_ON_THE_DOOR,
            name="Knock on the door",
        )
    elif door_byte == 0x04:
        # pry the door
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.DOOR, True)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.PRY_THE_DOOR,
            native_value=True,
            device_class=ExtendedBinarySensorDeviceClass.PRY_THE_DOOR,
            name="Pry the door",
        )
    elif door_byte == 0x05:
        # door stuck
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.DOOR, False)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_STUCK,
            native_value=True,
            device_class=ExtendedBinarySensorDeviceClass.DOOR_STUCK,
            name="Door stuck",
        )
    return {}


def obj0008(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """armed away"""
    value = xobj[0] ^ 1
    device.update_binary_sensor(
        key=ExtendedBinarySensorDeviceClass.ARMED,
        native_value=bool(value),  # Armed away
        device_class=ExtendedBinarySensorDeviceClass.ARMED,
        name="Armed",
    )
    # Lift up door handle outside the door sends this event from DSL-C08.
    if device_type == "DSL-C08":
        device.update_predefined_binary_sensor(
            BinarySensorDeviceClass.LOCK, bool(value)
        )
        # Fire Lock action event
        device.fire_event(
            key=EventDeviceKeys.LOCK,
            event_type="lock_outside_the_door",
            event_properties=None,
        )
        # # Update method sensor
        device.update_sensor(
            key=ExtendedSensorDeviceClass.LOCK_METHOD,
            name="Lock method",
            device_class=ExtendedSensorDeviceClass.LOCK_METHOD,
            native_value="manual",
            native_unit_of_measurement=None,
        )
    return {}


def obj0010(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Toothbrush"""
    if xobj[0] == 0:
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            native_value=True,  # Toothbrush On
            device_class=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            name="Toothbrush",
        )
    else:
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            native_value=False,  # Toothbrush Off
            device_class=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            name="Toothbrush",
        )
    if len(xobj) > 1:
        device.update_sensor(
            key=ExtendedSensorDeviceClass.COUNTER,
            name="Counter",
            native_unit_of_measurement=Units.TIME_SECONDS,
            device_class=ExtendedSensorDeviceClass.COUNTER,
            native_value=xobj[1],
        )
    return {}


def obj000a(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Body Temperature"""
    if len(xobj) == 2:
        (temp,) = T_STRUCT.unpack(xobj)
        if temp:
            device.update_predefined_sensor(
                SensorLibrary.TEMPERATURE__CELSIUS, temp / 100
            )
    return {}


def obj000b(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Lock"""
    if len(xobj) == 9:
        lock_action_int = xobj[0] & 0x0F
        lock_method_int = xobj[0] >> 4
        key_id = int.from_bytes(xobj[1:5], "little")
        short_key_id = key_id & 0xFFFF

        # Lock action (event) and lock method (sensor)
        if (
            lock_action_int not in BLE_LOCK_ACTION
            or lock_method_int not in BLE_LOCK_METHOD
        ):
            return {}
        lock_action = BLE_LOCK_ACTION[lock_action_int][2]
        lock_method = BLE_LOCK_METHOD[lock_method_int]

        # Some specific key_ids represent an error
        error = BLE_LOCK_ERROR.get(key_id)

        if not error:
            if key_id == 0x00000000:
                key_type = "administrator"
            elif key_id == 0xFFFFFFFF:
                key_type = "unknown operator"
            elif key_id == 0xDEADBEEF:
                key_type = "invalid operator"
            elif key_id <= 0x7FFFFFF:
                # Bluetooth (up to 2147483647)
                key_type = f"Bluetooth key {key_id}"
            else:
                # All other key methods have only key ids up to 65536

                if key_id <= 0x8001FFFF:
                    key_type = f"Fingerprint key id {short_key_id}"
                elif key_id <= 0x8002FFFF:
                    key_type = f"Password key id {short_key_id}"
                elif key_id <= 0x8003FFFF:
                    key_type = f"Keys key id {short_key_id}"
                elif key_id <= 0x8004FFFF:
                    key_type = f"NFC key id {short_key_id}"
                elif key_id <= 0x8005FFFF:
                    key_type = f"Two-step verification key id {short_key_id}"
                elif key_id <= 0x8006FFFF:
                    key_type = f"Human face key id {short_key_id}"
                elif key_id <= 0x8007FFFF:
                    key_type = f"Finger veins key id {short_key_id}"
                elif key_id <= 0x8008FFFF:
                    key_type = f"Palm print key id {short_key_id}"
                else:
                    key_type = f"key id {short_key_id}"

        # Lock type and state
        # Lock type can be `lock` or for ZNMS17LM `lock`, `childlock` or `antilock`
        if device_type == "ZNMS17LM":
            # Lock type can be `lock`, `childlock` or `antilock`
            lock_type = BLE_LOCK_ACTION[lock_action_int][1]
        else:
            # Lock type can only be `lock` for other locks
            lock_type = "lock"
        lock_state = BLE_LOCK_ACTION[lock_action_int][0]

        # Update lock state
        if lock_type == "lock":
            device.update_predefined_binary_sensor(
                BinarySensorDeviceClass.LOCK, lock_state
            )
        elif lock_type == "childlock":
            device.update_binary_sensor(
                key=ExtendedBinarySensorDeviceClass.CHILDLOCK,
                native_value=lock_state,
                device_class=ExtendedBinarySensorDeviceClass.CHILDLOCK,
                name="Childlock",
            )
        elif lock_type == "antilock":
            device.update_binary_sensor(
                key=ExtendedBinarySensorDeviceClass.ANTILOCK,
                native_value=lock_state,
                device_class=ExtendedBinarySensorDeviceClass.ANTILOCK,
                name="Antilock",
            )
        else:
            return {}

        # Update key_id sensor
        device.update_sensor(
            key=ExtendedSensorDeviceClass.KEY_ID,
            name="Key id",
            device_class=ExtendedSensorDeviceClass.KEY_ID,
            native_value=key_type,
            native_unit_of_measurement=None,
        )
        # Fire Lock action event: see BLE_LOCK_ACTTION
        device.fire_event(
            key=EventDeviceKeys.LOCK,
            event_type=lock_action,
            event_properties=None,
        )
        # # Update method sensor: see BLE_LOCK_METHOD
        device.update_sensor(
            key=ExtendedSensorDeviceClass.LOCK_METHOD,
            name="Lock method",
            device_class=ExtendedSensorDeviceClass.LOCK_METHOD,
            native_value=lock_method.value,
            native_unit_of_measurement=None,
        )
        if error:
            # Fire event with the error: see BLE_LOCK_ERROR
            device.fire_event(
                key=EventDeviceKeys.ERROR,
                event_type=error,
                event_properties=None,
            )
    return {}


def obj000f(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Moving with light"""
    if len(xobj) == 3:
        (illum,) = LIGHT_STRUCT.unpack(xobj + b"\x00")
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.MOTION, True)
        if device_type in ["MJYD02YL", "RTCGQ02LM"]:
            # MJYD02YL:  1 - moving no light, 100 - moving with light
            # RTCGQ02LM: 0 - moving no light, 256 - moving with light
            device.update_predefined_binary_sensor(
                BinarySensorDeviceClass.LIGHT, bool(illum >= 100)
            )
        elif device_type == "CGPR1":
            # CGPR1:     moving, value is illumination in lux
            device.update_predefined_sensor(SensorLibrary.LIGHT__LIGHT_LUX, illum)
    return {}


def obj1001(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """button"""
    if len(xobj) != 3:
        return {}

    (button_type, value, press_type) = BUTTON_STRUCT.unpack(xobj)

    # button_type represents the pressed button or rubiks cube rotation direction
    remote_command = None
    fan_remote_command = None
    ven_fan_remote_command = None
    bathroom_remote_command = None
    cube_rotation = None

    one_btn_switch = False
    two_btn_switch_left = False
    two_btn_switch_right = False
    three_btn_switch_left = False
    three_btn_switch_middle = False
    three_btn_switch_right = False

    if button_type == 0:
        remote_command = "on"
        fan_remote_command = "fan"
        ven_fan_remote_command = "swing"
        bathroom_remote_command = "stop"
        one_btn_switch = True
        two_btn_switch_left = True
        three_btn_switch_left = True
        cube_rotation = "rotate_right"
    elif button_type == 1:
        remote_command = "off"
        fan_remote_command = "light"
        ven_fan_remote_command = "power"
        bathroom_remote_command = "air_exchange"
        two_btn_switch_right = True
        three_btn_switch_middle = True
        cube_rotation = "rotate_left"
    elif button_type == 2:
        remote_command = "brightness"
        fan_remote_command = "wind_speed"
        ven_fan_remote_command = "timer_60_minutes"
        bathroom_remote_command = "fan"
        two_btn_switch_left = True
        two_btn_switch_right = True
        three_btn_switch_right = True
    elif button_type == 3:
        remote_command = "plus"
        fan_remote_command = "color_temperature"
        ven_fan_remote_command = "increase_wind_speed"
        bathroom_remote_command = "increase_speed"
        three_btn_switch_left = True
        three_btn_switch_middle = True
    elif button_type == 4:
        remote_command = "M"
        fan_remote_command = "wind_mode"
        ven_fan_remote_command = "timer_30_minutes"
        bathroom_remote_command = "decrease_speed"
        three_btn_switch_middle = True
        three_btn_switch_right = True
    elif button_type == 5:
        remote_command = "min"
        fan_remote_command = "brightness"
        ven_fan_remote_command = "decrease_wind_speed"
        bathroom_remote_command = "dry"
        three_btn_switch_left = True
        three_btn_switch_right = True
    elif button_type == 6:
        bathroom_remote_command = "light"
        three_btn_switch_left = True
        three_btn_switch_middle = True
        three_btn_switch_right = True
    elif button_type == 7:
        bathroom_remote_command = "swing"
    elif button_type == 8:
        bathroom_remote_command = "heat"

    # press_type represents the type of press or rotate
    # for dimmers, buton_type is used to represent the type of press
    # for dimmers, value or button_type is used to represent the direction and number
    # of steps, number of presses or duration of long press
    button_press_type = "no_press"
    btn_switch_press_type = None
    dimmer_value: int = 0

    if press_type == 0:
        button_press_type = "press"
        btn_switch_press_type = "press"
    elif press_type == 1:
        button_press_type = "double_press"
        btn_switch_press_type = "long_press"
    elif press_type == 2:
        button_press_type = "long_press"
        btn_switch_press_type = "double_press"
    elif press_type == 3:
        if button_type == 0:
            button_press_type = "press"
            dimmer_value = value
        if button_type == 1:
            button_press_type = "long_press"
            dimmer_value = value
    elif press_type == 4:
        if button_type == 0:
            if value <= 127:
                button_press_type = "rotate_right"
                dimmer_value = value
            else:
                button_press_type = "rotate_left"
                dimmer_value = 256 - value
        elif button_type <= 127:
            button_press_type = "rotate_right_pressed"
            dimmer_value = button_type
        else:
            button_press_type = "rotate_left_pressed"
            dimmer_value = 256 - button_type
    elif press_type == 5:
        button_press_type = "press"
    elif press_type == 6:
        button_press_type = "long_press"

    # return device specific output
    if device_type in ["RTCGQ02LM", "YLAI003", "JTYJGD03MI", "SJWS01LM"]:
        # RTCGQ02LM, JTYJGD03MI, SJWS01LM: press
        # YLAI003: press, double_press or long_press
        device.fire_event(
            key=EventDeviceKeys.BUTTON,
            event_type=button_press_type,
            event_properties=None,
        )
    elif device_type == "XMMF01JQD":
        # cube_rotation: rotate_left or rotate_right
        device.fire_event(
            key=EventDeviceKeys.CUBE,
            event_type=cube_rotation,
            event_properties=None,
        )
    elif device_type == "YLYK01YL":
        # Buttons: on, off, brightness, plus, min, M
        # Press types: press and long_press
        if remote_command == "on":
            device.update_predefined_binary_sensor(BinarySensorDeviceClass.POWER, True)
        elif remote_command == "off":
            device.update_predefined_binary_sensor(BinarySensorDeviceClass.POWER, False)
        device.fire_event(
            key=f"{str(EventDeviceKeys.BUTTON)}_{remote_command}",
            event_type=button_press_type,
            event_properties=None,
        )
    elif device_type == "YLYK01YL-FANRC":
        # Buttons: fan, light, wind_speed, wind_mode, brightness, color_temperature
        # Press types: press and long_press
        device.fire_event(
            key=f"{str(EventDeviceKeys.BUTTON)}_{fan_remote_command}",
            event_type=button_press_type,
            event_properties=None,
        )
    elif device_type == "YLYK01YL-VENFAN":
        # Buttons: swing, power, timer_30_minutes, timer_60_minutes,
        # increase_wind_speed, decrease_wind_speed
        # Press types: press and long_press
        device.fire_event(
            key=f"{str(EventDeviceKeys.BUTTON)}_{ven_fan_remote_command}",
            event_type=button_press_type,
            event_properties=None,
        )
    elif device_type == "YLYB01YL-BHFRC":
        # Buttons: heat, air_exchange, dry, fan, swing, decrease_speed, increase_speed,
        # stop or light
        # Press types: press and long_press
        device.fire_event(
            key=f"{str(EventDeviceKeys.BUTTON)}_{bathroom_remote_command}",
            event_type=button_press_type,
            event_properties=None,
        )
    elif device_type == "YLKG07YL/YLKG08YL":
        # Dimmer reports: press, long_press, rotate_left, rotate_right,
        # rotate_left_pressed  or rotate_right_pressed
        if button_press_type == "press":
            # it also reports how many times you pressed the dimmer.
            event_property = "number_of_presses"
        elif button_press_type == "long_press":
            # it also reports the duration (in seconds) you pressed the dimmer
            event_property = "duration"
        elif button_press_type in [
            "rotate_right",
            "rotate_left",
            "rotate_right_pressed",
            "rotate_left_pressed",
        ]:
            # it reports how far you rotate, measured in number of `steps`.
            event_property = "steps"
        else:
            event_property = None
        event_properties = parse_event_properties(
            event_property=event_property, value=dimmer_value
        )
        device.fire_event(
            key=EventDeviceKeys.DIMMER,
            event_type=button_press_type,
            event_properties=event_properties,
        )
    elif device_type == "K9B-1BTN":
        # Press types: press, double_press, long_press
        if one_btn_switch:
            device.fire_event(
                key=EventDeviceKeys.BUTTON,
                event_type=btn_switch_press_type,
                event_properties=None,
            )
    elif device_type == "K9B-2BTN":
        # Buttons: left and/or right
        # Press types: press, double_press, long_press
        # device can send button press of multiple buttons in one message
        if two_btn_switch_left:
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_left",
                event_type=btn_switch_press_type,
                event_properties=None,
            )
        if two_btn_switch_right:
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_right",
                event_type=btn_switch_press_type,
                event_properties=None,
            )
    elif device_type == "K9B-3BTN":
        # Buttons: left, middle and/or right
        # result can be press, double_press or long_press
        # device can send button press of multiple buttons in one message
        if three_btn_switch_left:
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_left",
                event_type=btn_switch_press_type,
                event_properties=None,
            )
        if three_btn_switch_middle:
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_middle",
                event_type=btn_switch_press_type,
                event_properties=None,
            )
        if three_btn_switch_right:
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_right",
                event_type=btn_switch_press_type,
                event_properties=None,
            )
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
    """Power on/off and Temperature"""
    device.update_predefined_binary_sensor(BinarySensorDeviceClass.POWER, xobj[0])
    device.update_predefined_sensor(SensorLibrary.TEMPERATURE__CELSIUS, xobj[1])
    return {}


def obj1006(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Humidity"""
    if len(xobj) == 2:
        (humi,) = H_STRUCT.unpack(xobj)
        if device_type in ["LYWSD03MMC", "MHO-C401"]:
            # To handle jagged stair stepping readings from these sensors.
            # https://github.com/custom-components/ble_monitor/blob/ef2e3944b9c1a635208390b8563710d0eec2a945/custom_components/ble_monitor/sensor.py#L752
            # https://github.com/esphome/esphome/blob/c39f6d0738d97ecc11238220b493731ec70c701c/esphome/components/xiaomi_lywsd03mmc/xiaomi_lywsd03mmc.cpp#L44C14-L44C99
            # https://github.com/custom-components/ble_monitor/issues/7#issuecomment-595948254
            device.update_predefined_sensor(
                SensorLibrary.HUMIDITY__PERCENTAGE, int(humi / 10)
            )
        else:
            device.update_predefined_sensor(
                SensorLibrary.HUMIDITY__PERCENTAGE, humi / 10
            )
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
            device.update_predefined_binary_sensor(
                BinarySensorDeviceClass.LIGHT, illum == 100
            )
        elif device_type in ["HHCCJCY01", "GCLS002"]:
            # illumination in lux
            device.update_predefined_sensor(SensorLibrary.LIGHT__LIGHT_LUX, illum)
    return {}


def obj1008(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Moisture"""
    device.update_predefined_sensor(SensorLibrary.MOISTURE__PERCENTAGE, xobj[0])
    return {}


def obj1009(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Conductivity"""
    if len(xobj) == 2:
        (cond,) = CND_STRUCT.unpack(xobj)
        device.update_predefined_sensor(SensorLibrary.CONDUCTIVITY__CONDUCTIVITY, cond)
    return {}


def obj1010(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Formaldehyde"""
    if len(xobj) == 2:
        (fmdh,) = FMDH_STRUCT.unpack(xobj)
        device.update_predefined_sensor(
            SensorLibrary.FORMALDEHYDE__CONCENTRATION_MILLIGRAMS_PER_CUBIC_METER,
            fmdh / 100,
        )
    return {}


def obj1012(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Power on/off"""
    device.update_predefined_binary_sensor(BinarySensorDeviceClass.POWER, xobj[0])
    return {}


def obj1013(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Consumable (in percent)"""
    device.update_sensor(
        key=ExtendedSensorDeviceClass.CONSUMABLE,
        name="Consumable",
        native_unit_of_measurement=Units.PERCENTAGE,
        device_class=ExtendedSensorDeviceClass.CONSUMABLE,
        native_value=xobj[0],
    )
    return {}


def obj1014(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Moisture"""
    device.update_predefined_binary_sensor(
        BinarySensorDeviceClass.MOISTURE, xobj[0] > 0
    )
    return {}


def obj1015(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Smoke"""
    device.update_predefined_binary_sensor(BinarySensorDeviceClass.SMOKE, xobj[0] > 0)
    return {}


def obj1017(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Time in seconds without motion"""
    if len(xobj) == 4:
        (no_motion_time,) = M_STRUCT.unpack(xobj)
        # seconds since last motion detected message
        # 0x1017 is send 3 seconds after 0x000f, 5 seconds arter 0x1007
        # and at 60, 120, 300, 600, 1200 and 1800 seconds after last motion.
        # Anything <= 30 seconds is regarded motion detected in the MiHome app.
        if no_motion_time <= 30:
            device.update_predefined_binary_sensor(BinarySensorDeviceClass.MOTION, True)
        else:
            device.update_predefined_binary_sensor(
                BinarySensorDeviceClass.MOTION, False
            )
    return {}


def obj1018(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Light intensity"""
    device.update_predefined_binary_sensor(BinarySensorDeviceClass.LIGHT, bool(xobj[0]))
    return {}


def obj1019(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Door/Window sensor"""
    open_obj = xobj[0]
    if open_obj == 0:
        # opened
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, True)
    elif open_obj == 1:
        # closed
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, False)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            native_value=False,  # reset door left open
            device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            name="Door left open",
        )
    elif open_obj == 2:
        # closing timeout
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, True)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            native_value=True,
            device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            name="Door left open",
        )
    elif open_obj == 3:
        # device reset (not implemented)
        return {}
    else:
        return {}
    return {}


def obj100a(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Battery"""
    batt = xobj[0]
    volt = 2.2 + (3.1 - 2.2) * (batt / 100)
    device.update_predefined_sensor(SensorLibrary.BATTERY__PERCENTAGE, batt)
    device.update_predefined_sensor(
        SensorLibrary.VOLTAGE__ELECTRIC_POTENTIAL_VOLT, volt
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

            device.update_predefined_binary_sensor(
                BinarySensorDeviceClass.LOCK, bool(lock_attribute & 0x01 ^ 1)
            )
            device.update_binary_sensor(
                key=ExtendedBinarySensorDeviceClass.CHILDLOCK,
                native_value=bool(lock_attribute >> 3 ^ 1),
                device_class=ExtendedBinarySensorDeviceClass.CHILDLOCK,
                name="Childlock",
            )
    return {}


def obj101b(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Timeout no movement"""
    # https://iot.mi.com/new/doc/accesses/direct-access/embedded-development/ble/object-definition#%E9%80%9A%E7%94%A8%E5%B1%9E%E6%80%A7
    device.update_predefined_binary_sensor(BinarySensorDeviceClass.MOTION, False)
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


def obj3003(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Brushing"""
    result = {}
    start_obj = xobj[0]
    if start_obj == 0:
        # Start of brushing
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            native_value=True,  # Toothbrush On
            device_class=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            name="Toothbrush",
        )
        # Start time has not been implemented
        start_time = struct.unpack("<L", xobj[1:5])[0]
        result["start time"] = datetime.datetime.fromtimestamp(
            start_time, tz=datetime.timezone.utc
        ).replace(tzinfo=None)
    elif start_obj == 1:
        # End of brushing
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            native_value=False,  # Toothbrush Off
            device_class=ExtendedBinarySensorDeviceClass.TOOTHBRUSH,
            name="Toothbrush",
        )
        # End time has not been implemented
        end_time = struct.unpack("<L", xobj[1:5])[0]
        result["end time"] = datetime.datetime.fromtimestamp(
            end_time, tz=datetime.timezone.utc
        ).replace(tzinfo=None)
    if len(xobj) == 6:
        device.update_sensor(
            key=ExtendedSensorDeviceClass.SCORE,
            name="Score",
            native_unit_of_measurement=None,
            device_class=ExtendedSensorDeviceClass.SCORE,
            native_value=xobj[5],
        )
    return result


# The following data objects are device specific. For now only added for
# LYWSD02MMC, MJWSD05MMC, XMWSDJ04MMC, XMWXKG01YL, LINPTECH MS1BB(MI), HS1BB(MI),
# K9BB, PTX https://miot-spec.org/miot-spec-v2/instances?status=all
def obj4803(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Battery"""
    device.update_predefined_sensor(SensorLibrary.BATTERY__PERCENTAGE, xobj[0])
    return {}


def obj4804(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Opening (state)"""
    opening_state = xobj[0]
    # State of the door/window, used in combination with obj4a12
    if opening_state == 1:
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, True)
    elif opening_state == 2:
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, False)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            native_value=False,  # reset door left open
            device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            name="Door left open",
        )
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DEVICE_FORCIBLY_REMOVED,
            native_value=False,  # reset device forcibly removed
            device_class=ExtendedBinarySensorDeviceClass.DEVICE_FORCIBLY_REMOVED,
            name="Device forcibly removed",
        )
    return {}


def obj4805(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Illuminance in lux"""
    (illum,) = struct.unpack("f", xobj)
    device.update_predefined_sensor(SensorLibrary.LIGHT__LIGHT_LUX, illum)
    return {}


def obj4806(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Moisture"""
    device.update_predefined_binary_sensor(
        BinarySensorDeviceClass.MOISTURE, xobj[0] > 0
    )
    return {}


def obj4818(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Time in seconds of no motion"""
    if len(xobj) == 2:
        (no_motion_time,) = struct.unpack("<H", xobj)
        # seconds since last motion detected message
        # 0 = motion detected
        # also send at 60, 120, 300, 600, 1200 and 1800 seconds after last motion.
        # Anything <= 30 seconds is regarded motion detected in the MiHome app.
        if no_motion_time <= 30:
            device.update_predefined_binary_sensor(BinarySensorDeviceClass.MOTION, True)
        else:
            device.update_predefined_binary_sensor(
                BinarySensorDeviceClass.MOTION, False
            )
    return {}


def obj4a01(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Low Battery"""
    device.update_predefined_binary_sensor(BinarySensorDeviceClass.BATTERY, xobj[0])
    return {}


def obj4a08(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Motion detected with Illuminance in lux"""
    (illum,) = struct.unpack("f", xobj)
    device.update_predefined_binary_sensor(BinarySensorDeviceClass.MOTION, True)
    device.update_predefined_sensor(SensorLibrary.LIGHT__LIGHT_LUX, illum)
    return {}


def obj4a0c(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Single press"""
    device.fire_event(
        key=EventDeviceKeys.BUTTON,
        event_type="press",
        event_properties=None,
    )
    return {}


def obj4a0d(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Double press"""
    device.fire_event(
        key=EventDeviceKeys.BUTTON,
        event_type="double_press",
        event_properties=None,
    )
    return {}


def obj4a0e(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Long press"""
    device.fire_event(
        key=EventDeviceKeys.BUTTON,
        event_type="long_press",
        event_properties=None,
    )
    return {}


def obj4a0f(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Device forcibly removed"""
    dev_forced = xobj[0]
    if dev_forced == 1:
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, True)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DEVICE_FORCIBLY_REMOVED,
            native_value=True,
            device_class=ExtendedBinarySensorDeviceClass.DEVICE_FORCIBLY_REMOVED,
            name="Device forcibly removed",
        )
    return {}


def obj4a12(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Opening (event)"""
    opening_state = xobj[0]
    # Opening event, used in combination with obj4804
    if opening_state == 1:
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, True)
    elif opening_state == 2:
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, False)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            native_value=False,
            device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            name="Door left open",
        )
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DEVICE_FORCIBLY_REMOVED,
            native_value=False,  # reset device forcibly removed
            device_class=ExtendedBinarySensorDeviceClass.DEVICE_FORCIBLY_REMOVED,
            name="Device forcibly removed",
        )
    return {}


def obj4a13(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Button press (MS1BB(MI))"""
    press = xobj[0]
    if press == 1:
        device.fire_event(
            key=EventDeviceKeys.BUTTON,
            event_type="press",
            event_properties=None,
        )
    return {}


def obj4a1a(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Door left open"""
    if xobj[0] == 1:
        device.update_predefined_binary_sensor(BinarySensorDeviceClass.OPENING, True)
        device.update_binary_sensor(
            key=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            native_value=False,
            device_class=ExtendedBinarySensorDeviceClass.DOOR_LEFT_OPEN,
            name="Door left open",
        )
    return {}


def obj4c01(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Temperature"""
    if len(xobj) == 4:
        temp = FLOAT_STRUCT.unpack(xobj)[0]
        device.update_predefined_sensor(
            SensorLibrary.TEMPERATURE__CELSIUS, round(temp, 2)
        )
    return {}


def obj4c02(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Humidity"""
    if len(xobj) == 1:
        humi = xobj[0]
        device.update_predefined_sensor(SensorLibrary.HUMIDITY__PERCENTAGE, humi)
    return {}


def obj4c03(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Battery"""
    device.update_predefined_sensor(SensorLibrary.BATTERY__PERCENTAGE, xobj[0])
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


def obj4e01(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Low Battery"""
    device.update_predefined_binary_sensor(BinarySensorDeviceClass.BATTERY, xobj[0])
    return {}


def obj4e0c(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Button press"""
    if device_type == "XMWXKG01YL":
        press = xobj[0]
        if press == 1:
            # left button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_left",
                event_type="press",
                event_properties=None,
            )
        elif press == 2:
            # right button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_right",
                event_type="press",
                event_properties=None,
            )
        elif press == 3:
            # both left and right button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_left",
                event_type="press",
                event_properties=None,
            )
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_right",
                event_type="press",
                event_properties=None,
            )
    elif device_type == "K9BB-1BTN":
        press = xobj[0]
        if press == 1:
            device.fire_event(
                key=EventDeviceKeys.BUTTON,
                event_type="press",
                event_properties=None,
            )
        elif press == 8:
            device.fire_event(
                key=EventDeviceKeys.BUTTON,
                event_type="long_press",
                event_properties=None,
            )
        elif press == 15:
            device.fire_event(
                key=EventDeviceKeys.BUTTON,
                event_type="double_press",
                event_properties=None,
            )
    elif device_type == "XMWXKG01LM":
        device.fire_event(
            key=EventDeviceKeys.BUTTON,
            event_type="press",
            event_properties=None,
        )
    return {}


def obj4e0d(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Double Press"""
    if device_type == "XMWXKG01YL":
        press = xobj[0]
        if press == 1:
            # left button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_left",
                event_type="double_press",
                event_properties=None,
            )
        elif press == 2:
            # right button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_right",
                event_type="double_press",
                event_properties=None,
            )
        elif press == 3:
            # both left and right button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_left",
                event_type="double_press",
                event_properties=None,
            )
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_right",
                event_type="double_press",
                event_properties=None,
            )
    elif device_type == "XMWXKG01LM":
        device.fire_event(
            key=EventDeviceKeys.BUTTON,
            event_type="double_press",
            event_properties=None,
        )
    return {}


def obj4e0e(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Long Press"""
    if device_type == "XMWXKG01YL":
        press = xobj[0]
        if press == 1:
            # left button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_left",
                event_type="long_press",
                event_properties=None,
            )
        elif press == 2:
            # right button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_right",
                event_type="long_press",
                event_properties=None,
            )
        elif press == 3:
            # both left and right button
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_left",
                event_type="long_press",
                event_properties=None,
            )
            device.fire_event(
                key=f"{str(EventDeviceKeys.BUTTON)}_right",
                event_type="long_press",
                event_properties=None,
            )
    elif device_type == "XMWXKG01LM":
        device.fire_event(
            key=EventDeviceKeys.BUTTON,
            event_type="long_press",
            event_properties=None,
        )
    return {}


def obj4e1c(
    xobj: bytes, device: XiaomiBluetoothDeviceData, device_type: str
) -> dict[str, Any]:
    """Device reset"""
    return {"device reset": True}


# Dataobject dictionary
# {dataObject_id: (converter}
xiaomi_dataobject_dict = {
    0x0003: obj0003,
    0x0006: obj0006,
    0x0007: obj0007,
    0x0008: obj0008,
    0x0010: obj0010,
    0x000A: obj000a,
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
    0x101B: obj101b,
    0x2000: obj2000,
    0x3003: obj3003,
    0x4803: obj4803,
    0x4804: obj4804,
    0x4805: obj4805,
    0x4806: obj4806,
    0x4818: obj4818,
    0x4A01: obj4a01,
    0x4A08: obj4a08,
    0x4A0C: obj4a0c,
    0x4A0D: obj4a0d,
    0x4A0E: obj4a0e,
    0x4A0F: obj4a0f,
    0x4A12: obj4a12,
    0x4A13: obj4a13,
    0x4A1A: obj4a1a,
    0x4C01: obj4c01,
    0x4C02: obj4c02,
    0x4C03: obj4c03,
    0x4C08: obj4c08,
    0x4C14: obj4c14,
    0x4E01: obj4e01,
    0x4E1C: obj4e1c,
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
        self.set_bindkey(bindkey)

        # Data that we know how to parse but don't yet map to the SensorData model.
        self.unhandled: dict[str, Any] = {}

        # The type of encryption to expect, based on flags in the bluetooth
        # frame.
        self.encryption_scheme = EncryptionScheme.NONE

        # If true then we have used the provided encryption key to decrypt at least
        # one payload.
        # If false then we have either not seen an encrypted payload, the key is wrong
        # or encryption is not in use
        self.bindkey_verified = False

        # If True then the decryption has failed or has not been verified yet.
        # If False then the decryption has succeeded.
        self.decryption_failed = True

        # If this is True, then we have not seen an advertisement with a payload
        # Until we see a payload, we can't tell if this device is encrypted or not
        self.pending = True

        # The last service_info we saw that had a payload
        # We keep this to help in reauth flows where we want to reprocess and old
        # value with a new bindkey.
        self.last_service_info: BluetoothServiceInfo | None = None

        # If this is True, the device is not sending advertisements
        # in a regular interval
        self.sleepy_device = False

    def set_bindkey(self, bindkey: bytes | None) -> None:
        """Set the bindkey."""
        if bindkey:
            if len(bindkey) == 12:
                # MiBeacon v2/v3 bindkey (requires 4 additional (fixed) bytes)
                bindkey = b"".join(
                    [bindkey[0:6], bytes.fromhex("8d3d3c97"), bindkey[6:]]
                )
            elif len(bindkey) == 16:
                self.cipher: AESCCM | None = AESCCM(bindkey, tag_length=4)
        else:
            self.cipher = None
        self.bindkey = bindkey

    def supported(self, data: BluetoothServiceInfo) -> bool:
        if not super().supported(data):
            return False
        return True

    def _start_update(self, service_info: BluetoothServiceInfo) -> None:
        """Update from BLE advertisement data."""
        _LOGGER.debug("Parsing Xiaomi BLE advertisement data: %s", service_info)

        for uuid, data in service_info.service_data.items():
            if uuid == SERVICE_MIBEACON:
                if self._parse_xiaomi(service_info, service_info.name, data):
                    self.last_service_info = service_info
            elif uuid == SERVICE_HHCCJCY10:
                if self._parse_hhcc(service_info, data):
                    self.last_service_info = service_info
            elif uuid == SERVICE_SCALE1:
                if self._parse_scale_v1(service_info, data):
                    self.last_service_info = service_info
            elif uuid == SERVICE_SCALE2:
                if self._parse_scale_v2(service_info, data):
                    self.last_service_info = service_info

    def _parse_hhcc(self, service_info: BluetoothServiceInfo, data: bytes) -> bool:
        """Parser for Pink version of HHCCJCY10."""
        if len(data) != 9:
            return False

        identifier = short_address(service_info.address)
        self.set_title(f"Plant Sensor {identifier} (HHCCJCY10)")
        self.set_device_name(f"Plant Sensor {identifier}")
        self.set_device_type("HHCCJCY10")
        self.set_device_manufacturer("HHCC Plant Technology Co. Ltd")

        xvalue_1 = data[0:3]
        (moist, temp) = struct.unpack(">BH", xvalue_1)
        self.update_predefined_sensor(SensorLibrary.TEMPERATURE__CELSIUS, temp / 10)
        self.update_predefined_sensor(SensorLibrary.MOISTURE__PERCENTAGE, moist)

        xvalue_2 = data[3:6]
        (illu,) = struct.unpack(">i", b"\x00" + xvalue_2)
        self.update_predefined_sensor(SensorLibrary.LIGHT__LIGHT_LUX, illu)

        xvalue_3 = data[6:9]
        (batt, cond) = struct.unpack(">BH", xvalue_3)
        self.update_predefined_sensor(SensorLibrary.BATTERY__PERCENTAGE, batt)
        self.update_predefined_sensor(SensorLibrary.CONDUCTIVITY__CONDUCTIVITY, cond)

        return True

    def _parse_xiaomi(
        self, service_info: BluetoothServiceInfo, name: str, data: bytes
    ) -> bool:
        """Parser for Xiaomi sensors"""
        # check for adstruc length
        i = 5  # till Frame Counter
        msg_length = len(data)
        if msg_length < i:
            _LOGGER.debug("Invalid data length (initial check), adv: %s", data.hex())
            return False

        mac_readable = service_info.address
        source_mac = bytes.fromhex(mac_readable.replace(":", ""))

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
            if xiaomi_mac != source_mac:
                _LOGGER.debug(
                    "MAC address doesn't match data frame. Expected: %s, Got: %s",
                    to_mac(xiaomi_mac),
                    to_mac(source_mac),
                )
                return False
        else:
            xiaomi_mac = source_mac

        # determine the device type
        device_id = data[2] + (data[3] << 8)
        try:
            device = DEVICE_TYPES[device_id]
        except KeyError:
            _LOGGER.info(
                "BLE ADV from UNKNOWN Xiaomi device: MAC: %s, ADV: %s",
                source_mac,
                data.hex(),
            )
            _LOGGER.debug("Unknown Xiaomi device found. Data: %s", data.hex())
            return False

        device_type = device.model

        self.device_id = device_id
        self.device_type = device_type

        # set to True if the device is not sending regular BLE advertisements
        self.sleepy_device = device_type in SLEEPY_DEVICE_MODELS

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

        identifier = short_address(service_info.address)
        self.set_title(f"{device.name} {identifier} ({device.model})")
        self.set_device_name(f"{device.name} {identifier}")
        self.set_device_type(device.model)
        self.set_device_manufacturer(device.manufacturer)

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
                    # V4/V5 encryption has an authentication tag, so we don't apply the
                    # same restriction there.
                    if self.encryption_scheme == EncryptionScheme.MIBEACON_LEGACY:
                        if self.decryption_failed is True:
                            # we only ask for reautentification
                            # till the decryption has failed twice.
                            self.bindkey_verified = False
                        else:
                            self.decryption_failed = True
                    _LOGGER.debug(
                        "Invalid payload data length, payload: %s", payload.hex()
                    )
                    break
                this_start = payload_start + 3
                dobject = payload[this_start:next_start]
                if (
                    dobject
                    and obj_length != 0
                    or hex(obj_typecode)
                    in ["0x4a0c", "0x4a0d", "0x4a0e", "0x4e0c", "0x4e0d", "0x4e0e"]
                ):
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

    def _parse_scale_v1(self, service_info: BluetoothServiceInfo, data: bytes) -> bool:
        if len(data) != 10:
            return False

        uuid16 = (data[3] << 8) | data[2]

        identifier = short_address(service_info.address)

        self.device_id = uuid16
        self.set_title(f"Mi Smart Scale ({identifier})")
        self.set_device_name(f"Mi Smart Scale ({identifier})")
        self.set_device_type("XMTZC01HM/XMTZC04HM")
        self.set_device_manufacturer("Xiaomi")
        self.pending = False
        self.sleepy_device = True

        control_byte = data[0]
        mass = float(int.from_bytes(data[1:3], byteorder="little"))

        mass_in_pounds = bool(int(control_byte & (1 << 0)))
        mass_in_catty = bool(int(control_byte & (1 << 4)))
        mass_in_kilograms = not mass_in_catty and not mass_in_pounds
        mass_stabilized = bool(int(control_byte & (1 << 5)))
        mass_removed = bool(int(control_byte & (1 << 7)))

        if mass_in_kilograms:
            # sensor advertises kg * 200
            mass /= 200
        elif mass_in_pounds:
            # sensor advertises lbs * 100, conversion to kg (1 lbs = 0.45359237 kg)
            mass *= 0.0045359237
        else:
            # sensor advertises catty * 100, conversion to kg (1 catty = 0.5 kg)
            mass *= 0.005

        self.update_predefined_sensor(
            SensorLibrary.MASS_NON_STABILIZED__MASS_KILOGRAMS, mass
        )
        if mass_stabilized and not mass_removed:
            self.update_predefined_sensor(SensorLibrary.MASS__MASS_KILOGRAMS, mass)

        return True

    def _parse_scale_v2(self, service_info: BluetoothServiceInfo, data: bytes) -> bool:
        if len(data) != 13:
            return False

        uuid16 = (data[3] << 8) | data[2]

        identifier = short_address(service_info.address)

        self.device_id = uuid16
        self.set_title(f"Mi Body Composition Scale ({identifier})")
        self.set_device_name(f"Mi Body Composition Scale ({identifier})")
        self.set_device_type("XMTZC02HM/XMTZC05HM/NUN4049CN")
        self.set_device_manufacturer("Xiaomi")
        self.pending = False
        self.sleepy_device = True

        control_bytes = data[:2]
        # skip bytes containing date and time
        impedance = int.from_bytes(data[9:11], byteorder="little")
        mass = float(int.from_bytes(data[11:13], byteorder="little"))

        # Decode control bytes
        control_flags = "".join([bin(byte)[2:].zfill(8) for byte in control_bytes])

        mass_in_pounds = bool(int(control_flags[7]))
        mass_in_catty = bool(int(control_flags[9]))
        mass_in_kilograms = not mass_in_catty and not mass_in_pounds
        mass_stabilized = bool(int(control_flags[10]))
        mass_removed = bool(int(control_flags[8]))
        impedance_stabilized = bool(int(control_flags[14]))

        if mass_in_kilograms:
            # sensor advertises kg * 200
            mass /= 200
        elif mass_in_pounds:
            # sensor advertises lbs * 100, conversion to kg (1 lbs = 0.45359237 kg)
            mass *= 0.0045359237
        else:
            # sensor advertises catty * 100, conversion to kg (1 catty = 0.5 kg)
            mass *= 0.005

        self.update_predefined_sensor(
            SensorLibrary.MASS_NON_STABILIZED__MASS_KILOGRAMS, mass
        )
        if mass_stabilized and not mass_removed:
            self.update_predefined_sensor(SensorLibrary.MASS__MASS_KILOGRAMS, mass)
            if impedance_stabilized:
                self.update_predefined_sensor(SensorLibrary.IMPEDANCE__OHM, impedance)

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
        associated_data = b"\x11"
        mic = data[-4:]
        encrypted_payload = data[i:-7]

        assert self.cipher is not None  # nosec
        # decrypt the data
        try:
            decrypted_payload = self.cipher.decrypt(
                nonce, encrypted_payload + mic, associated_data
            )
        except InvalidTag as error:
            if self.decryption_failed is True:
                # we only ask for reautentification till
                # the decryption has failed twice.
                self.bindkey_verified = False
            else:
                self.decryption_failed = True
            _LOGGER.warning("Decryption failed: %s", error)
            _LOGGER.debug("mic: %s", mic.hex())
            _LOGGER.debug("nonce: %s", nonce.hex())
            _LOGGER.debug("encrypted payload: %s", encrypted_payload.hex())
            return None
        if decrypted_payload is None:
            self.bindkey_verified = False
            _LOGGER.error(
                "Decryption failed for %s, decrypted payload is None",
                to_mac(xiaomi_mac),
            )
            return None
        self.decryption_failed = False
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

        if len(self.bindkey) != 16:
            self.bindkey_verified = False
            _LOGGER.error("Encryption key should be 12 bytes (24 characters) long")
            return None

        nonce = b"".join([data[0:5], data[-4:-1], xiaomi_mac[::-1][:-1]])
        encrypted_payload = data[i:-4]
        # cryptography can't decrypt a message without authentication
        # so we have to use Cryptodome
        associated_data = b"\x11"
        cipher = AES.new(self.bindkey, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(associated_data)

        assert cipher is not None  # nosec
        # decrypt the data
        # note that V2/V3 encryption will often pass the decryption process with a
        # wrong encryption key, resulting in useless data, and we won't be able
        # to verify this, as V2/V3 encryption does not use a tag to verify
        # the decrypted data. This will be filtered as wrong data length
        # during the conversion of the payload to sensor data.
        try:
            decrypted_payload = cipher.decrypt(encrypted_payload)
        except ValueError as error:
            self.bindkey_verified = False
            _LOGGER.warning("Decryption failed: %s", error)
            _LOGGER.debug("nonce: %s", nonce.hex())
            _LOGGER.debug("encrypted payload: %s", encrypted_payload.hex())
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
        if self.pending:
            # Never need to poll if we are pending as we don't even know what
            # kind of device we are
            return False

        if self.device_id not in [0x03BC, 0x0098]:
            return False

        return not last_poll or last_poll > TIMEOUT_1DAY

    async def async_poll(self, ble_device: BLEDevice) -> SensorUpdate:
        """
        Poll the device to retrieve any values we can't get from passive listening.
        """
        if self.device_id in [0x03BC, 0x0098]:
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
