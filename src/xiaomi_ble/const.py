"""Constants for Xiaomi BLE advertisements."""
from enum import Enum

from sensor_state_data import BaseDeviceClass

TIMEOUT_1DAY = 86400

SERVICE_MIBEACON = "0000fe95-0000-1000-8000-00805f9b34fb"
SERVICE_HHCCJCY10 = "0000fd50-0000-1000-8000-00805f9b34fb"
SERVICE_SCALE1 = "0000181d-0000-1000-8000-00805f9b34fb"
SERVICE_SCALE2 = "0000181b-0000-1000-8000-00805f9b34fb"

# This characteristic contains the current battery level for a HHCCJCY01
# as well as the firmware version
CHARACTERISTIC_BATTERY = "00001a02-0000-1000-8000-00805f9b34fb"


class EncryptionScheme(Enum):
    """Encryption Schemes for Xiaomi MiBeacon."""

    # No encryption is needed to use this device
    NONE = "none"

    # 12 byte encryption key expected
    MIBEACON_LEGACY = "mibeacon_legacy"

    # 16 byte encryption key expected
    MIBEACON_4_5 = "mibeacon_4_5"


class ExtendedBinarySensorDeviceClass(BaseDeviceClass):
    """Device class for additional binary sensors (compared to sensor-state-data)."""

    # On means armed (away), Off means disarmed
    ARMED = "armed"

    # On means door left open, Off means door closed
    DEVICE_FORCIBLY_REMOVED = "device_forcibly_removed"

    # On means door left open, Off means door closed
    DOOR_LEFT_OPEN = "door_left_open"

    # On means door stuck, Off means clear
    DOOR_STUCK = "door_stuck"

    # On means fingerprint Ok, Off means fingerprint Not Ok
    FINGERPRINT = "fingerprint"

    # On means door someone knocking on the door, Off means no knocking
    KNOCK_ON_THE_DOOR = "knock_on_the_door"

    # On means door pried, Off means door not pried
    PRY_THE_DOOR = "pry_the_door"

    # On means toothbrush On, Off means toothbrush Off
    TOOTHBRUSH = "toothbrush"

    # On means antilock turned On, Off means antilOck turned Off
    ANTILOCK = "antilock"

    # On means childlock Turned On, Off means childlock turned Off
    CHILDLOCK = "childlock"


class ExtendedSensorDeviceClass(BaseDeviceClass):
    """Device class for additional sensors (compared to sensor-state-data)."""

    # Consumable
    CONSUMABLE = "consumable"

    # Toothbrush counter
    COUNTER = "counter"

    # Key id
    KEY_ID = "key_id"

    # Lock method
    LOCK_METHOD = "lock_method"

    # Toothbrush score
    SCORE = "score"
