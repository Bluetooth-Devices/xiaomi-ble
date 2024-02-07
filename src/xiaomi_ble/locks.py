"""Constants for Xiaomi Locks."""
from enum import Enum


class BleLockMethod(Enum):
    """Methods for opening and closing locks."""

    BLUETOOTH = "bluetooth"
    PASSWORD = "password"  # nosec bandit B105
    BIOMETRICS = "biometrics"
    KEYS = "keys"
    TURNTABLE = "turntable"
    NFC = "nfc"
    ONE_TIME_PASSWORD = "one_time_password"  # nosec bandit B105
    TWO_STEP_VERIFICATION = "two_step_verification"
    HOMEKIT = "homekit"
    COERCION = "coercion"
    MANUAL = "manual"
    AUTOMATIC = "automatic"
    ABNORMAL = "abnormal"


# Definition of lock messages (TODO for translations add underscores)
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

BLE_LOCK_ACTION: dict[int, tuple[bool, str, str]] = {
    0b0000: (True, "lock", "unlock outside the door"),
    0b0001: (False, "lock", "lock"),
    0b0010: (False, "antilock", "turn on anti-lock"),
    0b0011: (True, "antilock", "turn off anti-lock"),
    0b0100: (True, "lock", "unlock inside the door"),
    0b0101: (False, "lock", "lock inside the door"),
    0b0110: (False, "childlock", "turn on child lock"),
    0b0111: (True, "childlock", "turn off child lock"),
    0b1000: (False, "lock", "lock outside the door"),
    0b1111: (True, "lock", "abnormal"),
}

BLE_LOCK_METHOD: dict[int, BleLockMethod] = {
    0b0000: BleLockMethod.BLUETOOTH,
    0b0001: BleLockMethod.PASSWORD,
    0b0010: BleLockMethod.BIOMETRICS,
    0b0011: BleLockMethod.KEYS,
    0b0100: BleLockMethod.TURNTABLE,
    0b0101: BleLockMethod.NFC,
    0b0110: BleLockMethod.ONE_TIME_PASSWORD,
    0b0111: BleLockMethod.TWO_STEP_VERIFICATION,
    0b1001: BleLockMethod.HOMEKIT,
    0b1000: BleLockMethod.COERCION,
    0b1010: BleLockMethod.MANUAL,
    0b1011: BleLockMethod.AUTOMATIC,
    0b1111: BleLockMethod.ABNORMAL,
}
