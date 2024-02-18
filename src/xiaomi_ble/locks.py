"""Constants for Xiaomi Locks."""
from enum import Enum


class BleLockMethod(Enum):
    """Methods for opening and closing locks."""

    BLUETOOTH = "bluetooth"
    PASSWORD = "password"  # nosec bandit B105
    BIOMETRICS = "biometrics"
    KEY_METHOD = "key_method"
    TURNTABLE = "turntable_method"
    NFC = "nfc_method"
    ONE_TIME_PASSWORD = "one_time_password"  # nosec bandit B105
    TWO_STEP_VERIFICATION = "two_step_verification"
    HOMEKIT = "homekit"
    COERCION = "coercion_method"
    MANUAL = "manual"
    AUTOMATIC = "automatic"
    ABNORMAL = "abnormal"


# Definition of lock messages
BLE_LOCK_ERROR = {
    0xC0DE0000: "frequent_unlocking_with_incorrect_password",
    0xC0DE0001: "frequent_unlocking_with_wrong_fingerprints",
    0xC0DE0002: "operation_timeout_password_input_timeout",
    0xC0DE0003: "lock_picking",
    0xC0DE0004: "reset_button_is_pressed",
    0xC0DE0005: "the_wrong_key_is_frequently_unlocked",
    0xC0DE0006: "foreign_body_in_the_keyhole",
    0xC0DE0007: "the_key_has_not_been_taken_out",
    0xC0DE0008: "error_nfc_frequently_unlocks",
    0xC0DE0009: "timeout_is_not_locked_as_required",
    0xC0DE000A: "failure_to_unlock_frequently_in_multiple_ways",
    0xC0DE000B: "unlocking_the_face_frequently_fails",
    0xC0DE000C: "failure_to_unlock_the_vein_frequently",
    0xC0DE000D: "hijacking_alarm",
    0xC0DE000E: "unlock_inside_the_door_after_arming",
    0xC0DE000F: "palmprints_frequently_fail_to_unlock",
    0xC0DE0010: "the_safe_was_moved",
    0xC0DE1000: "the_battery_level_is_less_than_10_percent",
    0xC0DE1001: "the_battery_level_is_less_than_5_percent",
    0xC0DE1002: "the_fingerprint_sensor_is_abnormal",
    0xC0DE1003: "the_accessory_battery_is_low",
    0xC0DE1004: "mechanical_failure",
    0xC0DE1005: "the_lock_sensor_is_faulty",
}

BLE_LOCK_ACTION: dict[int, tuple[bool, str, str]] = {
    0b0000: (True, "lock", "unlock_outside_the_door"),
    0b0001: (False, "lock", "locked"),
    0b0010: (False, "antilock", "turn_on_antilock"),
    0b0011: (True, "antilock", "release_the_antilock"),
    0b0100: (True, "lock", "unlock_inside_the_door"),
    0b0101: (False, "lock", "lock_inside_the_door"),
    0b0110: (False, "childlock", "turn_on_child_lock"),
    0b0111: (True, "childlock", "turn_off_child_lock"),
    0b1000: (False, "lock", "lock_outside_the_door"),
    0b1111: (True, "lock", "abnormal"),
}

BLE_LOCK_METHOD: dict[int, BleLockMethod] = {
    0b0000: BleLockMethod.BLUETOOTH,
    0b0001: BleLockMethod.PASSWORD,
    0b0010: BleLockMethod.BIOMETRICS,
    0b0011: BleLockMethod.KEY_METHOD,
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
