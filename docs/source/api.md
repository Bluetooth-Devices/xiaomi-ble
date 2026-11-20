# API reference

This page documents the public, supported API of `xiaomi_ble`. Everything listed
here is re-exported from the top-level package, so the canonical import is:

```python
from xiaomi_ble import XiaomiBluetoothDeviceData, EncryptionScheme
```

For a task-oriented walkthrough, see {doc}`usage`.

## Parsing advertisements

The heart of the library is {class}`~xiaomi_ble.XiaomiBluetoothDeviceData`. You
feed it `BluetoothServiceInfo` objects (from
[`home-assistant-bluetooth`](https://pypi.org/project/home-assistant-bluetooth/))
and it returns a `SensorUpdate` describing the device and any sensor, binary
sensor and event values decoded from the advertisement.

```{eval-rst}
.. autoclass:: xiaomi_ble.XiaomiBluetoothDeviceData
   :members: supported, update, set_bindkey, poll_needed, async_poll
   :show-inheritance:
```

### Encryption

Some Xiaomi devices encrypt their MiBeacon payloads and require a per-device
*bindkey*. The encryption scheme is detected automatically from the
advertisement flags and exposed on the
:attr:`~xiaomi_ble.XiaomiBluetoothDeviceData.encryption_scheme` attribute.

```{eval-rst}
.. autoclass:: xiaomi_ble.EncryptionScheme
   :members:
   :undoc-members:
```

## Retrieving bindkeys from the Xiaomi cloud

Encrypted devices need a bindkey before their payloads can be decoded. The
bindkey can be fetched from the Xiaomi cloud account that the device is paired
with using {class}`~xiaomi_ble.XiaomiCloudTokenFetch`.

```{eval-rst}
.. autoclass:: xiaomi_ble.XiaomiCloudTokenFetch
   :members:
   :show-inheritance:

.. autoclass:: xiaomi_ble.XiaomiCloudBLEDevice
   :members:
   :show-inheritance:
```

### Cloud exceptions

All cloud errors derive from {class}`~xiaomi_ble.XiaomiCloudException`, so a
single `except XiaomiCloudException` clause catches every failure mode.

```{eval-rst}
.. autoexception:: xiaomi_ble.XiaomiCloudException
   :show-inheritance:

.. autoexception:: xiaomi_ble.XiaomiCloudInvalidAuthenticationException
   :show-inheritance:

.. autoexception:: xiaomi_ble.XiaomiCloudInvalidUsernameException
   :show-inheritance:

.. autoexception:: xiaomi_ble.XiaomiCloudInvalidPasswordException
   :show-inheritance:

.. autoexception:: xiaomi_ble.XiaomiCloudTwoFactorAuthenticationException
   :show-inheritance:
```

## Module constants

```{eval-rst}
.. autodata:: xiaomi_ble.SLEEPY_DEVICE_MODELS
   :no-value:
```

`SLEEPY_DEVICE_MODELS` is the set of device models that advertise irregularly
(e.g. motion sensors and buttons that only transmit on activity). Consumers can
use it to relax availability timeouts for these "sleepy" devices.
