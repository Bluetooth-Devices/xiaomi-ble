# Usage

`xiaomi-ble` is a passive parser for the BLE advertisements broadcast by Xiaomi
MiBeacon devices (thermometers, scales, motion sensors, buttons, locks, and
more). You hand it the advertisement data your BLE stack already receives and it
returns a structured `SensorUpdate`. It never needs to connect to the device for
the common case — everything rides on the broadcast.

See {doc}`api` for the full reference.

## Parsing an advertisement

The entry point is {class}`~xiaomi_ble.XiaomiBluetoothDeviceData`. Create one
instance per device (it is stateful — it remembers the encryption scheme and the
last payload it saw), then feed it `BluetoothServiceInfo` objects:

```python
from xiaomi_ble import XiaomiBluetoothDeviceData
from home_assistant_bluetooth import BluetoothServiceInfo

device = XiaomiBluetoothDeviceData()

# `service_info` comes from your BLE scanner (e.g. Home Assistant's bluetooth
# integration or a bleak BLEDevice + AdvertisementData pair).
if device.supported(service_info):
    update = device.update(service_info)

    # Decoded numeric sensors (temperature, humidity, battery, ...)
    for key, value in update.entity_values.items():
        print(value.name, value.native_value)

    # Decoded binary sensors (motion, door open, ...)
    for key, value in update.binary_entity_values.items():
        print(value.name, value.native_value)

    # Stateless events (button presses, dimmer rotations, ...)
    for event in update.events.values():
        print(event.event_type)
```

`update()` returns a `SensorUpdate` (from
[`sensor-state-data`](https://pypi.org/project/sensor-state-data/)) with the
device metadata in `update.devices`, sensor definitions in
`update.entity_descriptions`, and the decoded readings in `update.entity_values`,
`update.binary_entity_values`, and `update.events`.

## Encrypted devices

Many Xiaomi devices encrypt their payloads and need a per-device **bindkey**.
After the first advertisement with a payload, the detected scheme is available on
`device.encryption_scheme` (see {class}`~xiaomi_ble.EncryptionScheme`).

Pass the bindkey when you construct the parser, or set it later with
{meth}`~xiaomi_ble.XiaomiBluetoothDeviceData.set_bindkey`:

```python
device = XiaomiBluetoothDeviceData(bindkey=bytes.fromhex("814aac74c4f17b6c1581e1ab87816b99"))
```

Two flags tell you whether decryption is healthy:

- `device.bindkey_verified` — `True` once at least one payload has been decrypted
  successfully with the supplied key.
- `device.decryption_failed` — `True` while decryption has not yet succeeded
  (wrong key, or no encrypted payload seen yet).

A consumer that wants to prompt the user to re-enter the key can watch for
`decryption_failed` becoming `True` after the key was previously verified.

## Fetching a bindkey from the Xiaomi cloud

If you don't already have the bindkey, you can retrieve it from the Xiaomi cloud
account the device is paired with, using
{class}`~xiaomi_ble.XiaomiCloudTokenFetch`:

```python
import aiohttp
from xiaomi_ble import XiaomiCloudTokenFetch, XiaomiCloudException

async with aiohttp.ClientSession() as session:
    fetcher = XiaomiCloudTokenFetch(username, password, session)
    try:
        cloud_device = await fetcher.get_device_info("A4:C1:38:D4:3C:48")
    except XiaomiCloudException:
        cloud_device = None

    if cloud_device is not None:
        device = XiaomiBluetoothDeviceData(
            bindkey=bytes.fromhex(cloud_device.bindkey)
        )
```

`get_device_info()` returns a {class}`~xiaomi_ble.XiaomiCloudBLEDevice`
(`name`, `mac`, `bindkey`) or `None` if the MAC is not found in the account. All
failure modes raise a subclass of {class}`~xiaomi_ble.XiaomiCloudException`.

## Active polling (optional)

A few devices expose values that are not in the broadcast (for example the
battery level on some sensors). For those,
{meth}`~xiaomi_ble.XiaomiBluetoothDeviceData.poll_needed` tells you when an active
connection is worthwhile, and
{meth}`~xiaomi_ble.XiaomiBluetoothDeviceData.async_poll` performs the GATT read:

```python
if device.poll_needed(service_info, last_poll):
    update = await device.async_poll(ble_device)
```

Most devices never need this — `poll_needed()` returns `False` for them.
