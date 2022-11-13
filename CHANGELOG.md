# Changelog

<!--next-version-placeholder-->

## v0.12.1 (2022-11-13)
### Fix
* Unit of measurement formaldehyde ([#23](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/23)) ([`48035a1`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/48035a1dd704c23d1b8e74be0c7342d7d7da61b7))

## v0.12.0 (2022-11-12)
### Feature
* Add support for HHCCJCY10 ([#21](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/21)) ([`0f387c2`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/0f387c244644a8469de935ce4e5800d882868d81))

## v0.11.0 (2022-11-09)
### Feature
* Add linptech ms1bb and hs1bb ([`52a21dd`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/52a21dd062d9a2172c8e23008f1ee80bbef6ce5e))

## v0.10.0 (2022-09-13)
### Feature
* Update for bleak 0.17 support ([#19](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/19)) ([`db14912`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/db14912f6c57f20363e85d49fe320765606e7ed3))

## v0.9.3 (2022-09-12)
### Fix
* Bump bleak-retry-connector ([#18](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/18)) ([`08fc5aa`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/08fc5aab0e6cf2e772cff962c7cf801328ef66e9))

## v0.9.2 (2022-08-25)
### Fix
* Use short_address from bluetooth_data_tools ([#16](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/16)) ([`d370cca`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/d370cca23c4c585437de5946d33383a550d06bc3))

## v0.9.1 (2022-08-16)
### Fix
* Rename Smart Door Lock E ([#13](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/13)) ([`ef11f5f`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/ef11f5fd799e9a67223b8dbe5569a33c3e214bc0))

## v0.9.0 (2022-08-11)
### Feature
* Intial support for binary_sensor devices ([#12](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/12)) ([`fc0ff14`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/fc0ff143d695beedd190cc002e1173c8c17f5783))

## v0.8.2 (2022-08-11)
### Fix
* Set title and device name to something useful ([`73c4d4b`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/73c4d4b59f6729f9806bdf85d2544698840f4198))

## v0.8.1 (2022-08-11)
### Fix
* Never poll if still pending ([`f617708`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/f617708e4f67d0a6a4d0b853efee5568a14f8aba))

## v0.8.0 (2022-08-06)
### Feature
* Support polling MiFlora battery ([#11](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/11)) ([`f08707b`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/f08707bd45d250a44ea7ca5da059feae61851089))

## v0.7.0 (2022-08-01)
### Feature
* Add XMZNMSBMCN03 ([#9](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/9)) ([`7ff0d49`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/7ff0d49f73f8150e520aaa77868a4f1bd65363b1))

## v0.6.4 (2022-08-01)
### Fix
* Refactor tests to avoid mypy failure ([`c1456d7`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/c1456d7fd96300ffc7bcc21c7d17d6ec63e7a287))
* Track last full service info so that we can quickly reauth the bindkey ([`c4feb20`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/c4feb20468fdfdd1a9c80c0bee77bef2a250d462))

## v0.6.3 (2022-08-01)
### Fix
* Unset bindkey_verified if bindkey starts to fail ([`d2fc9eb`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/d2fc9eb36289a0c4779e97439e682016ae0de1fc))

## v0.6.2 (2022-07-28)
### Fix
* Track whether or not we have seen a packet with a payload (HA75833) ([#8](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/8)) ([`c99f9a2`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/c99f9a2cbd09ac6cebd31349d49d6f038bfea0e6))

## v0.6.1 (2022-07-27)
### Fix
* Voltage sensor should have a device class ([`600bb78`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/600bb7819752b6f742e515eea177b65c83b1d3dc))

## v0.6.0 (2022-07-25)
### Feature
* Add Formaldehyde, Consumable and Voltage sensor ([`8292de7`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/8292de7425597897d562ea43380af221c661df90))

## v0.5.2 (2022-07-25)
### Fix
* Add special casing for when illumination is used for a binary sensor instead of a sensor ([`59c5729`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/59c5729b4c2f39944d61ab65c3aee40c6d041d21))

## v0.5.1 (2022-07-24)
### Fix
* Unset bindkey_verified on legacy devices if payload is corrupt as may be wrong key ([`f57827a`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/f57827a7caa0c9c6721f1d9773e89f3472ccf5c7))

## v0.5.0 (2022-07-24)
### Feature
* New bindkey_verified variable to track whether encryption is working ([`dc622a5`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/dc622a511e1909d96d706b77ff86c8ad1905bda0))

## v0.4.1 (2022-07-24)
### Fix
* Hide encrypted devices on macOS where we don't know MAC address (for now) ([`20d0e62`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/20d0e62939907b8d58888cd346bda5f3365f943c))

## v0.4.0 (2022-07-23)
### Feature
* Expose type of encryption to use on XiaomiBluetoothDeviceData ([`935482d`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/935482d0a78daf10b6e2ff772d32d195eba923ea))

## v0.3.0 (2022-07-23)
### Feature
* Add lux sensor to cgpr1 ([#5](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/5)) ([`accb30e`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/accb30eaa5dc710518e02b92bbfa1ed6c495c992))

## v0.2.0 (2022-07-23)
### Feature
* Add support for more sensor types ([`0a87594`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/0a875940fdf7330d53a03f3ca7b7a489353396b6))

### Fix
* Fix test regression ([`1f80374`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/1f80374c5c56049235ee55f1fc885b8da2cadbb6))
* Remove stray print ([`55d67d7`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/55d67d741c1c7dd8da14729619515e09680542e1))

## v0.1.0 (2022-07-22)
### Feature
* Bump version ([`01656a0`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/01656a03ae6ece3bbcf361bf14355894cf359f0d))

## v0.0.5 (2022-07-22)
### Feat
* Add support for Petoneer Smart Odor Eliminator Pro (SU001-T) ([`2281d03`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/2281d033323f8e78e5c2a192c8a900efe859308b))

## v0.0.4 (2022-07-22)
### Fix
* Workaround not knowing MAC on macOS ([`adcb639`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/adcb63967dbdfcd502c5fd15c27c33ceca5c7638))

## v0.0.3 (2022-07-22)
### Fix
* Trim service uuid from start of service data ([`8c35dc1`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/8c35dc16cf3a782f045d567bdce26e5a3296bbf9))

## v0.0.2 (2022-07-22)
### Fix
* Re-export sensor state classes like other bluetooth helpers ([`b7b97ba`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/b7b97ba50963218d45d9d883179302aca08987ca))

## v0.0.1 (2022-07-22)
### Fix
* Use fromutctimestamp for stable tests ([`c1e574c`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/c1e574c7a3e3eed98ee061764efc37599b9c251b))
* Give all tests right MAc, so validation passes on linux ([`da76a1d`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/da76a1dbad06e8eb0c990355d4b84dee3db23860))
* Get remaining tests working ([`8a042e4`](https://github.com/Bluetooth-Devices/xiaomi-ble/commit/8a042e4e2ef64151b6ad1db45ba9164d97a536cb))
