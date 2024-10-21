import base64
import hashlib
import hmac
import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Any

import aiohttp
import orjson
from Cryptodome.Cipher import ARC4
from yarl import URL

SERVERS = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]
_LOGGER = logging.getLogger(__name__)

# Adapted from PiotrMachowski's Xiaomi-cloud-tokens-extractor
# MIT License
#
# Copyright (c) 2020 Piotr Machowski
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


LOGIN_URL = URL("https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true")
LOGIN_URL2 = URL("https://account.xiaomi.com/pass/serviceLoginAuth2")


@dataclass
class XiaomiCloudBLEDevice:

    name: str
    mac: str
    bindkey: str


class XiaomiCloudException(Exception):
    """Raised when an error occurs during Xiaomi Cloud API communication."""


class XiaomiCloudInvalidAuthenticationException(XiaomiCloudException):
    """Raised when an invalid authentication method is provided."""


class XiaomiCloudInvalidUsernameException(XiaomiCloudInvalidAuthenticationException):
    """Raised when an invalid username is provided."""


class XiaomiCloudInvalidPasswordException(XiaomiCloudInvalidAuthenticationException):
    """Raised when an invalid password is provided."""


class XiaomiCloudTwoFactorAuthenticationException(
    XiaomiCloudInvalidAuthenticationException
):
    """Raised when two factor authentication is required."""

    def __init__(self, message: str, url: str) -> None:
        """Initialize the exception."""
        super().__init__(message)
        self.url = url


class XiaomiCloudConnector:
    """Encapsulates Xiaomi Cloud API."""

    def __init__(
        self, username: str, password: str, session: aiohttp.ClientSession
    ) -> None:
        """Initialize the Xiaomi Cloud API."""
        self._username = username
        self._password = password
        self._agent = self.generate_agent()
        self._device_id = self.generate_device_id()
        self._session = session
        self._sign: str | None = None
        self._ssecurity: str | None = None
        self.userId: str | None = None
        self._cUserId: str | None = None
        self._passToken: str | None = None
        self._location: str | None = None
        self._code: str | None = None
        self._serviceToken: str | None = None

    async def _login_step_1(self) -> bool:
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        cookies = {**self._cookies, "userId": self._username}
        response = await self._session.get(LOGIN_URL, headers=headers, cookies=cookies)
        valid = response.status == 200 and "_sign" in self.to_json(
            await response.text()
        )
        if valid:
            self._sign = self.to_json(await response.text())["_sign"]
        return valid

    async def _login_step_2(self) -> bool:
        url = LOGIN_URL2
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        fields = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(str.encode(self._password)).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": self._username,
            "_sign": self._sign,
            "_json": "true",
        }
        response = await self._session.post(
            url, headers=headers, params=fields, cookies=self._cookies
        )
        valid = response is not None and response.status == 200
        if valid:
            json_resp = self.to_json(await response.text())
            valid = "ssecurity" in json_resp and len(str(json_resp["ssecurity"])) > 4
            if valid:
                self._ssecurity = json_resp["ssecurity"]
                self.userId = json_resp["userId"]
                self._cUserId = json_resp["cUserId"]
                self._passToken = json_resp["passToken"]
                self._location = json_resp["location"]
                self._code = json_resp["code"]
            elif "notificationUrl" in json_resp:
                raise XiaomiCloudTwoFactorAuthenticationException(
                    "Two factor authentication required.", json_resp["notificationUrl"]
                )
        return valid

    async def _login_step_3(self) -> bool:
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        response = await self._session.get(
            self._location, headers=headers, cookies=self._cookies
        )
        if response.status == 200:
            self._serviceToken = response.cookies.get("serviceToken").value
        return response.status == 200

    async def login(self) -> bool:
        self._cookies = {
            "sdkVersion": "accountsdk-18.8.15",
            "deviceId": self._device_id,
        }
        if not await self._login_step_1():
            raise XiaomiCloudInvalidUsernameException("Invalid username.")

        if not await self._login_step_2():
            raise XiaomiCloudInvalidPasswordException("Invalid password.")

        if not await self._login_step_3():
            raise XiaomiCloudException("Unable to get service token.")

        return True

    async def get_homes(self, country: str) -> dict[str, Any] | None:
        url = self.get_api_url(country) + "/v2/homeroom/gethome"
        params = {
            "data": '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}'  # noqa
        }
        return await self.execute_api_call_encrypted(url, params)

    async def get_devices(
        self, country: str, home_id: str, owner_id: str
    ) -> dict[str, Any] | None:
        url = self.get_api_url(country) + "/v2/home/home_device_list"
        params = {
            "data": '{"home_owner": '
            + str(owner_id)
            + ',"home_id": '
            + str(home_id)
            + ',  "limit": 200,  "get_split_device": true, "support_smart_home": true}'
        }
        return await self.execute_api_call_encrypted(url, params)

    async def get_dev_cnt(self, country: str) -> dict[str, Any] | None:
        url = self.get_api_url(country) + "/v2/user/get_device_cnt"
        params = {"data": '{ "fetch_own": true, "fetch_share": true}'}
        return await self.execute_api_call_encrypted(url, params)

    async def get_beaconkey(self, country: str, did: str) -> dict[str, Any] | None:
        url = self.get_api_url(country) + "/v2/device/blt_get_beaconkey"
        params = {"data": '{"did":"' + did + '","pdid":1}'}
        return await self.execute_api_call_encrypted(url, params)

    async def execute_api_call_encrypted(
        self, url: str, params: dict[str, Any]
    ) -> dict[str, Any] | None:
        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        cookies = {
            "userId": str(self.userId),
            "yetAnotherServiceToken": str(self._serviceToken),
            "serviceToken": str(self._serviceToken),
            "locale": "en_GB",
            "timezone": "GMT+02:00",
            "is_daylight": "1",
            "dst_offset": "3600000",
            "channel": "MI_APP_STORE",
            **self._cookies,
        }
        millis = round(time.time() * 1000)
        nonce = self.generate_nonce(millis)
        signed_nonce = self.signed_nonce(nonce)
        assert self._ssecurity is not None
        fields = self.generate_enc_params(
            url, "POST", signed_nonce, nonce, params, self._ssecurity
        )
        response = await self._session.post(
            url, headers=headers, cookies=cookies, params=fields
        )
        if response.status == 200:
            decoded = self.decrypt_rc4(
                self.signed_nonce(fields["_nonce"]), await response.text()
            )
            return orjson.loads(decoded)
        if response.status > 400 and response.status < 500:
            raise XiaomiCloudInvalidAuthenticationException("Authentication failed")
        return None

    @staticmethod
    def get_api_url(country: str) -> str:
        return (
            "https://"
            + ("" if country == "cn" else (country + "."))
            + "api.io.mi.com/app"
        )

    def signed_nonce(self, nonce: str) -> str:
        assert self._ssecurity is not None
        hash_object = hashlib.sha256(
            base64.b64decode(self._ssecurity) + base64.b64decode(nonce)
        )
        return base64.b64encode(hash_object.digest()).decode("utf-8")

    @staticmethod
    def signed_nonce_sec(nonce: str, ssecurity: str) -> str:
        hash_object = hashlib.sha256(
            base64.b64decode(ssecurity) + base64.b64decode(nonce)
        )
        return base64.b64encode(hash_object.digest()).decode("utf-8")

    @staticmethod
    def generate_nonce(millis: int) -> str:
        nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder="big")
        return base64.b64encode(nonce_bytes).decode()

    @staticmethod
    def generate_agent() -> str:
        agent_id = "".join(
            map(lambda i: chr(i), [random.randint(65, 69) for _ in range(13)])
        )
        return f"Android-7.1.1-1.0.0-ONEPLUS A3010-136-{agent_id} APP/xiaomi.smarthome APPV/62830"  # noqa

    @staticmethod
    def generate_device_id() -> str:
        return "".join(
            map(lambda i: chr(i), [random.randint(97, 122) for _ in range(6)])
        )

    @staticmethod
    def generate_signature(
        url: str, signed_nonce: str, nonce: str, params: dict[str, Any]
    ) -> str:
        signature_params: list[str] = [url.split("com")[1], signed_nonce, nonce]
        for k, v in params.items():
            signature_params.append(f"{k}={v}")
        signature_string = "&".join(signature_params)
        signature = hmac.new(
            base64.b64decode(signed_nonce),
            msg=signature_string.encode(),
            digestmod=hashlib.sha256,
        )
        return base64.b64encode(signature.digest()).decode()

    @staticmethod
    def generate_enc_signature(
        url: str, method: str, signed_nonce: str, params: dict[str, Any]
    ) -> str:
        signature_params: list[str] = [
            str(method).upper(),
            url.split("com")[1].replace("/app/", "/"),
        ]
        for k, v in params.items():
            signature_params.append(f"{k}={v}")
        signature_params.append(signed_nonce)
        signature_string = "&".join(signature_params)
        return base64.b64encode(
            hashlib.sha1(signature_string.encode("utf-8")).digest()
        ).decode()

    @staticmethod
    def generate_enc_params(
        url: str,
        method: str,
        signed_nonce: str,
        nonce: str,
        params: dict[str, Any],
        ssecurity: str,
    ) -> dict[str, Any]:
        params["rc4_hash__"] = XiaomiCloudConnector.generate_enc_signature(
            url, method, signed_nonce, params
        )
        for k, v in params.items():
            params[k] = XiaomiCloudConnector.encrypt_rc4(signed_nonce, v)
        params.update(
            {
                "signature": XiaomiCloudConnector.generate_enc_signature(
                    url, method, signed_nonce, params
                ),
                "ssecurity": ssecurity,
                "_nonce": nonce,
            }
        )
        return params

    @staticmethod
    def to_json(response_text: str) -> dict[str, Any]:
        """Convert a response to a JSON object."""
        return orjson.loads(response_text.replace("&&&START&&&", ""))

    @staticmethod
    def encrypt_rc4(password: str, payload: str) -> str:
        """Encrypt a piece of data."""
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return base64.b64encode(r.encrypt(payload.encode())).decode()

    @staticmethod
    def decrypt_rc4(password: str, payload: str) -> str:
        """Decrypt a piece of data."""
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return r.encrypt(base64.b64decode(payload))


class XiaomiCloudTokenFetch:

    def __init__(
        self, username: str, password: str, session: aiohttp.ClientSession
    ) -> None:
        """Initialize the Xiaomi Cloud API."""
        self._username = username
        self._password = password
        self._session = session

    async def get_device_info(
        self, mac: str, servers: list[str] = SERVERS
    ) -> XiaomiCloudBLEDevice | None:
        """Get the token for a given MAC address."""
        formatted_mac = format_mac_upper(mac)
        connector = XiaomiCloudConnector(self._username, self._password, self._session)
        await connector.login()
        assert connector.userId is not None
        homes: dict[str, str] = {}

        for server in servers:
            home_info = await connector.get_homes(server)
            if home_info is not None:
                for h in home_info["result"]["homelist"]:
                    homes[h["id"]] = connector.userId

            dev_cnt = await connector.get_dev_cnt(server)
            if dev_cnt is not None:
                for h in dev_cnt["result"]["share"]["share_family"]:
                    homes[h["home_id"]] = h["home_owner"]

            for home_id, owner_id in homes.items():
                devices = await connector.get_devices(server, home_id, owner_id)
                if (
                    devices is None
                    or not devices["result"]
                    or not devices["result"]["device_info"]
                ):
                    continue

                device_info: list[dict[str, Any]] = devices["result"]["device_info"]
                for device in device_info:
                    if (
                        device["mac"] != formatted_mac
                        or "did" not in device
                        or "blt" not in device["did"]
                    ):
                        continue
                    key_result = await connector.get_beaconkey(server, device["did"])
                    if (
                        key_result
                        and (result := key_result.get("result"))
                        and (beacon_key := result.get("beaconkey"))
                    ):
                        _LOGGER.debug(
                            "Found beacon key for %s: %s (%s)",
                            formatted_mac,
                            beacon_key,
                            device,
                        )
                        return XiaomiCloudBLEDevice(
                            device["name"], device["mac"], beacon_key
                        )

        return None


def format_mac_upper(mac: str) -> str:
    """Format the mac address string to be upper case."""
    to_test = mac

    if len(to_test) == 17 and to_test.count(":") == 5:
        return to_test.upper()

    if len(to_test) == 17 and to_test.count("-") == 5:
        to_test = to_test.replace("-", "")
    elif len(to_test) == 14 and to_test.count(".") == 2:
        to_test = to_test.replace(".", "")

    if len(to_test) == 12:
        # no : included
        return ":".join(
            to_test.upper()[i : i + 2] for i in range(0, 12, 2)  # noqa: E203
        )

    # Not sure how formatted, return original
    return mac
