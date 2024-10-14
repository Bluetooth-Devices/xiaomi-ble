import asyncio
import pprint
from getpass import getpass

from aiohttp import ClientSession

from xiaomi_ble import XiaomiCloudTokenFetch
from xiaomi_ble.cloud import SERVERS

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


async def main(username: str, password: str, mac: str, servers: list[str]) -> None:
    async with ClientSession() as session:
        fetcher = XiaomiCloudTokenFetch(username, password, session)
        device_info = await fetcher.get_device_info(mac, servers)
        if device_info:
            pprint.pprint(device_info)
            return
        print(f"No devices found matching the provided MAC address: {mac}.")


print("Username (email or user ID):")
username = input()
print("Password:")
password = getpass("")
print("Mac address:")
mac = input()
print(f"Server (one of: {','.join(SERVERS)}) Leave empty to check all available:")
server = input()
while server not in ["", *SERVERS]:
    print(f"Invalid server provided. Valid values: {','.join(SERVERS)}")
    print("Server:")
    server = input()

print()

asyncio.run(main(username, password, mac, [server] if server else SERVERS))
