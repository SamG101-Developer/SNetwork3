from __future__ import annotations
from src.crypto_engines.secure_bytes import secure_bytes
import socket
import stun


class ip:
    def __init__(self):
        self._ip: str = ""

    @property
    def bytes(self) -> secure_bytes:
        return secure_bytes(socket.inet_aton(self._ip))

    @property
    def string(self) -> str:
        return self._ip

    @property
    def socket_format(self) -> tuple[str, int]:
        return self.string, 0  # TODO : get port from config file

    @property
    def ip(self) -> str:
        return self._ip

    @ip.setter
    def ip(self, new_ip_address: str):
        assert self._ip == ""
        self._ip = new_ip_address

    @staticmethod
    def from_string(self, string_format: str) -> ip:
        ip_object: ip = ip()
        ip_object.ip = string_format
        return ip_object

    @staticmethod
    def from_bytes(bytes_format: bytes) -> ip:
        ip_object: ip = ip()
        ip_object.ip = socket.inet_ntoa(bytes_format)
        return ip_object

    @staticmethod
    def from_socket_format(socket_format: tuple[str, int]) -> ip:
        ip_object: ip = ip()
        ip_object.ip = socket_format[0]
        return ip_object

    @staticmethod
    def this() -> ip:
        ip_object: ip = ip()
        ip_object.ip = stun.get_ip_info()[1]
        return ip_object

    def __eq__(self, other: ip) -> bool:
        return self.ip == ip.ip

    def __gt__(self, other: ip) -> bool:
        return int.from_bytes(self.bytes, "little") > int.from_bytes(ip.bytes, "little")


if __name__ == "__main__":
    print(ip.this())
