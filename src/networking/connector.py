import abc, socket
from typing import Optional
from src.crypto_engines.secure_bytes import secure_bytes
from src.networking.connection_request import request
from src.networking.ip import ip


class abstract_connector(abc.ABC):
    @abc.abstractmethod
    def send(self, request_object: request, who_to: ip) -> None:
        ...

    @abc.abstractmethod
    def recv(self) -> (secure_bytes, ip):
        ...


class socket_connector(abstract_connector):
    _socket: socket.socket

    def __init__(self, configured_socket: Optional[socket.socket] = None) -> None:
        self._socket = configured_socket or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, request_object: request, who_to: ip) -> None:
        self._socket.sendto(request_object.bytes, who_to.socket_format)

    def recv(self) -> (secure_bytes, ip):
        raw_response, raw_ip = self._socket.recvfrom(1024)
        return secure_bytes(raw_response), ip.from_bytes(raw_ip)
