from src.networking.connection_protocol import connection_protocol
from src.crypto_engines.secure_bytes import secure_bytes


class request:
    _command: connection_protocol
    _flag   : connection_protocol
    _data   : secure_bytes

    def __init__(self, command: connection_protocol, flag: connection_protocol = b"", data: secure_bytes = b""):
        self._command = command
        self._flag    = flag
        self._data    = data

    @property
    def command(self) -> connection_protocol:
        return self._command

    @property
    def flag(self) -> connection_protocol:
        return self._flag

    @property
    def data(self) -> secure_bytes:
        return self._data

    @data.setter
    def data(self, new_data: secure_bytes):
        # Used to encrypt the data after it has already been set
        self._data = new_data

    @property
    def bytes(self) -> secure_bytes:
        return self._command.value + (self._flag.value or b'\x00') + (self._data or b'\x00')

    @classmethod
    def from_received_data(cls, data: bytes):
        return cls(command=data[0:1], flag=data[1:2], data=data[2:])


class response(request):
    ...
