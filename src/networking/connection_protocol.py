from enum import Enum
from src.crypto_engines.secure_bytes import secure_bytes
from src.networking.ip import ip
from src.networking.connection_request import request, response


class connection_protocol(Enum):  # TODO -> separate into connection_command(Enum) and connection_flag(Enum)
    COMMAND_FORWARD         = 0x01.to_bytes(1, "little")
    COMMAND_CLOSING         = 0x02.to_bytes(1, "little")  # this node is closing the connection
    COMMAND_CONNECT_REQUEST = 0x03.to_bytes(1, "little")  # request to connect to a relay node
    COMMAND_CONNECT_REJECT  = 0x04.to_bytes(1, "little")  # connection rejected
    COMMAND_CONNECT_TIMEOUT = 0x05.to_bytes(1, "little")  # connection timed out
    COMMAND_CONNECT_ACCEPT  = 0x05.to_bytes(1, "little")  # connection accepted, and send signed ePKn
    COMMAND_KEM_KEY         = 0x07.to_bytes(1, "little")  # incoming kem wrapped key
    COMMAND_CONFIRM_KEM_KEY = 0x08.to_bytes(1, "little")  # confirm
    COMMAND_EXTEND_CIRCUIT  = 0x09.to_bytes(1, "little")  # extend circuit

    FLAG_NONE = secure_bytes(0x00.to_bytes(1, "little"))
    FLAG_PH1 = 0x01.to_bytes(1, "little")
    FLAG_PH2 = 0x02.to_bytes(1, "little")
    FLAG_PH3 = 0x04.to_bytes(1, "little")
    FLAG_PH4 = 0x08.to_bytes(1, "little")
    FLAG_PH5 = 0x10.to_bytes(1, "little")
    FLAG_PH6 = 0x20.to_bytes(1, "little")
    FLAG_PH7 = 0x40.to_bytes(1, "little")
    FLAG_PH8 = 0x80.to_bytes(1, "little")

    @staticmethod
    def extract(raw: secure_bytes) -> (request | response, tuple[ip, ip, ip]):
        new_command, new_flag = connection_protocol(raw[0:1]), connection_protocol(raw[1:2])
        new_data = raw[2:-8]
        prev_ip, curr_ip, next_ip = ip.from_bytes(raw[-12:-8]), ip.from_bytes(raw[-8:-4]), ip.from_bytes(raw[-4:])
        return request(new_command, new_flag, new_data), (prev_ip, curr_ip, next_ip)
