from src.crypto_engines.secure_bytes import secure_bytes
from src.networking.ip import ip


class dht:
    @staticmethod
    def select_node() -> ip:
        ...

    @staticmethod
    def select_node_and_get_public_key() -> (ip, secure_bytes):
        ...

    @staticmethod
    def get_static_public_key(node: ip) -> secure_bytes:
        ...
