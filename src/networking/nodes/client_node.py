from src.crypto_engines.secure_bytes import secure_bytes
from src.crypto_engines.key_encapsulation import kem
from src.crypto_engines.utils import byte_tools
from src.crypto_engines.digitial_signatures import digital_signatures

from src.dht.dht import dht

from src.networking.nodes.node import node
from src.networking.connection_protocol import connection_protocol
from src.networking.connection_request import request, response
from src.networking.ip import ip


class client_node(node):
    _number_hops: int

    def __init__(self):
        super().__init__()
        self._number_hops = 3  # todo: load from config
        self._init_circuit()



    def _init_packet_handler(self) -> None:
        ...
