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

    def _init_circuit(self) -> None:
        self._my_ephemeral_asymmetric_key_pair = kem.generate_keypair()

        who_to, their_static_public_key = dht.select_node_and_get_public_key()
        init_message = byte_tools.merge(self._my_ephemeral_public_key, ip.this().bytes)
        signature, message = digital_signatures.sign(self._my_static_private_key, init_message, their_static_public_key)

        self._candidate_next_node_ip = who_to
        self._socket.sendto(byte_tools.merge(signature, message), who_to.socket_format)

    def _init_packet_handler(self) -> None:
        ...

    def _handle_connection_accept_command(self, response_: response, who_from: ip) -> None:
        super()._handle_connection_accept_command(response_, who_from)
        self._init_packet_handler()

    def _handle_connection_reject_command(self, response_: response, who_from: ip) -> None:
        super()._handle_connection_reject_command(response_, who_from)
        self._init_circuit()
