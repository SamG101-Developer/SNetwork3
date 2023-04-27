from typing import Optional

from src.crypto_engines.digitial_signatures import digital_signatures
from src.crypto_engines.utils import byte_tools, key_pair, key_set
from src.crypto_engines.key_encapsulation import kem
from src.crypto_engines.secure_bytes import secure_bytes
from src.crypto_engines.symmetric import symmetric_cipher

from src.dht.dht import dht

from src.networking.connection_request  import response
from src.networking.connection_protocol import connection_protocol
from src.networking.ip import ip

import socket


class node:
    _client: bool

    _my_static_asymmetric_key_pair: key_pair
    _my_ephemeral_asymmetric_key_pair: key_pair
    _socket: socket.socket

    _prev_node_ip: ip
    _next_node_ip: ip
    _candidate_next_node_ip: Optional[ip]

    _e2e_prev_node_master_key: key_set
    _e2e_next_node_master_key: key_set

    def __init__(self, client: bool = False):
        self._client = client
        self._socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._socket.bind(("", 5000))
        self._number_hops = 3

        if self._client:
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

    def _handle_recv(self, response_: response, who_from: ip) -> None:
        match response_.command:
            case connection_protocol.COMMAND_CONNECT_REQUEST if self._qualified_to_accept_connection():
                their_signed_ephemeral_public_key, their_ephemeral_public_key = byte_tools.unmerge(response_.data, 1)
                their_static_public_key = dht.get_static_public_key(who_from)
                digital_signatures.verify(their_static_public_key, their_ephemeral_public_key, their_signed_ephemeral_public_key, self._my_ephemeral_public_key)

                wrapped_master_key, master_key = kem.kem_wrap(their_ephemeral_public_key)
                signature, message = digital_signatures.sign(self._my_static_private_key, wrapped_master_key, their_ephemeral_public_key)
                self._socket.sendto(byte_tools.merge(signature, message).raw, who_from.socket_format)
                self._e2e_prev_node_master_key = key_set(master_key)

            case connection_protocol.COMMAND_CONNECT_ACCEPT if self._candidate_next_node_ip and who_from == self._candidate_next_node_ip:
                their_static_public_key = dht.get_static_public_key(who_from)
                signed_wrapped_master_key, wrapped_master_key = byte_tools.unmerge(response_.data, 1)
                digital_signatures.verify(their_static_public_key, wrapped_master_key, signed_wrapped_master_key, self._my_ephemeral_public_key)
                self._e2e_next_node_master_key = key_set(kem.kem_unwrap(self._my_ephemeral_private_key, wrapped_master_key))

                if self._client:
                    self._init_packet_handler()
                else:
                    plain_text = byte_tools.merge(connection_protocol.COMMAND_CONNECT_ACCEPT, who_from.bytes, response_.data)
                    cipher_text = symmetric_cipher.encrypt(self._e2e_prev_node_master_key.symmetric_cipher_key, plain_text)
                    self._socket.sendto(response(connection_protocol.COMMAND_FORWARD, data=cipher_text), self._prev_node_ip.socket_format)

            case connection_protocol.COMMAND_CONNECT_REJECT if self._candidate_next_node_ip and who_from == self._candidate_next_node_ip:
                self._candidate_next_node_ip = None
                if self._client:
                    self._init_circuit()
                else:
                    plain_text = byte_tools.merge(connection_protocol.COMMAND_CONNECT_REJECT, who_from.bytes, response_.data)
                    cipher_text = symmetric_cipher.encrypt(self._e2e_prev_node_master_key.symmetric_cipher_key, plain_text)
                    self._socket.sendto(response(connection_protocol.COMMAND_FORWARD, data=cipher_text), self._prev_node_ip.socket_format)

    def _qualified_to_accept_connection(self) -> bool:
        ...

    @property
    def _my_ephemeral_public_key(self) -> secure_bytes:
        return self._my_ephemeral_asymmetric_key_pair.public_key

    @property
    def _my_ephemeral_private_key(self) -> secure_bytes:
        return self._my_ephemeral_asymmetric_key_pair.secret_key

    @property
    def _my_static_public_key(self) -> secure_bytes:
        return self._my_static_asymmetric_key_pair.public_key

    @property
    def _my_static_private_key(self) -> secure_bytes:
        return self._my_static_asymmetric_key_pair.secret_key
