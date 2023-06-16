from src.networking.nodes.node import node
from src.networking.connection_request import response
from src.networking.connection_protocol import connection_protocol
from src.networking.ip import ip

from src.crypto_engines.symmetric import symmetric_cipher
from src.crypto_engines.digitial_signatures import digital_signatures
from src.crypto_engines.key_encapsulation import kem
from src.crypto_engines.utils import byte_tools, key_set

from src.dht.dht import dht

import socket


class circuit_node(node):
    def __init__(self):
        super().__init__()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(ip.this().socket_format)

    def _handle_connection_request_command(self, response_: response, who_from: ip) -> None:
        # When a circuit node receives a CONN_REQ command, it will be to start a new circuit. This means that the node
        # making the connection request will sit directly behind this node in the circuit. As part of the handshake, the
        # message will contain the other node's ephemeral public key, signed with their static private key. Given their
        # IP is known, this node can verify that the received ephemeral public key is indeed from the node making the
        # connection request. An adversary could change the IP addresses on the packets and recompute the CRCs as well
        # as changing the signed key to their own signed key, but this is mitigated by signatures embedding the
        # recipient's address in -- this circuit node will embed the IP address of the recipient node in the data it
        # sends back, so if the recipient receives data (via the adversary), their own IP won't be in the signed
        # message, so they will know someone is intercepting the messages, and can close the connection. There is no
        # advantage to the recipient encrypting their ephemeral key with the circuit node's public key, as public keys
        # are designed to be available to everyone, and KEMs don't allow for this anyway.
        their_signed_ephemeral_public_key, their_ephemeral_public_key = byte_tools.unmerge(response_.data, 1)
        their_static_public_key = dht.get_static_public_key(who_from)
        digital_signatures.verify(
            their_static_public_key=their_static_public_key,
            message=their_ephemeral_public_key,
            signature=their_signed_ephemeral_public_key,
            my_ephemeral_public_key=self._my_ephemeral_public_key)

        # Once this node has verified the recipient's ephemeral public key, it can generate a master key for
        # authenticated, symmetric, end-to-end encryption over the shared channel. This master key is then KEM-wrapped
        # under the recipient's ephemeral public key, and signed with this node's static private key. This allows for
        # the recipient to verify that the master key is from this node, and that it is for them and that the handshake
        # hasn't been tampered with. The wrapped master key and signature is then sent to the recipient. KEM-then-sign
        # has to be used rather than sign-then-KEM, because KEM-wrapping generates the underlying key too, so the input
        # cannot be changed. For a handshake, however, security is not compromised by this.
        wrapped_master_key, master_key = kem.kem_wrap(their_ephemeral_public_key)
        signature, message = digital_signatures.sign(self._my_static_private_key, wrapped_master_key, their_ephemeral_public_key)
        bytes_to_send = byte_tools.merge(signature, message).raw
        self._socket.sendto(bytes_to_send, who_from.socket_format)

        # Save the master key to the previous node, so that it can be used to encrypt data sent to the recipient, and
        # decrypt data received from the recipient. The tag authentication is automatically handled by the symmetric
        # cipher functions.
        self._e2e_prev_node_master_key = key_set(master_key)
