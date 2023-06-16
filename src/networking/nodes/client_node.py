from src.crypto_engines.secure_bytes import secure_bytes
from src.crypto_engines.key_encapsulation import kem
from src.crypto_engines.utils import byte_tools, key_set
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
        self._number_hops = 3
        self._init_circuit()

    def _init_circuit(self) -> None:
        # Clear all IP addresses (these could be non-Null from a previous circuit connection attempt). Generate a new
        # ephemeral asymmetric key pair, to ensure perfect forward secrecy, ensuring that each session is uniquely
        # encrypted.
        self._prev_node_ip = None
        self._next_node_ip = None
        self._my_ephemeral_asymmetric_key_pair = kem.generate_keypair()

        # Select a node from the DHT to connect to. Form the connection request command, and send it to the selected
        # node. The connection request consists of the CON_REQ command, the ephemeral public key of this node, and the
        # signature of the ephemeral public key. The signature will embed meta data such as the recipients id (their
        # static public key) and a timestamp.
        who_to, their_static_public_key = dht.select_node_and_get_public_key()
        init_message = byte_tools.merge(self._my_ephemeral_public_key, ip.this().bytes)
        signature, message = digital_signatures.sign(self._my_static_private_key, init_message, their_static_public_key)

        # Set the candidate next node IP address, and send the connection request to the selected node. The
        # candidate IP address is required so that an incoming CON_ACC or CON_REJ command can be verified as being
        # as coming from the correct node.
        self._candidate_next_node_ip = who_to
        self._socket.sendto(byte_tools.merge(signature, message), who_to.socket_format)

    def _init_packet_handler(self) -> None:
        ...

    def _handle_connection_accept_command(self, response_: response, who_from: ip) -> None:
        # The client node receives a connection accept command from another node. The first operation performed is to
        # verify the signature of the KEMed symmetric master key. If the signature is valid, the client node will
        # KEM unwrap the symmetric master key and save it against the "next" node, so that any data sent and received
        # between this node and the next node in the route can be encrypted and decrypted.
        signed_wrapped_master_key, wrapped_master_key = byte_tools.unmerge(response_.data, 1)
        digital_signatures.verify(
            their_static_public_key=dht.get_static_public_key(who_from),
            message=wrapped_master_key,
            signature=signed_wrapped_master_key,
            my_ephemeral_public_key=self._my_ephemeral_public_key)

        # Save the key against the next node, and then initialise the packet handler. This will begin packet
        # interception, manipulation and injection, after exchanging the packet keys to the other nodes in the route
        # via the route itself.
        self._e2e_next_node_master_key = key_set(kem.kem_unwrap(self._my_ephemeral_private_key, wrapped_master_key))
        self._init_packet_handler()

    def _handle_connection_reject_command(self, response_: response, who_from: ip) -> None:
        # The client node receives a connection reject command from another node. Check the signature of the reason
        # for rejection, and if there is a signature mismatch then there is ap possibility that someone had forced the
        # rejection, so retry the connection. If the signature is valid, then the client node will re-initialise the
        # circuit, and try to connect to another node.
        signed_reason_to_reject, reason_to_reject = response_.data
        digital_signatures.verify(
            their_static_public_key=dht.get_static_public_key(who_from),
            message=reason_to_reject,
            signature=signed_reason_to_reject,
            my_ephemeral_public_key=self._my_ephemeral_public_key)

        # TODO - try reconnect if the signature is invalid

        # Re-initialise the circuit, and try to connect to another node. Reset the candidate next node IP address to
        # None, so that the circuit is re-initialised.
        self._candidate_next_node_ip = None
        self._init_circuit()
