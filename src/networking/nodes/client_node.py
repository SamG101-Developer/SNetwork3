from typing import Optional

from src.crypto_engines.secure_bytes import secure_bytes
from src.crypto_engines.key_encapsulation import kem
from src.crypto_engines.utils import byte_tools, key_set
from src.crypto_engines.digitial_signatures import digital_signatures
from src.crypto_engines.symmetric import symmetric_cipher

from src.dht.dht import dht

from src.networking.nodes.node import node
from src.networking.connection_protocol import connection_protocol
from src.networking.connection_request import request, response
from src.networking.ip import ip


class client_node(node):
    _number_hops: int
    _nodes_in_circuit: [(ip, secure_bytes, key_set)]
    _next_node_accepted: Optional[bool]

    def __init__(self):
        super().__init__()
        self._number_hops = 3
        self._nodes_in_circuit = []
        self._next_node_accepted = None

        self._e2e_next_node_master_key = key_set.random()
        self._init_packet_handler()

    def _init_packet_handler(self) -> None:
        # To start the connection process, the client will simulate sending itself a connection extension command,
        # by calling the method that the "extend" command would call. This will cause the correct method to call and
        # begin creating the circuit.
        self._nodes_in_circuit.append((ip.this(), None, None))

        # Iterate so that there are the correct number of nodes in the relay circuit. Each iteration will add another
        # node into the circuit, and will perform a KEM key exchange with the node, via the existing relay circuit.
        for i in range(1, self._number_hops + 1):

            # Find a new node (and its associated public key) to connect to, by querying the DHT. Construct the
            # connection request command, and wrap it in the correct number of forwarded messages - each iteration
            # will remove 1 "forward" command, so the correct node will receive the actual command. The "extend"
            # command is used to tell the current circuit node to extend the circuit by 1 node. The layered
            # encryption means that only the last node will ever see the IP address of the target node.
            target_node, target_node_static_public_key = dht.select_node_and_get_public_key()
            request_ = request(
                command=connection_protocol.COMMAND_EXTEND_CIRCUIT,
                flag=connection_protocol.FLAG_NONE,
                data=target_node)

            for j in range(i - 1):
                request_ = request(connection_protocol.COMMAND_FORWARD, connection_protocol.FLAG_NONE, request_.bytes)
                request_.data = symmetric_cipher.encrypt(self._nodes_in_circuit[j][2].symmetric_key, request_.data)

            # The first node will either be fhe first in the list of nodes, or if that list is empty, ie the first node
            # hasn't joined the circuit yet, then the first node will be the target node, meaning that there will be
            # no forwarding (i=0), so the routing isn't changed. Send the (possibly wrapped) request to the first node
            # in the circuit, and wait for a response (flag will be set). This must be a blocking operation as the
            # circuit has to be constructed in order.
            self._socket.sendto(request_.bytes, self._nodes_in_circuit[0][0].socket_format)

            # Wait for a reject or accept response from the target node. If the response is a reject, then the node
            # will be removed from the circuit, and the loop will continue, so that another node can be selected.
            while self._next_node_accepted is None:
                pass

            # Decrement i so that the loop doesn't skip a node. If the response is an accept, then the node will be
            # added to the circuit, and the loop will continue, so that another node can be selected.
            if not self._next_node_accepted:
                i -= 1
                continue

            # The target node has accepted the connection request, so the next node in the circuit will be the target
            # node. Along with the forwarded "accept" message back from the circuit, the target node will also send
            # back its ephemeral public key, and a signature of the ephemeral public key.
            wrapped_symmetric_key, symmetric_key = kem.kem_wrap(self._nodes_in_circuit[-1][1])
            self._nodes_in_circuit[-1] = (
                self._nodes_in_circuit[-1][0],
                self._nodes_in_circuit[-1][1],
                key_set(symmetric_key))

            # Create the "kem key" request to send to the target node, and wrap it in the correct number of forwarded
            # messages. The data being sent is the wrapped symmetric key, which is encrypted with the target nodes
            # ephemeral public key. The The ephemeral public key being sent it not authenticated ie vulnerable to
            # MITM attacks. This is mitigated with uni-directional authentication in the message received back from
            # the target node.
            request_ = request(
                command=connection_protocol.COMMAND_KEM_KEY,
                flag=connection_protocol.FLAG_NONE,
                data=wrapped_symmetric_key)

            for j in range(i - 1):
                request_ = request(connection_protocol.COMMAND_FORWARD, connection_protocol.FLAG_NONE, request_.bytes)
                request_.data = symmetric_cipher.encrypt(self._nodes_in_circuit[j][2].symmetric_key, request_.data)

            # Send the (possibly wrapped) request to the target node via the first node in the circuit. The first node
            # will unwrap the request, and forward it to the next node in the circuit. The target node will unwrap the
            # request, and perform a KEM key exchange with the client node. The target node will then send back a
            # response, which will be forwarded back to the client node.
            self._socket.sendto(request_.bytes, self._nodes_in_circuit[0][0].socket_format)

    def _handle_connection_accept_command(self, response_: response, who_from: ip) -> None:
        super()._handle_connection_accept_command(response_, who_from)

        # If the connection being accepted has reached the client node, then either the client and node 1 have
        # successfully connected, or another connection in the circuit has been successful and the client is being
        # told the ephemeral key of that node.
        their_ephemeral_public_key_and_signature = byte_tools.unmerge(response_.data, 1)[1]
        their_ephemeral_public_key, their_ephemeral_public_key_signature = byte_tools.unmerge(their_ephemeral_public_key_and_signature, 1)
        digital_signatures.verify(
            their_static_public_key=dht.get_static_public_key(who_from),
            message=their_ephemeral_public_key,
            signature=their_ephemeral_public_key_signature,
            my_ephemeral_public_key=self._my_ephemeral_public_key)

        self._nodes_in_circuit.append((who_from, key_set(their_ephemeral_public_key), None))
        self._candidate_next_node_ip = who_from
        self._next_node_accepted = True

    def _handle_connection_reject_command(self, response_: response, who_from: ip) -> None:
        super()._handle_connection_reject_command(response_, who_from)

        # Re-initialise the circuit, and try to connect to another node. Reset the candidate next node IP address to
        # None, so that the circuit is re-initialised.
        self._candidate_next_node_ip = None
        self._next_node_accepted = False
