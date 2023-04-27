import socket
import threading


class node_spawner:
    _monitor_inbound: socket.socket
    _spawned_nodes: list[threading.Thread]


    def __init__(self):
        self._monitor_inbound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._monitor_inbound.bind(("", 0))  # todo
        self._monitor_inbound.setblocking(False)

        self._spawned_nodes = []
        while True:

