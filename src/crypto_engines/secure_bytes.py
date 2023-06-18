from __future__ import annotations

import os

from cryptography.hazmat.primitives.constant_time import bytes_eq
from src.crypto_engines.hashing import hashing


class secure_bytes(bytes):
    """
    The secure_bytes class is a wrapper class around the bytes class that implements constant time comparison methods.
    """
    _bytes: bytes

    def __init__(self, b=b""):
        # Assign the bytes object to the internal bytes object.
        self._bytes = b

    @staticmethod
    def random(length: int) -> secure_bytes:
        # Return a secure_bytes object with random bytes.
        return secure_bytes(os.urandom(length))

    def __eq__(self, other: secure_bytes) -> bool:
        # Compare the internal bytes objects using the constant time comparison method.
        salt = secure_bytes(os.urandom(32))
        hash_lhs = hashing.hash(salt + self)
        hash_rhs = hashing.hash(salt + other)

        checks = []
        for b1, b2 in zip(hash_lhs, hash_rhs):
            checks.append(b1 == b2)
        return all(checks)

    def __ne__(self, other: secure_bytes) -> bool:
        # Compare the internal bytes objects using the constant time comparison method.
        return not self == other

    def __add__(self, other: secure_bytes) -> secure_bytes:
        # Add the internal bytes objects.
        return secure_bytes(self._bytes + other._bytes)

    def __radd__(self, other: secure_bytes) -> secure_bytes:
        # Add the internal bytes objects.
        return secure_bytes(other._bytes + self._bytes)

    def __getitem__(self, item: int | slice) -> secure_bytes:
        # Get the item from the internal bytes object (taking the same amount of time no matter where in the byte-string
        # the item is).
        value = b""
        for i in range(len(self._bytes)):
            value = self._bytes[item] if i == item else value
        return secure_bytes(value)

    def __setitem__(self, key: int | slice, value: secure_bytes) -> None:
        # Set the item in the internal bytes object (taking the same amount of time no matter where in the byte-string
        # the item is).
        for i in range(len(self._bytes)):
            self._bytes[key] = value._bytes if i == key else self._bytes[key]

    def __contains__(self, item: secure_bytes) -> bool:
        # Check if the item is in the internal bytes object (taking the same amount of time no matter where in the byte-
        # string the item is).
        value = False
        for i in range(len(self._bytes)):
            value |= self._bytes[i] == item._bytes
        return value

    def __len__(self) -> int:
        # Return the length of the internal bytes object.
        return len(self._bytes)

    def __str__(self) -> str:
        # Return the string representation of the internal bytes object.
        return self._bytes.decode("utf-8")

    def __repr__(self) -> str:
        # Return the string representation of the internal bytes object.
        return self._bytes.decode("utf-8")

    def __hash__(self) -> int:
        # Return the hash of the internal bytes object.
        return hash(self._bytes)

    def __iter__(self) -> secure_bytes:
        # Return the iterator of the internal bytes object.
        return self

    def __reversed__(self) -> secure_bytes:
        # Return the reversed iterator of the internal bytes object.
        return secure_bytes(self._bytes[::-1])

    @property
    def raw(self) -> bytes:
        # Return the internal bytes object.
        return self._bytes
