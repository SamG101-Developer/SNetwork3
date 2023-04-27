from __future__ import annotations
from src.crypto_engines.hashing import hashing
from src.crypto_engines.key_derivation import kdf
from src.crypto_engines.secure_bytes import secure_bytes
from src.crypto_engines.symmetric import symmetric_cipher
import time


class key_set:
    def __init__(self, master_key: secure_bytes):
        self._master_key = master_key
        self._hashed_master_key = hashing.hash(master_key)
        self._symmetric_cipher_key = kdf.derive_key(master_key, secure_bytes(b"SYMMETRIC-CIPHER-KEY"), symmetric_cipher.KEY_LENGTH)

    @property
    def master_key(self) -> secure_bytes:
        return self._master_key

    @property
    def hashed_master_key(self) -> secure_bytes:
        return self._hashed_master_key

    @property
    def symmetric_cipher_key(self) -> secure_bytes:
        return self._symmetric_cipher_key


class key_pair:
    def __init__(self, secret_key: secure_bytes | None = None, public_key: secure_bytes | None = None):
        self._secret_key = secret_key
        self._public_key = public_key

    @property
    def secret_key(self) -> secure_bytes:
        # Get the internal secret key (used for signing messages or decrypting kem messages). If the secret key is None,
        # then an exception will be raised.
        assert self._secret_key is not None
        return self._secret_key

    @property
    def public_key(self) -> secure_bytes:
        # Get the internal public key (used for verifying signatures or encrypting kem messages). If the public key is
        # None, then an exception will be raised.
        assert self._public_key is not None
        return self._public_key

    @property
    def public_key_hash(self) -> secure_bytes:
        # Get the hash of the public key (used for inserting into signed messages to ensure the receiver is the intended
        # receiver). If the public key is None, then an exception will be raised.
        assert self.public_key is not None
        return hashing.hash(self.public_key)

    @staticmethod
    def this() -> key_pair:
        # Get this device's static keys -- these keys are used for signing and verifying messages. They cannot be used
        # for encrypting or decrypting messages, as this would break forward secrecy.
        return key_pair.import_key_pair("../../profile/static_keys.keys")

    @staticmethod
    def import_key_pair(file_path: str) -> key_pair:
        # Import a saved key pair into a key pair instance from a file. The file must be a binary file that contains the
        # secret key followed by the public key, separated by pre-determined merger character.
        secret_key, public_key = byte_tools.unmerge(open(file_path, "rb").read())
        return key_pair(secret_key, public_key)

    def export_key_pair(self, file_path: str) -> None:
        # Export the key pair from a key pair instance into a file. The file will be a binary file that will contain the
        # secret key followed by the public key, separated by pre-determined merger character.
        merged_keys = byte_tools.merge(self._secret_key, self._public_key)
        open(file_path, "wb").write(merged_keys)


class byte_tools:
    DELIMITER = b"-"

    @staticmethod
    def merge(*args: secure_bytes) -> secure_bytes:
        # Merge multiple bytes objects into a single bytes object, separating them with a pre-determined merger
        # character stored as a static const member of the class.
        return secure_bytes(byte_tools.DELIMITER.join(args))

    @staticmethod
    def unmerge(message: secure_bytes, max_splits: int = 1) -> [secure_bytes]:
        # Split a bytes object into multiple bytes objects, separated by a pre-determined merger character stored as a
        # static const member of the class.
        return message.split(byte_tools.DELIMITER, max_splits)

    @staticmethod
    def int_to_bytes(i: int | float) -> secure_bytes:
        return secure_bytes(i.to_bytes(i.bit_length() // 8 + 1, "little"))

    @staticmethod
    def split_at_n(message: bytes, n: int) -> tuple[secure_bytes, secure_bytes]:
        # Split a bytes object into multiple bytes objects, each of length n.
        return secure_bytes(message[:n]), secure_bytes(message[n:])


class timestamp:
    TOLERANCE = 500_000

    @staticmethod
    def current_time_bytes() -> secure_bytes:
        current_time: float = time.time_ns()
        return byte_tools.int_to_bytes(current_time)

    @staticmethod
    def in_tolerance(t1: secure_bytes, t2: secure_bytes) -> bool:
        t1 = int.from_bytes(t1, "little")
        t2 = int.from_bytes(t2, "little")
        return t1 > t2 and t1 - t2 < timestamp.TOLERANCE


class counter:
    def __init__(self, counter_length: int, forwards: bool = True):
        self._counter_length: int = counter_length
        self._forwards: bool = forwards
        self._value: int = 0

        # set the counter to its default value (0 or MAX)
        self.reset()

    def reset(self) -> counter:
        # reset the value to its initial value
        self._value = 0 if self._forwards else (1 << self._counter_length) - 1
        return self

    def step_value(self) -> counter:
        # increment a forward counter, or decrement a backwards counter
        self._value += 1 if self._forwards else -1
        return self

    @property
    def value(self) -> int:
        return self._value
