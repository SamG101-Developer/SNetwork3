from cryptography.hazmat.primitives.hashes import Hash, SHA3_512, SHAKE256, SHA512
from typing import TypeVar
from src.crypto_engines.secure_bytes import secure_bytes

T = TypeVar("T")


class hashing:
    # List of algorithms to use for hashing in preferred order - if there are consistent issues with the first
    # algorithm, it will be removed from the list and the next algorithm will be used instead
    hash_algorithms = [SHA3_512, SHAKE256, SHA512]

    # The following constants are used to define the current algorithm to use for hashing. They are used to define the
    # access information for the current algorithm.
    BLOCK_SIZE  = hash_algorithms[0].block_size
    DIGEST_SIZE = hash_algorithms[0].digest_size
    HASH_NAME   = hash_algorithms[0].name

    @staticmethod
    def hash(data: secure_bytes, encoding: T = secure_bytes) -> T:
        # Create a hash of the data using the current algorithm, and encoding (default are secure bytes). The current
        # algorithm is the first algorithm in the list of algorithms to use for hashing.
        hash_engine = Hash(hashing.hash_algorithms[0]())
        hash_engine.update(data)
        return encoding(hash_engine.finalize())

    @staticmethod
    def switch_to_backup() -> None:
        # Switch the current algorithm to the next algorithm in the list of algorithms to use for hashing. If the
        # current algorithm is the last algorithm in the list, then then an exception will be raised.
        assert len(hashing.hash_algorithms) > 1
        hashing.hash_algorithms.pop(0)
