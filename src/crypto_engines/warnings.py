class symmetric_failed_decryption_warning(Warning):
    """
    The symmetric_failed_decryption_warning warning is thrown when an encrypted message cannot be decrypted into the
    correct plaintext, ie the attached meta ata is not identifiable, and therefore the decryption must've failed (this
    is the only determinant, as layered encryption is impossible to determine if the decryption is correct or not)
    """


class timestamp_out_of_tolerance_warning(Warning):
    """
    The timestamp_out_of_tolerance_warning warning is thrown when a signed message is received, and the timestamp is out
    of a set tolerance. This might be the result of a replay attack, here a previous message that has been signed has
    been captured and is being resent (would have to be withing the 20-second same-key window).
    """
    pass


class mac_mismatch_warning(Warning):
    """
    The mac_mismatch_warning warning is thrown when a message is received and the recalculated mac of the data doesn't
    equal the one sent along. This might be the result of an adversary changing the data being transmitted, changing the
    mac tag, or changing both. In any case, the packet / message is discarded.
    """
    pass
