import hashlib
import hmac
import secrets
from dataclasses import dataclass


@dataclass
class SealingKeys:
    """Hides the code structure from servers.

    Each packet is encrypted with a SHAKE-256 keystream bound to its file, chunk
    and ESI, and stored under a pseudorandom name. Servers then cannot read the
    RaptorQ header, the systematic source symbols or the chunk a packet belongs
    to, so they cannot concentrate corruption on a single chunk.
    """

    key: bytes
    file_id: bytes

    @classmethod
    def generate(cls):
        return cls(key=secrets.token_bytes(32), file_id=secrets.token_bytes(16))

    def packet_file(self, chunk_index, packet_index) -> str:
        digest = hmac.new(
            self.key,
            b"name" + self._position(chunk_index, packet_index),
            hashlib.sha256,
        ).hexdigest()
        return f"{digest[:32]}.pkl"

    def seal(self, chunk_index, packet_index, data) -> bytes:
        keystream = hashlib.shake_256(
            self.key + b"stream" + self._position(chunk_index, packet_index)
        ).digest(len(data))
        return bytes(byte ^ mask for byte, mask in zip(data, keystream))

    # XOR with the same keystream inverts the encryption.
    open = seal

    def _position(self, chunk_index, packet_index) -> bytes:
        return (
            self.file_id
            + chunk_index.to_bytes(8, "big")
            + packet_index.to_bytes(8, "big")
        )
