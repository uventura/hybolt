import hashlib
import hmac
import secrets
from dataclasses import dataclass


@dataclass
class SealingKeys:
    """Hides the code structure from servers.

    Each packet is encrypted with a SHAKE-256 keystream bound to its file, chunk
    and ESI, and stored under a pseudorandom name. Servers then cannot read the
    systematic source symbols or tell which chunk a packet belongs to, so they
    cannot concentrate corruption on a single chunk.
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

    def keystream(self, chunk_index, packet_index, length) -> bytes:
        return hashlib.shake_256(
            self.key + b"stream" + self._position(chunk_index, packet_index)
        ).digest(length)

    def seal(self, chunk_index, packet_index, data) -> bytes:
        keystream = self.keystream(chunk_index, packet_index, len(data))
        sealed = int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")
        return sealed.to_bytes(len(data), "big")

    # XOR with the same keystream inverts the encryption.
    open = seal

    def _position(self, chunk_index, packet_index) -> bytes:
        return (
            self.file_id
            + chunk_index.to_bytes(8, "big")
            + packet_index.to_bytes(8, "big")
        )
