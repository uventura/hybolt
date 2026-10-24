import hashlib
from abc import ABC, abstractmethod

from raptorq import Decoder as RaptorQDecoder

from hybolt.encryption.block import Block, LocalBlock
from hybolt.encryption.local_mac import LocalMac
from hybolt.encryption.retrievability import RetrievabilityProof, xor_macs
from hybolt.logger.logger import execution_logger
from hybolt.utils.operators import xor_bytes
from hybolt.utils.padding import remove_padding


class DecodingStrategy(ABC):
    """Strategy for reconstructing one metadata unit (a chunk or a legacy file)."""

    codec = ""

    def __init__(self, metadata, server_cache, proof: RetrievabilityProof, sealer=None):
        self._metadata = metadata
        self._server_cache = server_cache
        self._proof = proof
        self._sealer = sealer
        if self._proof.enabled and self._proof.requires_client_macs:
            self._validate_proof_metadata()

    @abstractmethod
    def decode(self) -> bytes:
        pass

    @abstractmethod
    def _validate_proof_metadata(self):
        """Raise ValueError when the metadata cannot back a retrievability proof."""

    def _server_for(self, packet):
        server = self._server_cache.get(packet.server)
        if server is None:
            raise ValueError(f"Server not found for storage location: {packet.server}")
        return server

    def _download_verified_block(self, block, expected_mac):
        if not self._proof.verify(block.server, block, expected_mac):
            return None

        if block.packet_file:
            data = block.server.download_block(block.index, block.packet_file)
        else:
            data = block.server.download_block(block.index)

        if not self._proof.verify_download(block.server, block, data):
            return None

        if not block.packet_sha256:
            execution_logger.warning(
                f"Block {block.index} has no integrity hash; skipping SHA-256 check"
            )
            return data

        if hashlib.sha256(data).hexdigest() != block.packet_sha256:
            execution_logger.error(
                f"Integrity verification failed for block index: {block.index}"
            )
            return None

        return data

    def _missing_proof_metadata_error(self, detail):
        return ValueError(
            f"{self.codec} metadata cannot back the retrievability proof: {detail}. "
            "Re-encode with the proof enabled or decode with it disabled."
        )


class LtDecodingStrategy(DecodingStrategy):
    """Peeling decoder; a packet's MAC is the XOR of its source blocks' MACs."""

    codec = "lt"

    def __init__(self, metadata, server_cache, proof, sealer=None):
        self._local_mac = self._build_local_mac(metadata)
        super().__init__(metadata, server_cache, proof, sealer)
        self._local_blocks = self._build_local_blocks(metadata)

    def decode(self):
        data = self._retrieve_blocks()
        result = b""
        for msg_i in sorted(data.keys()):
            result += data[msg_i].data
        return remove_padding(result)

    def _validate_proof_metadata(self):
        if not self._metadata.polynomials:
            raise self._missing_proof_metadata_error("no challenge polynomials")
        if not self._local_mac:
            raise self._missing_proof_metadata_error("no source block MACs")

    def _expected_mac(self, block):
        return lambda polynomial_index: xor_macs(
            [self._local_mac[i][polynomial_index].mac for i in block.indices]
        )

    def _retrieve_blocks(self):
        retrieved_data = {}
        num_blocks_to_retrieve = self._find_num_blocks_to_retrieve()

        blocks = self._local_blocks.copy()
        self._log_all_local_blocks(blocks)

        rejected_blocks = set()
        retrieved_at_cycle_start = 0

        degree = 1
        execution_logger.debug(
            f"Number of blocks to retrieve: {num_blocks_to_retrieve}"
        )
        while len(retrieved_data.keys()) < num_blocks_to_retrieve:
            execution_logger.debug(
                f"Degree: {degree}, solved: {retrieved_data.keys()}\n"
            )

            for _, block in enumerate(blocks.get(degree, [])):
                if id(block) in rejected_blocks:
                    continue

                solvable_parts = int(
                    self._count_solvable_parts(block, set(retrieved_data.keys()))
                )
                execution_logger.debug(f"Solvable parts: {solvable_parts}")
                execution_logger.debug(f"Block: {block}")
                if solvable_parts == 0:
                    execution_logger.debug("Block is already solved, skipping.\n")
                    continue

                partial_block = self._solve_partial_block(block, retrieved_data)
                if partial_block is None:
                    rejected_blocks.add(id(block))
                    continue

                partial_block.degree = solvable_parts
                execution_logger.debug(f"Partial block data: {partial_block}\n")

                # An unreduced partial carries no new information; re-queuing it
                # into the list being iterated would never terminate.
                if solvable_parts < len(block.indices):
                    blocks.setdefault(solvable_parts, []).append(partial_block)

                if solvable_parts == 1:
                    retrieved_index = partial_block.indices[0]
                    retrieved_data[retrieved_index] = partial_block
                    execution_logger.info(f"Retrieved block index: {retrieved_index}")
            degree += 1
            if degree > max(blocks.keys()):
                degree = 1
                if len(retrieved_data) == retrieved_at_cycle_start:
                    raise ValueError("Insufficient verified blocks to reconstruct data")
                retrieved_at_cycle_start = len(retrieved_data)
            execution_logger.debug("-" * 40)

        execution_logger.debug(retrieved_data)
        return retrieved_data

    def _find_num_blocks_to_retrieve(self):
        max_index = -1
        for blocks in self._local_blocks.values():
            for block in blocks:
                if block.indices:
                    max_index = max(max_index, max(block.indices))
        return max_index + 1

    def _count_solvable_parts(self, block, retrieved_indices):
        return len(block.indices) - len(set(block.indices) & retrieved_indices)

    def _solve_partial_block(self, block, retrieved_data):
        if not isinstance(block, Block):
            data = self._download_verified_block(block, self._expected_mac(block))
            if data is None:
                return None
        else:
            data = block.data

        indices = set(block.indices)
        if len(indices) == 1 and not indices.issubset(retrieved_data):
            return Block(block.index, block.degree, block.indices, data)

        # Build a new index list: the original block keeps its indices so a later
        # challenge still combines the MACs of every source block it covers.
        remaining_indices = []
        for index in block.indices:
            if index in retrieved_data:
                data = xor_bytes(data, retrieved_data[index].data)
            else:
                remaining_indices.append(index)
        return Block(block.index, block.degree, remaining_indices, data)

    def _log_all_local_blocks(self, blocks):
        execution_logger.debug("-" * 20)
        execution_logger.debug(" " * 4 + "LOCAL BLOCKS")
        execution_logger.debug("-" * 20)

        for block in blocks:
            execution_logger.debug(f"[{block}]:")
            for e in blocks[block]:
                execution_logger.debug(f"  {e}")
            execution_logger.debug("-" * 10)
        execution_logger.debug("_" * 20)

    def _build_local_blocks(self, metadata):
        local_blocks = {}
        execution_logger.debug("Building local blocks from metadata")
        for packet in metadata.packets:
            local_block = LocalBlock(
                index=packet.packet_index,
                degree=packet.degree,
                indices=list(packet.indices),
                server=self._server_for(packet),
                packet_file=getattr(packet, "packet_file", ""),
                packet_sha256=getattr(packet, "packet_sha256", ""),
            )
            local_blocks.setdefault(packet.degree, []).append(local_block)
            execution_logger.debug(
                "Generated local block: "
                f"index={local_block.index}, "
                f"degree={local_block.degree}, "
                f"indices={local_block.indices}, "
                f"server={local_block.server._storage_location}"
            )

        execution_logger.debug(
            f"Built local blocks grouped by degree: "
            f"{ {degree: len(blocks) for degree, blocks in local_blocks.items()} }"
        )
        return local_blocks

    def _build_local_mac(self, metadata):
        if not metadata.blocks:
            execution_logger.debug("No local MAC entries found in metadata")
            return []

        num_blocks = max(block.block_index for block in metadata.blocks) + 1
        local_mac = [
            [None for _ in range(len(metadata.polynomials))] for _ in range(num_blocks)
        ]

        execution_logger.debug(
            f"Building local MAC matrix with {num_blocks} blocks and "
            f"{len(metadata.polynomials)} polynomials"
        )

        for block_metadata in metadata.blocks:
            local_mac[block_metadata.block_index][block_metadata.polynomial_index] = (
                LocalMac(
                    mac=block_metadata.mac_value,
                    polynomial_index=block_metadata.polynomial_index,
                    block_index=block_metadata.block_index,
                )
            )
            execution_logger.debug(
                "Generated local MAC: "
                f"block_index={block_metadata.block_index}, "
                f"polynomial_index={block_metadata.polynomial_index}, "
                f"mac_value={block_metadata.mac_value}"
            )

        execution_logger.debug(
            "Built local MAC matrix occupancy: "
            f"{[sum(mac is not None for mac in row) for row in local_mac]}"
        )

        return local_mac


class RaptorQDecodingStrategy(DecodingStrategy):
    """Feeds verified packets to a RaptorQ decoder; each packet carries its own MACs."""

    codec = "raptorq"

    def decode(self):
        transfer_length = getattr(self._metadata, "transfer_length", 0)
        symbol_size = getattr(self._metadata, "symbol_size", 0)
        if transfer_length <= 0 or symbol_size <= 0:
            raise ValueError("RaptorQ metadata is missing transfer parameters")

        decoder = RaptorQDecoder.with_defaults(transfer_length, symbol_size)
        for packet in self._metadata.packets:
            if not getattr(packet, "packet_sha256", ""):
                raise ValueError(
                    f"RaptorQ packet {packet.packet_index} has no integrity hash"
                )

            block = LocalBlock(
                index=packet.packet_index,
                degree=packet.degree,
                indices=list(packet.indices),
                server=self._server_for(packet),
                packet_file=packet.packet_file,
                packet_sha256=packet.packet_sha256,
            )
            packet_data = self._download_verified_block(
                block, lambda polynomial_index, macs=packet.macs: macs[polynomial_index]
            )
            if packet_data is None:
                continue
            if self._sealer is not None:
                packet_data = self._sealer.open(
                    self._metadata.chunk_index, packet.packet_index, packet_data
                )

            decoded = decoder.decode(packet_data)
            if decoded is not None:
                return decoded

        raise ValueError("Insufficient valid RaptorQ packets to reconstruct data")

    def _validate_proof_metadata(self):
        polynomial_count = len(self._metadata.polynomials)
        if polynomial_count == 0:
            raise self._missing_proof_metadata_error("no challenge polynomials")

        for packet in self._metadata.packets:
            if len(getattr(packet, "macs", [])) != polynomial_count:
                raise self._missing_proof_metadata_error(
                    f"packet {packet.packet_index} has no MAC for every polynomial"
                )


DECODING_STRATEGIES = {
    strategy.codec: strategy
    for strategy in (LtDecodingStrategy, RaptorQDecodingStrategy)
}


def create_decoding_strategy(
    metadata, server_cache, proof, sealer=None
) -> DecodingStrategy:
    codec = getattr(metadata, "codec", LtDecodingStrategy.codec)
    strategy = DECODING_STRATEGIES.get(codec)
    if strategy is None:
        raise ValueError(f"Unsupported codec: {codec}")
    return strategy(metadata, server_cache, proof, sealer)
