import pickle
import random
from pathlib import Path

from hybolt.logger.progress import advance_progress, create_progress_task, get_progress
from hybolt.logger.logger import execution_logger
from hybolt.server.server import Server
from hybolt.encryption.encoding_metadata import PacketMetadata


class PacketSaver:
    def __init__(self, packets, input_path, server_list=None, chunk_index=None):
        self.packets = packets
        self.input_path = input_path
        self.server_list = server_list
        self.chunk_index = chunk_index
        self.progress = get_progress()
        self._packet_metadata = []

    def save(self):
        if not self.server_list:
            raise ValueError("server_list is required")

        self._shuffle_packets()
        self._save_to_servers()

    @property
    def packet_metadata(self):
        return self._packet_metadata

    def _shuffle_packets(self):
        random.shuffle(self.packets)

    def _save_to_servers(self):
        servers = [
            Server(server_dict["storage_location"]) for server_dict in self.server_list
        ]
        execution_logger.debug(
            f"Saving {len(self.packets)} packets across {len(servers)} servers"
        )
        task_id = create_progress_task(
            self.progress,
            "Saving packets to server storage",
            total=len(self.packets),
        )

        for packet in self.packets:
            self._save_single_packet(packet, servers, task_id)

        execution_logger.debug("Packet distribution completed")

    def _save_single_packet(self, packet, servers, task_id):
        server_index = packet.index % len(servers)
        server = servers[server_index]
        packet.set_server(server)
        server_storage = Path(server._storage_location)
        server_storage.mkdir(parents=True, exist_ok=True)
        packet_file = (
            server_storage / self._packet_file_name(packet.index)
        )

        with open(packet_file, "wb") as f:
            pickle.dump(packet, f)

        self._packet_metadata.append(
            PacketMetadata(
                server=server._storage_location,
                packet_index=packet.index,
                degree=packet.degree,
                indices=packet.indices,
                packet_file=packet_file.name,
            )
        )

        advance_progress(self.progress, task_id)

    def _packet_file_name(self, packet_index):
        if self.chunk_index is None:
            return f"{self.input_path.stem}_packet_{packet_index}.pkl"
        return f"{self.input_path.stem}_chunk_{self.chunk_index}_packet_{packet_index}.pkl"
