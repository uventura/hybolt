import glob
import pickle
import shutil
from pathlib import Path

import hybolt.utils.galois as ga


class Server:
    def __init__(self, storage_location: str):
        self._storage_location = storage_location
        Path(self._storage_location).mkdir(parents=True, exist_ok=True)

    def storage_check_block(self, check_block):
        source_path = Path(check_block)
        destination_path = Path(self._storage_location) / source_path.name
        shutil.copyfile(source_path, destination_path)

    def store_packet(self, packet, packet_file) -> Path:
        packet_path = Path(self._storage_location) / packet_file
        with open(packet_path, "wb") as file:
            pickle.dump(packet, file)
        return packet_path

    def download_block(self, block_index, packet_file=""):
        block_path = self._find_check_block(block_index, packet_file)
        if block_path is None:
            raise ValueError("Check block not found")

        return self._read_block_data(block_path)

    def receive_challenge(self, polynomial, check_block_index, packet_file=""):
        block_path = self._find_check_block(check_block_index, packet_file)
        if block_path is None:
            raise ValueError("Check block not found")

        response = self._compute_response(polynomial, block_path)
        return response

    def receive_aggregate_challenge(self, polynomial, packet_files, shifts=None):
        """Hy-SAIL Algorithm 2: answer (sum of x^k_eta * c_eta) mod P_j."""
        remainders = []
        for packet_file in packet_files:
            block_path = self._find_check_block(None, packet_file)
            if block_path is None:
                raise ValueError(f"Check block not found: {packet_file}")
            remainders.append(self._compute_response(polynomial, block_path))

        return ga.aggregate_remainders(remainders, polynomial, shifts)

    def remove_packet(self, packet_file):
        Path(self._storage_location, packet_file).unlink(missing_ok=True)

    def _find_check_block(self, check_block_index, packet_file=""):
        if packet_file:
            packet_path = Path(self._storage_location) / packet_file
            return str(packet_path) if packet_path.is_file() else None

        pattern = str(
            Path(self._storage_location) / f"*_packet_{check_block_index}.pkl"
        )
        matches = glob.glob(pattern)
        return matches[0] if matches else None

    def _compute_response(self, polynomial, block_path):
        data = self._read_block_data(block_path)
        coefs = ga.bytes_to_poly_coeffs(data)
        return ga.gf2_poly_mod(coefs, polynomial)

    def _read_block_data(self, block_path):
        with open(block_path, "rb") as file:
            try:
                payload = pickle.load(file)
            except (pickle.UnpicklingError, EOFError):
                file.seek(0)
                return file.read()

        if hasattr(payload, "data"):
            return payload.data

        return payload
