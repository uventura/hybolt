import numpy as np

from hybolt.encryption.local_mac import LocalMac
import hybolt.utils.galois as ga
from hybolt.utils.operators import calculate_mac_for_block


def test_given_block_and_polynomial_when_calculating_mac_then_returns_expected_local_mac():
    block = b"ABCD"
    representation = ga.bytes_to_poly_coeffs(block)
    polynomial = np.array([1, 1, 0, 1, 1], dtype=np.uint8)

    mac = calculate_mac_for_block(
        representation=representation,
        polynomial=polynomial,
        polynomial_index=2,
        block_index=7,
    )

    expected = ga.gf2_poly_mod(ga.bytes_to_poly_coeffs(block), polynomial    )

    assert isinstance(mac, LocalMac)
    assert mac.polynomial_index == 2
    assert mac.block_index == 7
    assert np.array_equal(mac.mac, expected)
