import numpy as np

from hybolt.utils.galois import (
    _poly_coeffs_to_int,
    bytes_to_poly_coeffs,
    gf2_poly_mod,
    generate_challenge_polynomial,
)


def test_given_bytes_when_converting_to_polynomial_then_maps_binary_coefficients():
    msg = b"\x0a"

    result = bytes_to_poly_coeffs(msg)
    expected = np.array([0, 1, 0, 1, 0, 0, 0, 0])

    np.testing.assert_array_equal(result, expected)


def test_given_message_matching_primitive_when_calculating_mac_then_returns_empty_mac():
    m_x = np.array([1, 0, 1, 1])
    p_x = np.array([1, 0, 1, 1])

    mac = gf2_poly_mod(m_x, p_x)

    np.testing.assert_array_equal(mac, np.array([0, 0, 0], dtype=np.uint8))


def test_given_known_polynomial_division_when_calculating_modulo_then_returns_expected_remainder():
    m_x = np.array([1, 1, 0, 1])
    p_x = np.array([1, 1, 1])

    mac = gf2_poly_mod(m_x, p_x)

    np.testing.assert_array_equal(mac, np.array([0, 1], dtype=np.uint8))


def test_given_zero_dividend_when_calculating_modulo_then_preserves_remainder_width():
    m_x = np.array([0, 0, 0], dtype=np.uint8)
    p_x = np.array([1, 1], dtype=np.uint8)

    mac = gf2_poly_mod(m_x, p_x)

    np.testing.assert_array_equal(mac, np.array([0], dtype=np.uint8))


def test_given_polynomial_coefficients_when_converting_to_int_then_treats_first_as_low_bit():
    coefficients = np.array([1, 0, 1, 1], dtype=np.uint8)

    result = _poly_coeffs_to_int(coefficients)

    assert result == 13


def test_given_degree_when_generating_challenge_then_output_length_is_correct():
    degree = 127

    poly = generate_challenge_polynomial(degree)

    assert len(poly) == degree + 1


def test_given_degree_when_generating_challenge_then_coefficients_are_binary():
    degree = 16

    poly = generate_challenge_polynomial(degree)

    assert np.all((poly == 0) | (poly == 1))


def test_given_degree_when_generating_challenge_then_highest_degree_coefficient_is_set():
    degree = 127

    poly = generate_challenge_polynomial(degree)

    assert poly[-1] == 1


def test_given_degree_when_generating_challenge_then_constant_term_is_non_zero():
    degree = 127

    poly = generate_challenge_polynomial(degree)

    assert poly[0] == 1


def test_given_multiple_challenges_when_generating_them_then_they_are_randomly_distributed():
    degree = 64

    poly1 = generate_challenge_polynomial(degree)
    poly2 = generate_challenge_polynomial(degree)

    assert not np.array_equal(poly1, poly2)
