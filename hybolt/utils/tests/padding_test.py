from hybolt.utils.padding import add_padding, remove_padding


def test_given_short_payload_when_adding_padding_then_fills_remaining_block_space():
    payload = b"A"
    block_size = 4

    result = add_padding(payload, block_size)

    assert result == b"A\x03\x03\x03"


def test_given_block_sized_payload_when_adding_padding_then_adds_full_block():
    payload = b"DATA"
    block_size = 4

    result = add_padding(payload, block_size)

    assert result == b"DATA\x04\x04\x04\x04"


def test_given_valid_padding_when_removing_padding_then_returns_original_payload():
    padded_payload = b"DATA\x04\x04\x04\x04"

    result = remove_padding(padded_payload)

    assert result == b"DATA"


def test_given_invalid_padding_when_removing_padding_then_keeps_data_unchanged():
    short_payload = b"AB"
    invalid_padding = b"DATA\x04\x04\x04\x03"

    short_result = remove_padding(short_payload)
    invalid_padding_result = remove_padding(invalid_padding)

    assert short_result == short_payload
    assert invalid_padding_result == invalid_padding
