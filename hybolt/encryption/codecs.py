"""The fountain codes a chunk can be encoded with, keyed by the name in its metadata.

Each module provides `Encoder`, `Decoder`, `source_symbol_count`,
`symbol_support`, `recoverable` and `SYSTEMATIC`; every packet of both codes
is the XOR of the source blocks in its support.
"""

from hybolt.encryption import online_codes, raptor

CODECS = {module.CODEC: module for module in (raptor, online_codes)}
DEFAULT_CODEC = raptor.CODEC
CODEC_NAMES = {raptor.CODEC: "Raptor R10", online_codes.CODEC: "Online Codes"}


def codec_module(codec: str):
    module = CODECS.get(codec)
    if module is None:
        raise ValueError(f"Unsupported codec: {codec}")
    return module
