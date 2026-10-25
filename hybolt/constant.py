MAX_MAC_THREADS = 8
POLYNOMIAL_SET_SIZE = 40
POLYNOMIAL_LAMBDA = 127
# A full chunk holds DEFAULT_SOURCE_SYMBOLS R10 source symbols of
# DEFAULT_SYMBOL_SIZE bytes. R10 needs a nearly constant number of symbols
# beyond K, so K = 100 tolerates losing 14% of a chunk's packets in 99% of
# cases at the default redundancy, where K = 10 tolerated none; a repair still
# downloads only about K / 2 packets of one chunk.
DEFAULT_SOURCE_SYMBOLS = 100
DEFAULT_SYMBOL_SIZE = 6500
DEFAULT_CHUNK_SIZE = DEFAULT_SOURCE_SYMBOLS * DEFAULT_SYMBOL_SIZE
# Repair packets per source packet: r = ceil(redundancy * K).
DEFAULT_REDUNDANCY = 0.25
