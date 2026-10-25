DEFAULT_BLOCK_SIZE_PERCENTAGE = 0.10
MAX_MAC_THREADS = 8
POLYNOMIAL_SET_SIZE = 40
POLYNOMIAL_LAMBDA = 127
# Repair packets per source packet. R10 is not MDS: with the default K = 10,
# 0.25 (r = 3) loses a chunk to 15% of single-packet losses, while 0.5
# (r = 5) survives every single loss and 98% of double losses.
DEFAULT_REDUNDANCY = 0.5
