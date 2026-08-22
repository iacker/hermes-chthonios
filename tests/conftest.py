"""Test config: run scrypt cheaply so the suite is fast.

Production defaults to N=2**20 (~1s, ~1GB RAM per derivation). Tests exercise
the same code paths; the work factor is a runtime knob, not part of what we're
testing. N is stored per-envelope, so a low-N seal still round-trips correctly.
"""
import os

os.environ.setdefault("CHTHONIOS_SCRYPT_N", str(1 << 14))
