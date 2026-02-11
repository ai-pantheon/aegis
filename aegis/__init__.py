"""
Aegis — The Cloak
Client-side encryption and request anonymization for private data stores.

Aegis provides two cryptographically bound layers:
1. Vault — AES-256-GCM envelope encryption (the lock)
2. Cloak — Request anonymization: padding, stripping, shuffling, tokens (the cloak)

These layers are cryptographically bound: the Vault's encryption key requires
a seal that only the Cloak can derive. You MUST use the Cloak to access the Vault.
Attempting to use the Vault directly will fail — not by policy, but by math.

Usage:
    from aegis import Cloak
    cloak = Cloak("my-passphrase")
    cloak.store({"category": {"key": "value"}})
"""

from aegis.cloak import Cloak
from aegis.padding import pad_to_bucket, unpad_from_bucket, BUCKET_SIZES
from aegis.shuffle import ShuffleBuffer
from aegis.tokens import PrivacyTokenIssuer

__version__ = "0.2.0"
__all__ = [
    "Cloak",
    "ShuffleBuffer",
    "PrivacyTokenIssuer",
    "pad_to_bucket",
    "unpad_from_bucket",
    "BUCKET_SIZES",
]
