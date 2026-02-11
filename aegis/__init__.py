"""
Aegis — The Cloak
Client-side encryption and request anonymization for private data stores.

Aegis provides two layers of protection:
1. Vault — AES-256-GCM envelope encryption (the lock)
2. Cloak — Request anonymization: padding, stripping, shuffling, tokens (the cloak)

Together they ensure: your data is encrypted at rest with keys only you hold,
and the pattern of access reveals nothing about the data inside.
"""

from aegis.vault import Vault
from aegis.cloak import Cloak
from aegis.padding import pad_to_bucket, unpad_from_bucket, BUCKET_SIZES
from aegis.shuffle import ShuffleBuffer
from aegis.tokens import PrivacyTokenIssuer

__version__ = "0.1.0"
__all__ = [
    "Vault",
    "Cloak",
    "ShuffleBuffer",
    "PrivacyTokenIssuer",
    "pad_to_bucket",
    "unpad_from_bucket",
    "BUCKET_SIZES",
]
