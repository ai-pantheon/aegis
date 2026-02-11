"""
Vault — Encrypted Data Storage
AES-256-GCM envelope encryption for any categorized data store.

Each data category gets a unique Data Encryption Key (DEK).
The DEK is encrypted by the user's Key Encryption Key (KEK).
The KEK is derived from the user's passphrase and never stored.

Your data. Your keys. Your control.
"""

import json
import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# KEK derivation parameters
PBKDF2_ITERATIONS = 600_000  # OWASP recommended minimum
SALT_SIZE = 16
NONCE_SIZE = 12  # AES-256-GCM standard
KEY_SIZE = 32    # 256 bits


def derive_kek(passphrase: str, salt: bytes) -> bytes:
    """Derive a Key Encryption Key from a passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def generate_dek() -> bytes:
    """Generate a random Data Encryption Key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_data(data: bytes, key: bytes) -> dict:
    """Encrypt data with AES-256-GCM. Returns nonce + ciphertext."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_data(encrypted: dict, key: bytes) -> bytes:
    """Decrypt AES-256-GCM encrypted data."""
    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


class Vault:
    """
    Encrypted data store using envelope encryption.

    Envelope encryption:
    - Each data category gets its own DEK (Data Encryption Key)
    - DEKs are encrypted by the KEK (derived from your passphrase)
    - Data is encrypted by the category's DEK
    - The KEK never touches disk

    Args:
        passphrase: Your secret passphrase. Used to derive the KEK.
        vault_dir: Directory to store encrypted files. Created if it doesn't exist.
    """

    def __init__(self, passphrase: str, vault_dir: str | Path = "./vault-encrypted"):
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.salt_file = self.vault_dir / ".vault-salt"

        # Load or create salt
        if self.salt_file.exists():
            self.salt = base64.b64decode(self.salt_file.read_text())
        else:
            self.salt = os.urandom(SALT_SIZE)
            self.salt_file.write_text(base64.b64encode(self.salt).decode())

        # Derive KEK from passphrase (never stored)
        self.kek = derive_kek(passphrase, self.salt)

        # DEK registry: category -> DEK (loaded on demand)
        self._deks: dict[str, bytes] = {}

    def _get_dek(self, category: str) -> bytes:
        """Get or create the DEK for a data category."""
        if category in self._deks:
            return self._deks[category]

        dek_file = self.vault_dir / f".dek-{category}"

        if dek_file.exists():
            # Load and decrypt existing DEK
            encrypted_dek = json.loads(dek_file.read_text())
            dek = decrypt_data(encrypted_dek, self.kek)
        else:
            # Generate new DEK and encrypt it with KEK
            dek = generate_dek()
            encrypted_dek = encrypt_data(dek, self.kek)
            dek_file.write_text(json.dumps(encrypted_dek))

        self._deks[category] = dek
        return dek

    def store(self, category: str, data: dict) -> dict:
        """
        Encrypt and store a data category.

        Args:
            category: Name for this data group (e.g., "contacts", "notes").
            data: Any JSON-serializable dictionary.

        Returns:
            Metadata about what was stored.
        """
        dek = self._get_dek(category)

        # Serialize to JSON bytes
        plaintext = json.dumps(data, indent=2).encode("utf-8")

        # Encrypt with the category's DEK
        encrypted = encrypt_data(plaintext, dek)

        # Build envelope
        envelope = {
            "category": category,
            "encrypted": encrypted,
            "plaintext_size": len(plaintext),
        }

        # Write to vault
        vault_file = self.vault_dir / f"{category}.vault"
        vault_file.write_text(json.dumps(envelope, indent=2))

        return {
            "category": category,
            "plaintext_bytes": len(plaintext),
            "encrypted_bytes": len(encrypted["ciphertext"]),
            "vault_file": str(vault_file),
        }

    def load(self, category: str) -> dict:
        """
        Load and decrypt a data category from the vault.

        Args:
            category: The category name to load.

        Returns:
            The decrypted data as a dictionary. Empty dict if not found.
        """
        vault_file = self.vault_dir / f"{category}.vault"

        if not vault_file.exists():
            return {}

        envelope = json.loads(vault_file.read_text())
        dek = self._get_dek(category)

        # Decrypt
        plaintext = decrypt_data(envelope["encrypted"], dek)
        return json.loads(plaintext.decode("utf-8"))

    def store_all(self, data: dict[str, dict]) -> list[dict]:
        """Encrypt and store multiple categories at once."""
        results = []
        for category, category_data in data.items():
            result = self.store(category, category_data)
            results.append(result)
        return results

    def load_all(self) -> dict:
        """Load and decrypt all categories from the vault."""
        data = {}
        for vault_file in self.vault_dir.glob("*.vault"):
            category = vault_file.stem
            data[category] = self.load(category)
        return data

    def verify(self, category: str, original: dict) -> bool:
        """Verify that stored data decrypts to match the original."""
        loaded = self.load(category)
        return json.dumps(loaded, sort_keys=True) == json.dumps(original, sort_keys=True)

    def categories(self) -> list[str]:
        """List all stored categories."""
        return [f.stem for f in self.vault_dir.glob("*.vault")]

    def stats(self) -> dict:
        """Get vault statistics."""
        total_bytes = 0
        cats = []
        for f in self.vault_dir.glob("*.vault"):
            total_bytes += f.stat().st_size
            cats.append(f.stem)
        return {
            "vault_dir": str(self.vault_dir),
            "categories": cats,
            "total_files": len(cats),
            "total_bytes_on_disk": total_bytes,
        }
