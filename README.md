# Aegis

**Client-side encryption and request anonymization for private data stores.**

Your data. Your keys. Your control. Aegis gives you two layers of protection that work together:

| Layer | What It Does |
|-------|-------------|
| **Vault** | AES-256-GCM envelope encryption. Each data category gets its own key. The master key is derived from your passphrase and never stored. |
| **Cloak** | Request anonymization. Bucket padding, metadata stripping, order shuffling, and privacy tokens. An observer sees fixed-size encrypted blobs in random order with no identifying metadata. |

Part of the **[You Own You](https://ai-pantheon.ai)** initiative by **[AI Pantheon](https://ai-pantheon.ai)**.

---

## Install

```bash
pip install aegis-cloak
```

Or from source:

```bash
git clone https://github.com/ai-pantheon/aegis.git
cd aegis
pip install -e .
```

Requires Python 3.10+ and the `cryptography` library.

---

## Quick Start

### Vault Only (Encryption)

```python
from aegis import Vault

vault = Vault("my-secret-passphrase", vault_dir="./my-vault")

# Store encrypted data
vault.store("contacts", {
    "friends": [
        {"name": "Alice", "note": "Met at the conference"},
        {"name": "Bob", "note": "College roommate"},
    ]
})

# Load and decrypt
contacts = vault.load("contacts")
print(contacts)

# Verify integrity
assert vault.verify("contacts", contacts)
```

### Full Cloak (Encryption + Anonymization)

```python
from aegis import Cloak

cloak = Cloak("my-secret-passphrase", vault_dir="./my-vault")

# Store multiple categories through the full pipeline
report = cloak.store({
    "journal": {"entries": [{"date": "2026-02-11", "text": "It works."}]},
    "bookmarks": {"links": [{"url": "https://example.com"}]},
    "settings": {"theme": "dark"},
})

print(f"Shuffle order: {report['shuffle_order']}")
print(f"Padding overhead: {report['total_padded_bytes'] - report['total_plaintext_bytes']} bytes")
print(f"Metadata stripped from each request")

# Load everything back
data = cloak.load_all()
```

---

## How It Works

### Vault: Envelope Encryption

```
Your Passphrase
    ↓ PBKDF2-SHA256 (600K iterations)
Key Encryption Key (KEK) ← never stored
    ↓ encrypts
Data Encryption Key (DEK) ← one per category, stored encrypted
    ↓ encrypts
Your Data → AES-256-GCM → ciphertext on disk
```

- Each data category gets its own DEK (Data Encryption Key)
- DEKs are encrypted by the KEK (Key Encryption Key)
- The KEK is derived from your passphrase via PBKDF2 with 600,000 iterations
- The KEK exists only in memory, never on disk
- Wrong passphrase = decryption fails. No backdoors.

### Cloak: Traffic Analysis Resistance

Even with encryption, an observer could learn from *patterns*: how big is the data? What order is it accessed? How often? The Cloak eliminates these side channels:

| Technique | What It Prevents |
|-----------|-----------------|
| **Bucket Padding** | Size fingerprinting. All payloads are padded to fixed sizes (1KB, 4KB, 16KB, 64KB, 256KB, 1MB). An observer can't tell a 100-byte config from a 3KB document. |
| **Metadata Stripping** | Identity correlation. IP addresses, user agents, session IDs, and timestamps are stripped. Timestamps are bucketed to 10-second windows. |
| **Shuffle Buffer** | Order correlation. Categories are stored in random order. The sequence reveals nothing about the data structure. |
| **Privacy Tokens** | Request linking. Each operation uses a single-use HMAC token that proves authorization without linking requests together. |

---

## Architecture

```
Your Application
    ↓
┌─────────── Cloak ───────────┐
│  Strip metadata              │
│  Pad to bucket size          │
│  Shuffle order               │
│  Use privacy token           │
│  ┌─────── Vault ──────────┐ │
│  │  Derive KEK (PBKDF2)   │ │
│  │  Get/create DEK         │ │
│  │  AES-256-GCM encrypt    │ │
│  │  Write to disk          │ │
│  └─────────────────────────┘ │
└──────────────────────────────┘
    ↓
Encrypted, padded, shuffled files on disk
```

---

## API Reference

### `Vault(passphrase, vault_dir="./vault-encrypted")`

| Method | Description |
|--------|-------------|
| `store(category, data)` | Encrypt and store a data category |
| `load(category)` | Load and decrypt a category |
| `store_all(data_dict)` | Store multiple categories |
| `load_all()` | Load all categories |
| `verify(category, original)` | Verify stored data matches original |
| `categories()` | List stored category names |
| `stats()` | Get vault statistics |

### `Cloak(passphrase, vault_dir="./vault-encrypted")`

| Method | Description |
|--------|-------------|
| `store(data_dict)` | Store through full anonymization pipeline |
| `load_all()` | Load all categories |
| `load(category)` | Load a single category |
| `verify_all(original_dict)` | Verify all categories |
| `stats()` | Get operational statistics |

### Utilities

| Function/Class | Description |
|---------------|-------------|
| `pad_to_bucket(data)` | Pad bytes to next bucket size |
| `unpad_from_bucket(padded)` | Remove padding |
| `ShuffleBuffer` | Collect and randomize items |
| `PrivacyTokenIssuer` | Issue and verify unlinkable tokens |

---

## Running Tests

```bash
cd tests
python test_integration.py
```

---

## Security Notes

- **Passphrase strength matters.** Aegis uses PBKDF2 with 600K iterations, but a weak passphrase is still a weak passphrase.
- **Privacy tokens are simplified.** Production multi-user deployments should use blind-signed RSA tokens per RFC 9576-9578 (Privacy Pass protocol). The HMAC implementation here is suitable for single-user or trusted environments.
- **This is not a replacement for TLS.** Aegis protects data at rest and against server-side access. Use TLS for data in transit.
- **Audit the code.** That's why it's open source.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by **[AI Pantheon](https://ai-pantheon.ai)** as part of the **You Own You** initiative.
