"""
Aegis — Basic Usage Example

Demonstrates encrypting and anonymizing a personal data store.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis import Cloak, Vault


def main():
    # Your passphrase — the only key to your data
    passphrase = "my-secret-passphrase-change-this"

    # ── Example 1: Using the Vault directly (encryption only) ──
    print("=" * 50)
    print("  Example 1: Vault (Encryption)")
    print("=" * 50)

    vault = Vault(passphrase, vault_dir="./example-vault")

    # Store some data
    contacts = {
        "friends": [
            {"name": "Alice", "note": "Met at the conference"},
            {"name": "Bob", "note": "College roommate"},
        ]
    }

    result = vault.store("contacts", contacts)
    print(f"Stored: {result['plaintext_bytes']} bytes -> {result['encrypted_bytes']} bytes encrypted")

    # Load it back
    loaded = vault.load("contacts")
    print(f"Loaded: {loaded}")

    # Verify integrity
    match = vault.verify("contacts", contacts)
    print(f"Integrity check: {'PASS' if match else 'FAIL'}")

    # ── Example 2: Using the Cloak (encryption + anonymization) ──
    print()
    print("=" * 50)
    print("  Example 2: Cloak (Full Anonymization)")
    print("=" * 50)

    cloak = Cloak(passphrase, vault_dir="./example-cloak")

    # A data store with multiple categories
    my_data = {
        "journal": {
            "entries": [
                {"date": "2026-02-10", "text": "Had a breakthrough idea today."},
                {"date": "2026-02-11", "text": "Built the prototype. It works."},
            ]
        },
        "bookmarks": {
            "links": [
                {"url": "https://example.com", "tag": "reference"},
                {"url": "https://docs.python.org", "tag": "python"},
            ]
        },
        "settings": {
            "theme": "dark",
            "language": "en",
        },
    }

    # Store through the full pipeline
    report = cloak.store(my_data)

    print(f"Shuffle order: {report['shuffle_order']}")
    print(f"(Original order was: {list(my_data.keys())})")
    print(f"Privacy tokens used: {report['tokens_used']}")
    print(f"Plaintext: {report['total_plaintext_bytes']} bytes")
    print(f"Padded:    {report['total_padded_bytes']} bytes")
    print(f"Encrypted: {report['total_encrypted_bytes']} bytes")

    for cat in report["categories"]:
        print(f"  {cat['category']}: {cat['plaintext_bytes']}B -> padded {cat['padded_size']}B -> encrypted {cat['encrypted_bytes']}B")
        print(f"    Metadata stripped: {cat['metadata_stripped']}")

    # Load everything back
    loaded_data = cloak.load_all()
    print(f"\nLoaded {len(loaded_data)} categories: {list(loaded_data.keys())}")

    # Verify integrity
    results = cloak.verify_all(my_data)
    for category, status in results.items():
        print(f"  [{status}] {category}")

    # Stats
    print(f"\nStats: {cloak.stats()}")

    # ── Cleanup example files ──
    import shutil
    shutil.rmtree("./example-vault", ignore_errors=True)
    shutil.rmtree("./example-cloak", ignore_errors=True)
    print("\nCleaned up example files.")


if __name__ == "__main__":
    main()
