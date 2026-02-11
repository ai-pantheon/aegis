"""
Aegis — Integration Tests
Tests the full encrypt/pad/shuffle/verify pipeline.
"""

import json
import shutil
import sys
from pathlib import Path

# Add parent to path for local development
sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis import Vault, Cloak, pad_to_bucket, unpad_from_bucket, BUCKET_SIZES
from aegis import ShuffleBuffer, PrivacyTokenIssuer

TEST_PASSPHRASE = "test-passphrase-do-not-use-in-production"
TEST_VAULT_DIR = Path(__file__).parent / "test-vault"
TEST_CLOAK_DIR = Path(__file__).parent / "test-cloak"


def setup():
    """Clean up test directories."""
    for d in [TEST_VAULT_DIR, TEST_CLOAK_DIR]:
        if d.exists():
            shutil.rmtree(d)


def test_padding():
    """Test bucket padding round-trip."""
    print("Testing padding...", end=" ")
    for size in [10, 100, 1000, 5000, 20000, 100000]:
        data = b"x" * size
        padded = pad_to_bucket(data)
        # Padded size should be one of the bucket sizes
        assert len(padded) in BUCKET_SIZES, f"Padded to {len(padded)}, not a bucket size"
        # Round-trip
        recovered = unpad_from_bucket(padded)
        assert recovered == data, f"Round-trip failed for size {size}"
    print("PASS")


def test_shuffle():
    """Test shuffle buffer randomization."""
    print("Testing shuffle...", end=" ")
    buf = ShuffleBuffer()
    items = list(range(100))
    for i in items:
        buf.add(i)
    assert buf.size == 100
    result = buf.flush()
    assert buf.size == 0
    assert sorted(result) == items  # Same items
    assert result != items  # Different order (statistically certain with 100 items)
    print("PASS")


def test_tokens():
    """Test privacy token issue and verify."""
    print("Testing tokens...", end=" ")
    issuer = PrivacyTokenIssuer()
    tokens = issuer.issue_batch(10)
    assert len(tokens) == 10
    for t in tokens:
        assert issuer.verify(t), "Valid token failed verification"

    # Invalid token should fail
    assert not issuer.verify("not-a-valid-token")
    assert issuer.issued_count == 10
    print("PASS")


def test_vault():
    """Test vault encrypt/decrypt round-trip."""
    print("Testing vault...", end=" ")
    vault = Vault(TEST_PASSPHRASE, vault_dir=TEST_VAULT_DIR)

    data = {"records": [{"id": 1, "value": "hello"}, {"id": 2, "value": "world"}]}

    # Store
    result = vault.store("test-category", data)
    assert result["plaintext_bytes"] > 0
    assert result["encrypted_bytes"] > 0

    # Load
    loaded = vault.load("test-category")
    assert loaded == data

    # Verify
    assert vault.verify("test-category", data)

    # Stats
    stats = vault.stats()
    assert stats["total_files"] == 1
    assert "test-category" in stats["categories"]

    print("PASS")


def test_vault_multiple():
    """Test vault with multiple categories."""
    print("Testing vault (multi-category)...", end=" ")
    vault = Vault(TEST_PASSPHRASE, vault_dir=TEST_VAULT_DIR)

    data = {
        "alpha": {"items": [1, 2, 3]},
        "beta": {"items": [4, 5, 6]},
        "gamma": {"items": [7, 8, 9]},
    }

    vault.store_all(data)
    loaded = vault.load_all()

    for cat in data:
        assert cat in loaded, f"Category {cat} missing"
        assert loaded[cat] == data[cat], f"Category {cat} data mismatch"

    print("PASS")


def test_cloak():
    """Test full cloak pipeline."""
    print("Testing cloak (full pipeline)...", end=" ")
    cloak = Cloak(TEST_PASSPHRASE, vault_dir=TEST_CLOAK_DIR)

    data = {
        "notes": {"entries": [{"text": "Private note 1"}, {"text": "Private note 2"}]},
        "config": {"theme": "dark", "lang": "en"},
        "contacts": {"people": [{"name": "Alice"}, {"name": "Bob"}]},
    }

    # Store
    report = cloak.store(data)
    assert report["tokens_used"] == 3
    assert len(report["shuffle_order"]) == 3
    assert report["total_plaintext_bytes"] > 0
    assert report["total_padded_bytes"] >= report["total_plaintext_bytes"]
    assert report["total_encrypted_bytes"] > 0

    # Metadata was stripped
    for cat_report in report["categories"]:
        assert "ip_address" in cat_report["metadata_stripped"]
        assert "user_agent" in cat_report["metadata_stripped"]
        assert "session_id" in cat_report["metadata_stripped"]

    # Load all
    loaded = cloak.load_all()
    assert len(loaded) == 3
    for cat in data:
        assert cat in loaded

    # Load individual
    notes = cloak.load("notes")
    assert notes == data["notes"]

    # Verify
    results = cloak.verify_all(data)
    for cat, status in results.items():
        assert status == "PASS", f"Verification failed for {cat}"

    # Stats
    stats = cloak.stats()
    assert stats["requests_processed"] > 0
    assert stats["categories_stored"] == 3

    print("PASS")


def test_wrong_passphrase():
    """Test that wrong passphrase fails to decrypt."""
    print("Testing wrong passphrase...", end=" ")
    vault1 = Vault("correct-passphrase", vault_dir=TEST_VAULT_DIR / "wrong-pass-test")
    vault1.store("secret", {"data": "sensitive"})

    # Try to load with different passphrase
    try:
        vault2 = Vault("wrong-passphrase", vault_dir=TEST_VAULT_DIR / "wrong-pass-test")
        vault2.load("secret")
        print("FAIL (should have raised an exception)")
        return
    except Exception:
        pass  # Expected — decryption should fail
    print("PASS")


def main():
    setup()
    print("=" * 50)
    print("  Aegis Integration Tests")
    print("=" * 50)
    print()

    tests = [
        test_padding,
        test_shuffle,
        test_tokens,
        test_vault,
        test_vault_multiple,
        test_cloak,
        test_wrong_passphrase,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL: {e}")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed")

    # Cleanup
    setup()

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
