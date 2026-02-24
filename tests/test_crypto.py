"""Comprehensive unit tests for the crypto module."""

import base64

import nacl.exceptions
import nacl.public
import pytest

from any_llm_platform_client.crypto import (
    KeyComponents,
    decrypt_data,
    encrypt_data,
    extract_public_key,
    format_any_llm_key,
    generate_keypair,
    get_public_key_from_private,
    load_private_key,
    parse_any_llm_key,
)


class TestParseAnyLLMKey:
    """Tests for parse_any_llm_key function."""

    def test_parse_valid_key(self, valid_any_llm_key):
        """Test parsing a valid ANY_LLM_KEY."""
        components = parse_any_llm_key(valid_any_llm_key)

        assert isinstance(components, KeyComponents)
        assert components.key_id == "12345678"
        assert components.public_key_fingerprint == "abcdef01"
        assert (
            components.base64_encoded_private_key
            == "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA=="  # pragma: allowlist secret
        )

    def test_parse_invalid_format(self):
        """Test that invalid format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid ANY_LLM_KEY format"):
            parse_any_llm_key("invalid-key-format")

    def test_parse_missing_version(self):
        """Test that missing version prefix raises ValueError."""
        with pytest.raises(ValueError, match="Invalid ANY_LLM_KEY format"):
            parse_any_llm_key("WRONG.v1.12345678.abcdef01-YWJj")

    def test_parse_wrong_version(self):
        """Test that wrong version raises ValueError."""
        with pytest.raises(ValueError, match="Invalid ANY_LLM_KEY format"):
            parse_any_llm_key("ANY.v2.12345678.abcdef01-YWJj")

    def test_parse_missing_components(self):
        """Test that missing components raise ValueError."""
        with pytest.raises(ValueError, match="Invalid ANY_LLM_KEY format"):
            parse_any_llm_key("ANY.v1.12345678")

    def test_parse_empty_string(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid ANY_LLM_KEY format"):
            parse_any_llm_key("")

    def test_parse_only_prefix(self):
        """Test that only prefix raises ValueError."""
        with pytest.raises(ValueError, match="Invalid ANY_LLM_KEY format"):
            parse_any_llm_key("ANY.v1.")


class TestLoadPrivateKey:
    """Tests for load_private_key function."""

    def test_load_valid_key(self):
        """Test loading a valid 32-byte private key."""
        # Generate a valid 32-byte key
        valid_key = base64.b64encode(b"a" * 32).decode("utf-8")
        private_key = load_private_key(valid_key)

        assert isinstance(private_key, nacl.public.PrivateKey)
        assert len(bytes(private_key)) == 32

    def test_load_key_wrong_length_short(self):
        """Test that key shorter than 32 bytes raises ValueError."""
        short_key = base64.b64encode(b"short").decode("utf-8")

        with pytest.raises(ValueError, match="X25519 private key must be 32 bytes"):
            load_private_key(short_key)

    def test_load_key_wrong_length_long(self):
        """Test that key longer than 32 bytes raises ValueError."""
        long_key = base64.b64encode(b"a" * 64).decode("utf-8")

        with pytest.raises(ValueError, match="X25519 private key must be 32 bytes"):
            load_private_key(long_key)

    def test_load_key_invalid_base64(self):
        """Test that invalid base64 raises error."""
        # binascii.Error is a subclass of ValueError
        with pytest.raises(ValueError):
            load_private_key("not-valid-base64!!!")

    def test_load_key_empty_string(self):
        """Test that empty string raises ValueError."""
        empty_key = base64.b64encode(b"").decode("utf-8")

        with pytest.raises(ValueError, match="X25519 private key must be 32 bytes"):
            load_private_key(empty_key)


class TestExtractPublicKey:
    """Tests for extract_public_key function."""

    def test_extract_public_key(self):
        """Test extracting public key from private key."""
        private_key = nacl.public.PrivateKey.generate()
        public_key_b64 = extract_public_key(private_key)

        # Verify it's valid base64
        public_key_bytes = base64.b64decode(public_key_b64)
        assert len(public_key_bytes) == 32

        # Verify it matches the private key's public key
        assert public_key_bytes == bytes(private_key.public_key)

    def test_extract_public_key_deterministic(self):
        """Test that extracting public key is deterministic."""
        private_key = nacl.public.PrivateKey.generate()
        public_key_1 = extract_public_key(private_key)
        public_key_2 = extract_public_key(private_key)

        assert public_key_1 == public_key_2


class TestEncryptDecryptData:
    """Tests for encrypt_data and decrypt_data functions."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption and decryption work together."""
        private_key = nacl.public.PrivateKey.generate()
        public_key = private_key.public_key
        plaintext = "secret message"

        # Encrypt
        encrypted = encrypt_data(plaintext, public_key)

        # Verify encrypted data is base64
        encrypted_bytes = base64.b64decode(encrypted)
        assert len(encrypted_bytes) > 32  # At least ephemeral key + some ciphertext

        # Decrypt
        decrypted = decrypt_data(encrypted, private_key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode(self):
        """Test encryption/decryption with unicode characters."""
        private_key = nacl.public.PrivateKey.generate()
        public_key = private_key.public_key
        plaintext = "Hello 世界 🌍"

        encrypted = encrypt_data(plaintext, public_key)
        decrypted = decrypt_data(encrypted, private_key)

        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_string(self):
        """Test encryption/decryption with empty string."""
        private_key = nacl.public.PrivateKey.generate()
        public_key = private_key.public_key
        plaintext = ""

        encrypted = encrypt_data(plaintext, public_key)
        decrypted = decrypt_data(encrypted, private_key)

        assert decrypted == plaintext

    def test_encrypt_decrypt_long_text(self):
        """Test encryption/decryption with long text."""
        private_key = nacl.public.PrivateKey.generate()
        public_key = private_key.public_key
        plaintext = "a" * 10000

        encrypted = encrypt_data(plaintext, public_key)
        decrypted = decrypt_data(encrypted, private_key)

        assert decrypted == plaintext

    def test_decrypt_with_wrong_key(self):
        """Test that decryption with wrong key fails."""
        private_key1 = nacl.public.PrivateKey.generate()
        private_key2 = nacl.public.PrivateKey.generate()
        public_key1 = private_key1.public_key
        plaintext = "secret message"

        encrypted = encrypt_data(plaintext, public_key1)

        # Attempting to decrypt with wrong key should raise nacl's CryptoError
        with pytest.raises(nacl.exceptions.CryptoError):
            decrypt_data(encrypted, private_key2)

    def test_decrypt_invalid_data_too_short(self):
        """Test that decryption with invalid short data raises ValueError."""
        private_key = nacl.public.PrivateKey.generate()
        # Create encrypted data that's too short (< 32 bytes)
        invalid_encrypted = base64.b64encode(b"short").decode("utf-8")

        with pytest.raises(ValueError, match="Invalid sealed box format: too short"):
            decrypt_data(invalid_encrypted, private_key)

    def test_decrypt_invalid_base64(self):
        """Test that decryption with invalid base64 raises error."""
        private_key = nacl.public.PrivateKey.generate()

        # binascii.Error is a subclass of ValueError
        with pytest.raises(ValueError):
            decrypt_data("not-valid-base64!!!", private_key)

    def test_encrypt_produces_different_ciphertexts(self):
        """Test that encrypting same plaintext produces different ciphertexts due to random ephemeral key."""
        private_key = nacl.public.PrivateKey.generate()
        public_key = private_key.public_key
        plaintext = "secret message"

        encrypted1 = encrypt_data(plaintext, public_key)
        encrypted2 = encrypt_data(plaintext, public_key)

        # Different ephemeral keys should produce different ciphertexts
        assert encrypted1 != encrypted2

        # But both should decrypt to the same plaintext
        assert decrypt_data(encrypted1, private_key) == plaintext
        assert decrypt_data(encrypted2, private_key) == plaintext


class TestGenerateKeypair:
    """Tests for generate_keypair function."""

    def test_generate_keypair(self):
        """Test generating a new keypair."""
        private_key, public_key = generate_keypair()

        assert isinstance(private_key, nacl.public.PrivateKey)
        assert isinstance(public_key, nacl.public.PublicKey)
        assert len(bytes(private_key)) == 32
        assert len(bytes(public_key)) == 32

    def test_generate_keypair_unique(self):
        """Test that generated keypairs are unique."""
        private_key1, public_key1 = generate_keypair()
        private_key2, public_key2 = generate_keypair()

        assert bytes(private_key1) != bytes(private_key2)
        assert bytes(public_key1) != bytes(public_key2)

    def test_generate_keypair_public_matches_private(self):
        """Test that generated public key matches private key."""
        private_key, public_key = generate_keypair()

        assert bytes(public_key) == bytes(private_key.public_key)


class TestFormatAnyLLMKey:
    """Tests for format_any_llm_key function."""

    def test_format_any_llm_key(self):
        """Test formatting a private key as ANY_LLM_KEY string."""
        private_key = nacl.public.PrivateKey.generate()
        any_llm_key = format_any_llm_key(private_key)

        # Verify format matches pattern
        assert any_llm_key.startswith("ANY.v1.")
        parts = any_llm_key.split(".")
        assert len(parts) == 4  # ANY, v1, key_id, fingerprint-key

        # Verify key_id is 8 hex chars
        key_id = parts[2]
        assert len(key_id) == 8
        assert all(c in "0123456789abcdef" for c in key_id)

        # Verify fingerprint-key part
        fingerprint_and_key = parts[3]
        assert "-" in fingerprint_and_key
        fingerprint, encoded_key = fingerprint_and_key.split("-", 1)

        # Verify fingerprint is 8 hex chars
        assert len(fingerprint) == 8
        assert all(c in "0123456789abcdef" for c in fingerprint)

        # Verify key is valid base64
        decoded_key = base64.b64decode(encoded_key)
        assert len(decoded_key) == 32

    def test_format_any_llm_key_roundtrip(self):
        """Test that formatted key can be parsed back."""
        private_key = nacl.public.PrivateKey.generate()
        any_llm_key = format_any_llm_key(private_key)

        # Parse it back
        components = parse_any_llm_key(any_llm_key)

        # Load the private key
        loaded_key = load_private_key(components.base64_encoded_private_key)

        # Verify it's the same key
        assert bytes(loaded_key) == bytes(private_key)

    def test_format_any_llm_key_unique_key_ids(self):
        """Test that different keys get unique key IDs."""
        private_key1 = nacl.public.PrivateKey.generate()
        private_key2 = nacl.public.PrivateKey.generate()

        key1 = format_any_llm_key(private_key1)
        key2 = format_any_llm_key(private_key2)

        # Extract key IDs
        key_id1 = key1.split(".")[2]
        key_id2 = key2.split(".")[2]

        # Key IDs should be different (with very high probability)
        assert key_id1 != key_id2

    def test_format_any_llm_key_deterministic_fingerprint(self):
        """Test that fingerprint is deterministic for the same key."""
        private_key = nacl.public.PrivateKey.generate()

        key1 = format_any_llm_key(private_key)
        key2 = format_any_llm_key(private_key)

        # Extract fingerprints
        fingerprint1 = key1.split(".")[3].split("-")[0]
        fingerprint2 = key2.split(".")[3].split("-")[0]

        # Fingerprints should be the same for the same key
        assert fingerprint1 == fingerprint2


class TestGetPublicKeyFromPrivate:
    """Tests for get_public_key_from_private function."""

    def test_get_public_key_from_private(self):
        """Test getting public key from private key."""
        private_key = nacl.public.PrivateKey.generate()
        public_key = get_public_key_from_private(private_key)

        assert isinstance(public_key, nacl.public.PublicKey)
        assert bytes(public_key) == bytes(private_key.public_key)

    def test_get_public_key_deterministic(self):
        """Test that getting public key is deterministic."""
        private_key = nacl.public.PrivateKey.generate()
        public_key1 = get_public_key_from_private(private_key)
        public_key2 = get_public_key_from_private(private_key)

        assert bytes(public_key1) == bytes(public_key2)
