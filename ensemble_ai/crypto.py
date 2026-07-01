"""Encryption at rest for sensitive vulnerability data (code diffs, root causes, etc.).

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` library.
In production, set ENSEMBLE_ENCRYPTION_KEY env var to a base64-encoded 32-byte key.
Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

The key is lazily initialized on first encrypt/decrypt call if init_key() wasn't called
explicitly at startup. This ensures consistent behavior regardless of import order.
"""
import os
import logging

logger = logging.getLogger(__name__)
_fernet = None
_key_initialized = False

def init_key():
    """Load the encryption key from env. Call once at startup for best results.
    If not called, the key is auto-initialized on first use (ephemeral in dev)."""
    global _fernet, _key_initialized
    from cryptography.fernet import Fernet
    key = os.environ.get("ENSEMBLE_ENCRYPTION_KEY")
    if not key:
        logger.warning("ENSEMBLE_ENCRYPTION_KEY not set — using ephemeral dev key. NOT FOR PRODUCTION.")
        key = Fernet.generate_key()
    _fernet = Fernet(key)
    _key_initialized = True


def _ensure_key():
    """Lazy key init — called on first encrypt/decrypt if init_key() wasn't called."""
    global _key_initialized
    if not _key_initialized:
        init_key()


def encrypt(plaintext: str) -> str:
    """Encrypt a string. Returns base64 ciphertext. Falls back to plaintext if not initialized."""
    if not plaintext:
        return plaintext
    _ensure_key()
    if _fernet is None:
        return plaintext
    try:
        return _fernet.encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return plaintext


def decrypt(ciphertext: str) -> str:
    """Decrypt a string. Returns plaintext if not encrypted (legacy data) or not initialized.
    vuln:3 fix — if decryption fails (key mismatch), return a clear placeholder
    instead of leaking the ciphertext to the dashboard."""
    if not ciphertext:
        return ciphertext
    _ensure_key()
    if _fernet is None:
        return ciphertext
    # Fernet tokens always start with 'gAAAAA' — skip decryption for plaintext defaults
    if not ciphertext.startswith('gAAAAA'):
        return ciphertext
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        # Key mismatch or corrupt ciphertext — don't leak the raw ciphertext
        return "[ENCRYPTED — key mismatch]"
