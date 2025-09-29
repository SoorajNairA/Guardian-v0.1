import hashlib
import secrets
import re
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


_ph = PasswordHasher()


def hash_api_key(plain_key: str) -> str:
    """Hash API key with Argon2 for production security."""
    return _ph.hash(plain_key)


def verify_api_key(plain_key: str, hashed_key: str) -> bool:
    """Verify API key against Argon2 hash."""
    # Validate input parameters
    if not plain_key or not hashed_key:
        return False
    
    if not isinstance(plain_key, str) or not isinstance(hashed_key, str):
        return False
    
    try:
        _ph.verify(hashed_key, plain_key)
        return True
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def legacy_hash_api_key(plain_key: str) -> str:
    """Legacy SHA-256 for migration compatibility."""
    return hashlib.sha256(plain_key.encode("utf-8")).hexdigest()


def validate_api_key_format(api_key: str) -> bool:
    """Validate API key format with security constraints."""
    if not api_key or not isinstance(api_key, str):
        return False
    
    # Length constraints: 8-128 characters
    if len(api_key) < 8 or len(api_key) > 128:
        return False
    
    # Check for null bytes or control characters
    if '\x00' in api_key or any(ord(c) < 32 and c not in '\t\n\r' for c in api_key):
        return False
    
    # Ensure proper UTF-8 encoding
    try:
        api_key.encode('utf-8')
    except UnicodeEncodeError:
        return False
    
    # Allow alphanumeric characters plus specific special characters
    # Pattern: alphanumeric, hyphens, underscores, dots
    allowed_pattern = re.compile(r'^[a-zA-Z0-9\-_.]+$')
    if not allowed_pattern.match(api_key):
        return False
    
    return True


def secure_compare_keys(key1: str, key2: str) -> bool:
    """Secure constant-time comparison to prevent timing attacks."""
    if not isinstance(key1, str) or not isinstance(key2, str):
        return False
    
    # Ensure both keys are properly encoded
    try:
        key1_bytes = key1.encode('utf-8')
        key2_bytes = key2.encode('utf-8')
    except UnicodeEncodeError:
        return False
    
    return secrets.compare_digest(key1_bytes, key2_bytes)


