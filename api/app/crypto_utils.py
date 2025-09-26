import hashlib


def hash_api_key(plain_key: str) -> str:
    # Use SHA-256; in production prefer a slow KDF plus salt. This is a stopgap.
    return hashlib.sha256(plain_key.encode("utf-8")).hexdigest()



