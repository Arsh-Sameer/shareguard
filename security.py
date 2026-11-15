"""Integrity and confidentiality helpers: HMAC share tags, SHA-256, Fernet."""
import hashlib, hmac, secrets
from cryptography.fernet import Fernet


class IntegrityError(Exception):
    pass


def make_party_keys(parties):
    """One random 256-bit HMAC key per party (shared with the computing nodes)."""
    return {p: secrets.token_bytes(32) for p in parties}


def share_tag(key: bytes, party: str, stat: str, node: int, share: int) -> str:
    msg = f"{party}|{stat}|{node}|{share}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_tag(key, party, stat, node, share, tag) -> bool:
    return hmac.compare_digest(share_tag(key, party, stat, node, share), tag)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_bytes(data: bytes):
    key = Fernet.generate_key()
    return Fernet(key).encrypt(data), key


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)
