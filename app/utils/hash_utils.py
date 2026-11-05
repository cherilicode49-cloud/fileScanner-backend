import hashlib
from pathlib import Path
from typing import Union


def calculate_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Calculate SHA256 hash of a file efficiently using chunking."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_sha256_bytes(data: bytes) -> str:
    """Calculate SHA256 hash of a byte string."""
    return hashlib.sha256(data).hexdigest()


def calculate_md5(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Calculate MD5 hash of a file."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
    return md5.hexdigest()

