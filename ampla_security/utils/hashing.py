import hashlib


def sha1(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha1(value).hexdigest()


def sha256(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def fingerprint(value: str | bytes, algorithm: str = "sha256") -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.new(algorithm, value).hexdigest()
