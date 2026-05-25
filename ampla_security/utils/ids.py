import uuid


def generate_uuid() -> str:
    return str(uuid.uuid4())


def normalize_id(value: str | int | None) -> str:
    if value is None:
        return ""
    return str(value).strip()


def safe_id(prefix: str, value: str | int | None) -> str:
    clean = normalize_id(value)
    return f"{prefix}-{clean}" if clean else prefix
