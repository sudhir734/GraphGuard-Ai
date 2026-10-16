"""Validation for the administrator-configured Streamlit API destination."""

from urllib.parse import urlsplit


def validate_api_base_url(value):
    value = value.strip().rstrip("/")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("GRAPHGUARD_API_URL is malformed.") from exc

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(
            "GRAPHGUARD_API_URL must be an administrator-configured "
            "HTTP(S) base URL without credentials, query, or fragment."
        )
    return value
