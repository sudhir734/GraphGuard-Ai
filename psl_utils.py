
from pathlib import Path

PSL_FILE = Path(__file__).with_name("public_suffix_list.dat")


def normalize_name(name: str) -> str:
    name = name.strip().rstrip(".").lower()
    if not name or any(ch in name for ch in "/:@\\"):
        raise ValueError("Expected a domain name, not a URL or path.")

    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain name.") from exc

    labels = name.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(c.isalnum() or c == "-" for c in label)
        for label in labels
    ):
        raise ValueError("Invalid domain label.")

    return name


def load_rules(path=PSL_FILE):
    normal = set()
    wildcard = set()
    exceptions = set()
    section = "unknown"

    with Path(path).open(encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()

            if not line or line.startswith("//"):
                if "BEGIN ICANN DOMAINS" in line:
                    section = "icann"
                elif "BEGIN PRIVATE DOMAINS" in line:
                    section = "private"
                continue

            if line.startswith("!"):
                exceptions.add(line[1:].lower())
            elif line.startswith("*."):
                wildcard.add(line[2:].lower())
            else:
                normal.add(line.lower())

    if not normal:
        raise RuntimeError("No PSL rules loaded. Check the PSL file.")

    return normal, wildcard, exceptions


NORMAL, WILDCARD, EXCEPTIONS = load_rules()


def public_suffix(name: str) -> str:
    name = normalize_name(name)
    labels = name.split(".")
    exception_length = 0
    best_length = 1  # PSL's implicit default rule: *

    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        length = len(labels) - i

        if candidate in EXCEPTIONS:
            exception_length = max(exception_length, length)

        if candidate in NORMAL:
            best_length = max(best_length, length)

        # A wildcard *.suffix matches one additional label.
        if i > 0 and candidate in WILDCARD:
            best_length = max(best_length, length + 1)

    if exception_length:
        best_length = exception_length - 1

    return ".".join(labels[-best_length:])


def registrable_domain(name: str):
    name = normalize_name(name)
    suffix = public_suffix(name)
    labels = name.split(".")
    suffix_labels = suffix.split(".")

    if len(labels) <= len(suffix_labels):
        return None

    return ".".join(labels[-(len(suffix_labels) + 1):])


def is_public_suffix(name: str) -> bool:
    return normalize_name(name) == public_suffix(name)


if __name__ == "__main__":
    print(f"PSL normal rules: {len(NORMAL):,}")
    print(f"PSL wildcard rules: {len(WILDCARD):,}")
    print(f"PSL exception rules: {len(EXCEPTIONS):,}")

    for example in (
        "example.com",
        "co.uk",
        "example.co.uk",
        "myproject.github.io",
    ):
        try:
            print(
                f"{example:28} "
                f"suffix={public_suffix(example):20} "
                f"registrable={registrable_domain(example)}"
            )
        except ValueError as exc:
            print(f"{example}: {exc}")
