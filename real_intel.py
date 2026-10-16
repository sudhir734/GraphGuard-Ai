
"""
GraphGuard AI — Free Public Intelligence Collector
Sources:
  1. Cloudflare DNS over HTTPS
  2. RDAP via rdap.org
  3. crt.sh Certificate Transparency

This module collects observations only.
It does not classify a domain as malicious or safe.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


USER_AGENT = "GraphGuard-AI/0.1 (public research collector)"
TIMEOUT_SECONDS = 8
MAX_CERTIFICATES = 20

DNS_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "NS": 2,
    "TXT": 16,
    "CNAME": 5,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value: str) -> str:
    """Validate and normalize a public DNS name."""
    value = value.strip().lower().rstrip(".")

    if "://" in value or "/" in value or "@" in value:
        raise ValueError("Enter a domain only, without a URL or path.")

    if not value or len(value) > 253:
        raise ValueError("Invalid domain length.")

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address.")

    try:
        domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain name.") from exc

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("Enter a fully qualified domain, such as example.com.")

    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("The domain contains an invalid DNS label.")

    if labels[-1] in {"localhost", "local", "internal", "test", "invalid", "example"}:
        raise ValueError(
            "Reserved or local-use domain. Use a publicly registered domain."
        )

    return domain


def get_json(url: str, accept: str = "application/json"):
    """Fetch JSON from a fixed public intelligence endpoint."""
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": accept,
        },
    )

    with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP status {response.status}")

        body = response.read(2_000_000)
        return json.loads(body.decode("utf-8"))


def observation(source: str, kind: str, value, details=None) -> dict:
    return {
        "source": source,
        "kind": kind,
        "value": value,
        "observed_at": utc_now(),
        "details": details or {},
    }


def collect_dns(domain: str) -> dict:
    results = []
    failed_queries = 0
    completed_queries = 0
    errors = []

    for record_type, record_number in DNS_TYPES.items():
        params = urlencode({"name": domain, "type": record_type})
        url = f"https://cloudflare-dns.com/dns-query?{params}"

        try:
            data = get_json(url, "application/dns-json")
            if not isinstance(data, dict):
                raise ValueError("DNS provider returned a non-object response")
            status = data.get("Status")

            if status not in (0, 3):
                failed_queries += 1
                errors.append(f"{record_type}: resolver status {status}")
                continue
            completed_queries += 1

            answers = data.get("Answer", [])
            if not isinstance(answers, list):
                raise ValueError("DNS provider returned invalid answers")
            for answer in answers:
                if not isinstance(answer, dict):
                    continue
                value = str(answer.get("data", "")).strip()

                if not value:
                    continue

                # Validate address records rather than trusting arbitrary text.
                if record_type in {"A", "AAAA"}:
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError:
                        continue

                    if (record_type == "A") != (address.version == 4):
                        continue

                results.append(
                    observation(
                        "Cloudflare DNS",
                        f"DNS_{record_type}",
                        value,
                        {
                            "ttl": answer.get("TTL"),
                            "record_type_number": record_number,
                            "resolver_status": status,
                        },
                    )
                )

        except (HTTPError, URLError, TimeoutError, OSError,
                ValueError, RuntimeError) as exc:
            failed_queries += 1
            errors.append(f"{record_type}: {type(exc).__name__}")
            continue

    if failed_queries:
        status = "partial" if completed_queries or results else "unavailable"
    else:
        status = "success" if results else "no_records"

    return {
        "source": "Cloudflare DNS",
        "status": status,
        "observations": results,
        **({"error": "; ".join(errors[:3])} if errors else {}),
    }


def collect_rdap(domain: str) -> dict:
    url = f"https://rdap.org/domain/{quote(domain, safe='.-')}"

    try:
        data = get_json(url)
        if not isinstance(data, dict):
            raise ValueError("RDAP provider returned a non-object response")

        events = []
        for event in data.get("events", []):
            if not isinstance(event, dict):
                continue
            events.append({
                "action": event.get("eventAction"),
                "date": event.get("eventDate"),
            })

        nameservers = [
            item.get("ldhName")
            for item in data.get("nameservers", [])
            if isinstance(item, dict) and item.get("ldhName")
        ]

        return {
            "source": "RDAP",
            "status": "success",
            "observations": [
                observation(
                    "RDAP",
                    "DOMAIN_REGISTRATION",
                    domain,
                    {
                        "handle": data.get("handle"),
                        "status": data.get("status", []),
                        "events": events,
                        "nameservers": nameservers,
                        "rdap_url": url,
                    },
                )
            ],
        }

    except HTTPError as exc:
        if exc.code == 404:
            return {
                "source": "RDAP",
                "status": "no_records",
                "observations": [],
            }
        return {
            "source": "RDAP",
            "status": "unavailable",
            "observations": [],
            "error": f"HTTPError: status {exc.code}",
        }
    except (URLError, TimeoutError, OSError,
            ValueError, RuntimeError) as exc:
        return {
            "source": "RDAP",
            "status": "unavailable",
            "observations": [],
            "error": str(exc)[:200],
        }



def collect_certificates(domain: str) -> dict:
    url = (
        "https://crt.sh/?"
        + urlencode({"q": f"%.{domain}", "output": "json"})
    )
    exact_url = (
        "https://crt.sh/?"
        + urlencode({"q": domain, "output": "json"})
    )

    def is_in_scope(name: str) -> bool:
        name = name.strip().lower().rstrip(".")

        # CT records can include wildcard names.
        if name.startswith("*."):
            name = name[2:]

        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            return False

        # Require an exact domain boundary.
        return name == domain or name.endswith("." + domain)

    try:
        # Query exact domain and subdomains separately.
        records = []
        seen_cert_ids = set()
        completed_queries = 0
        errors = []

        for query_url in (exact_url, url):
            try:
                data = get_json(query_url)

                if not isinstance(data, list):
                    raise ValueError(
                        "Certificate provider returned a non-list response"
                    )
                completed_queries += 1

                for cert in data:
                    if not isinstance(cert, dict):
                        continue
                    cert_id = cert.get("id")
                    key = str(cert_id) if cert_id is not None else json.dumps(
                        cert, sort_keys=True
                    )

                    if key in seen_cert_ids:
                        continue

                    seen_cert_ids.add(key)
                    records.append(cert)

            except (
                HTTPError, URLError, TimeoutError, OSError,
                ValueError, RuntimeError
            ) as exc:
                if isinstance(exc, HTTPError) and exc.code == 404:
                    completed_queries += 1
                    continue
                errors.append(type(exc).__name__)
                continue

        results = []

        for cert in records[:MAX_CERTIFICATES]:
            raw_names = cert.get("name_value") or ""

            # One CT certificate may contain many DNS names.
            names = sorted({
                name.strip().lower().rstrip(".")
                for name in raw_names.splitlines()
                if name.strip() and is_in_scope(name)
            })

            if not names:
                continue

            results.append(
                observation(
                    "crt.sh Certificate Transparency",
                    "CERTIFICATE_RECORD",
                    names,
                    {
                        "certificate_id": cert.get("id"),
                        "issuer": cert.get("issuer_name"),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after"),
                        "logged_at": cert.get("entry_timestamp"),
                        "lookup_url": exact_url,
                        "matching_name_count": len(names),
                        "scope_filter": "exact domain or subdomain boundary",
                    },
                )
            )

        return {
            "source": "crt.sh Certificate Transparency",
            "status": (
                "partial" if errors and (completed_queries or results)
                else "unavailable" if errors
                else "success" if results
                else "no_records"
            ),
            "observations": results,
            **(
                {"error": ", ".join(errors[:2])}
                if errors else {}
            ),
        }

    except (
        HTTPError, URLError, TimeoutError, OSError,
        ValueError, RuntimeError, TypeError,
    ) as exc:
        return {
            "source": "crt.sh Certificate Transparency",
            "status": "unavailable",
            "observations": [],
            "error": str(exc)[:200],
        }

def collect_intelligence(domain_input: str) -> dict:
    domain = normalize_domain(domain_input)

    # DNS, RDAP and certificate searches are independent.
    # Failures from one source do not erase results from others.
    sources = [
        collect_dns(domain),
        collect_rdap(domain),
        collect_certificates(domain),
    ]

    observations = [
        item
        for source in sources
        for item in source.get("observations", [])
    ]

    return {
        "domain": domain,
        "collected_at": utc_now(),
        "mode": "passive_public_intelligence",
        "sources": sources,
        "observations": observations,
        "assessment": {
            "verdict": "NOT_ASSESSED",
            "reason": (
                "Public observations have been collected. "
                "They do not independently establish whether "
                "the domain is malicious or safe."
            ),
        },
    }


def main():
    if len(sys.argv) != 2:
        print(
            'Usage: python real_intel.py "public-domain.com"',
            file=sys.stderr,
        )
        raise SystemExit(2)

    try:
        result = collect_intelligence(sys.argv[1])
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        raise SystemExit(2)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
