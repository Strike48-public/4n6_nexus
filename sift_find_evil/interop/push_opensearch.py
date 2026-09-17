"""Opt-in OpenSearch bulk-push driver for exported findings (SFE-b0om).

This is the ONLY outbound-network component of the interop surface, and it is
deliberately isolated from everything else:

  * It is NOT imported by ``sift_find_evil.interop.__init__`` or by the CLI's
    ``analyze`` path -- so nothing on the read-only evidence path can ever reach
    a network write.
  * It reads an ALREADY-EXPORTED file (the ``.ocsf.json`` / ``.stix.json`` an
    ``analyze --export`` run produced) and bulk-indexes it. It never touches
    evidence, never runs a detector, never writes to disk.
  * ``requests`` is import-guarded so the core engine installs without it.

Usage::

    python -m sift_find_evil.interop.push_opensearch analysis/findings.ocsf.json \\
        --url https://opensearch:9200 --index dfir-findings

Credentials come from the environment (``OPENSEARCH_USER`` / ``OPENSEARCH_PASS``)
or are omitted; they are never read from a file or hardcoded.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _load_docs(path: Path) -> list[dict]:
    """Load exported docs: a STIX bundle's ``objects``, or an OCSF event list."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and data.get("type") == "bundle":
        return list(data.get("objects", []))
    if isinstance(data, list):
        return data
    raise ValueError(
        f"{path}: expected a STIX bundle or an OCSF event list, got {type(data).__name__}"
    )


def _bulk_ndjson(docs: list[dict], index: str) -> str:
    """Build an OpenSearch ``_bulk`` NDJSON body for ``docs``."""
    lines: list[str] = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc, default=str))
    return "\n".join(lines) + "\n"


def _auth() -> "tuple[str, str] | None":
    user = os.environ.get("OPENSEARCH_USER")
    password = os.environ.get("OPENSEARCH_PASS")
    if user and password:
        return (user, password)
    return None


def push(path: Path, url: str, index: str, *, verify_tls: bool = True) -> dict:
    """Bulk-index the docs in ``path`` into ``index`` at ``url``.

    Returns the parsed OpenSearch ``_bulk`` response. Raises on transport error
    or a non-2xx status.
    """
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise SystemExit(
            "requests is required for OpenSearch push: pip install requests"
        ) from exc

    docs = _load_docs(path)
    body = _bulk_ndjson(docs, index)
    response = requests.post(
        f"{url.rstrip('/')}/_bulk",
        data=body,
        headers={"Content-Type": "application/x-ndjson"},
        auth=_auth(),
        verify=verify_tls,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def apply_template(url: str, template_name: str, template_path: Path) -> dict:
    """PUT an index template so mappings exist before the first push."""
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise SystemExit(
            "requests is required for OpenSearch push: pip install requests"
        ) from exc

    template = json.loads(template_path.read_text(encoding="utf-8"))
    response = requests.put(
        f"{url.rstrip('/')}/_index_template/{template_name}",
        json=template,
        auth=_auth(),
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def main(argv: "list[str] | None" = None) -> int:  # pragma: no cover - CLI glue
    parser = argparse.ArgumentParser(
        description="Bulk-push exported 4n6-nexus findings to OpenSearch (write-only).",
    )
    parser.add_argument("file", type=Path, help="Exported .ocsf.json or .stix.json")
    parser.add_argument("--url", required=True, help="OpenSearch base URL")
    parser.add_argument("--index", default="dfir-findings", help="Target index")
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Disable TLS verification (lab use only)",
    )
    parser.add_argument(
        "--apply-template",
        type=Path,
        metavar="TEMPLATE_JSON",
        help="PUT this index template before pushing",
    )
    args = parser.parse_args(argv)

    if args.apply_template:
        apply_template(args.url, "dfir-findings", args.apply_template)

    result = push(args.file, args.url, args.index, verify_tls=not args.no_verify_tls)
    errors = result.get("errors")
    print(
        f"Indexed {len(result.get('items', []))} docs into {args.index} (errors={errors})"
    )
    return 1 if errors else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
