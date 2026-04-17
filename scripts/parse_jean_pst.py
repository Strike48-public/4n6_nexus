"""Parse Jean's outlook.pst and emit a CSV of every message.

Walks the PST tree, records every message with headers, subject, sender,
recipients, timestamps, and body preview. Output goes to
`analysis/real_examples/nps-2008-jean/csv/Email.csv`.

We care specifically about messages in "Sent Items" around 2008-07-20/21,
the window bracketed by the AIM chat with alisonm57.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import pypff

PST = Path("analysis/real_examples/nps-2008-jean/extracted/email/outlook.pst")
OUT = Path("analysis/real_examples/nps-2008-jean/csv/Email.csv")


def _walk(folder, parents: tuple[str, ...]):
    try:
        name = folder.name or "<root>"
    except Exception:
        name = "<unnamed>"
    path = parents + (name,)

    for msg in folder.sub_messages:
        try:
            yield path, msg
        except Exception as exc:
            print(f"  skip message in {'/'.join(path)}: {exc}", file=sys.stderr)
            continue

    for sub in folder.sub_folders:
        yield from _walk(sub, path)


def _safe(obj, attr: str) -> str:
    try:
        v = getattr(obj, attr)
        if callable(v):
            v = v()
        if v is None:
            return ""
        return str(v).replace("\r", " ").replace("\n", " ").strip()
    except Exception:
        return ""


def main() -> int:
    if not PST.exists():
        print(f"ERROR: {PST} not found", file=sys.stderr)
        return 2

    OUT.parent.mkdir(parents=True, exist_ok=True)

    pst = pypff.file()
    pst.open(str(PST))
    try:
        root = pst.get_root_folder()
        rows: list[list[str]] = []
        for folder_path, msg in _walk(root, tuple()):
            folder = "/".join(folder_path)
            rows.append(
                [
                    folder,
                    _safe(msg, "delivery_time"),
                    _safe(msg, "client_submit_time"),
                    _safe(msg, "creation_time"),
                    _safe(msg, "modification_time"),
                    _safe(msg, "sender_name"),
                    _safe(msg, "sender_email_address"),
                    _safe(msg, "subject"),
                    _safe(msg, "transport_headers")[:2000],
                    (_safe(msg, "plain_text_body") or _safe(msg, "html_body"))[:1000],
                ]
            )

        with OUT.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "Folder",
                    "DeliveryTime",
                    "SubmitTime",
                    "CreationTime",
                    "ModificationTime",
                    "SenderName",
                    "SenderEmail",
                    "Subject",
                    "TransportHeaders",
                    "BodyPreview",
                ]
            )
            w.writerows(rows)

        print(f"Wrote {OUT} ({len(rows)} messages)")
    finally:
        pst.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
