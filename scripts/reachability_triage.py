"""Mechanical reachability triage for the batch 1 rows whose notes describe a failed load.

Reports only transport facts: DNS, TCP, TLS, HTTP status, and the final landing host.
It deliberately never reads page text, titles, or screenshots, so it cannot express an
opinion about whether a site is trustworthy.
"""

from __future__ import annotations

import json
import ssl
from datetime import datetime, timezone
from pathlib import Path

import httpx

from trustlens.research import annotations
from trustlens.security import check_request_url_sync, registrable_domain, url_parts

SHEET = Path("data/annotations/main/batch_01/annotator_a.csv")
OUT = Path("data/annotations/main/batch_01/reachability_triage.json")

NON_INSPECTION_TOKENS = (
    "unable",
    "not found",
    "cant be reached",
    "cannot",
    "not secure",
    "access denied",
    "403",
    "reloads",
    "takes time",
    "nothing to see",
    "not respond",
    "load",
)


def is_non_inspection(note: str) -> bool:
    lowered = note.lower()
    return any(token in lowered for token in NON_INSPECTION_TOKENS)


def probe_sync(url: str) -> dict[str, object]:
    record: dict[str, object] = {"requested": url, "outcome": "", "detail": ""}
    try:
        safe_url, _ = check_request_url_sync(url)
    except Exception as exc:  # noqa: BLE001 - report any guard rejection verbatim
        record["outcome"] = "rejected_by_guard"
        record["detail"] = f"{type(exc).__name__}: {exc}"
        return record
    host = url_parts(safe_url).host or ""
    record["host"] = host
    try:
        ip = _resolve(host)
    except Exception as exc:  # noqa: BLE001
        record["outcome"] = "dns_failure"
        record["detail"] = f"{type(exc).__name__}: {exc}"
        return record
    record["resolved_ip"] = ip
    for scheme in ("https", "http"):
        target = f"{scheme}://{host}/"
        try:
            with httpx.Client(
                timeout=httpx.Timeout(12.0, connect=8.0),
                follow_redirects=True,
                max_redirects=6,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                verify=(scheme == "https"),
            ) as client:
                response = client.get(target)
            record["outcome"] = "reachable"
            record.update(
                {
                    "scheme": scheme,
                    "status": response.status_code,
                    "final_url": str(response.url),
                    "final_host": url_parts(str(response.url)).host or "",
                    "final_domain": registrable_domain(
                        url_parts(str(response.url)).host or ""
                    ),
                    "content_type": response.headers.get("content-type", ""),
                    "bytes": len(response.content),
                    "redirects": len(response.history),
                }
            )
            return record
        except httpx.HTTPError as exc:
            record["last_error"] = f"{type(exc).__name__}: {exc}"
        except ssl.SSLError as exc:
            record["last_error"] = f"TLS: {exc}"
    record["outcome"] = "no_http_response"
    record["detail"] = str(record.pop("last_error", ""))
    return record


def _resolve(host: str) -> str:
    import socket

    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return infos[0][4][0] if infos else ""


def main() -> None:
    rows = annotations.read_csv_rows(SHEET)
    targets = [
        row
        for row in rows
        if is_non_inspection(str(row.get("notes", "")))
    ]
    results = []
    for row in targets:
        url = str(row.get("url") or f"https://{row['domain']}/")
        result = probe_sync(url)
        result.update(
            {
                "sample_id": row.get("sample_id", ""),
                "domain": row.get("domain", ""),
                "current_label": row.get("label", ""),
                "annotator_note": row.get("notes", ""),
            }
        )
        results.append(result)
        print(
            f"{row['domain']:28} {result['outcome']:16} "
            f"{result.get('status', '')} "
            f"{result.get('final_domain', '')} "
            f"{result.get('detail', '') or result.get('last_error', '')}"
        )
    OUT.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "scope": "transport facts only; no page content was read or judged",
                "probed": len(results),
                "reachable": sum(1 for r in results if r["outcome"] == "reachable"),
                "results": results,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
