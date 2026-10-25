import json
import sys
from pathlib import Path

BACKUP = Path(".tmp-ptest/repair_backup")


def rank(row):
    if "overall_risk" in row:
        return 2
    return 0 if "error" in row else 1


def main(paths):
    for raw in paths:
        path = Path(raw)
        best: dict[str, dict] = {}
        bad = 0
        dupes = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            url = str(row.get("url") or "").strip().lower()
            if not url:
                bad += 1
                continue
            if url in best:
                dupes += 1
                if rank(row) >= rank(best[url]):
                    best[url] = row
            else:
                best[url] = row
        BACKUP.mkdir(parents=True, exist_ok=True)
        backup = BACKUP / (path.name + ".dup")
        if not backup.exists():
            backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        with path.open("w", encoding="utf-8", newline="") as handle:
            for row in best.values():
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        scored = sum(1 for row in best.values() if "overall_risk" in row)
        print(f"{path}: kept {len(best)} unique urls ({scored} scored, "
              f"{len(best) - scored} not scored), collapsed {dupes} duplicate rows, "
              f"dropped {bad} unparseable; backup {backup}")


if __name__ == "__main__":
    main(sys.argv[1:])
