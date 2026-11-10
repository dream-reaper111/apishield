from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import SpecError, analyze_file


def main() -> None:
    parser = argparse.ArgumentParser(prog="apishield")
    parser.add_argument("specification", type=Path, help="authorized OpenAPI 3.0/3.1 JSON or YAML")
    args = parser.parse_args()
    try:
        report = analyze_file(args.specification)
    except (SpecError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
