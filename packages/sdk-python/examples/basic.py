"""Minimal Zombie Killer broadcaster example; performs no network activity."""

from pathlib import Path
from tempfile import TemporaryDirectory

from zombie_killer import Agent


def main() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        result = root / "synthetic-result.txt"
        result.write_text("synthetic", encoding="utf-8")
        with Agent(provider="custom", project="Example", role="Worker") as agent:
            agent.status("Writing a local synthetic result")
            agent.track_temp(result, root=root)
            agent.record_usage(requests=0, input_tokens=0, output_tokens=0)


if __name__ == "__main__":
    main()
