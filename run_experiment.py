import argparse
import json
import re
import selectors
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


QUERIES = [
   "For the experiment registry key, return the value named 'Marker' (key path + value).",
   "Find an experiment-created HKCU Software key consistent with the script (key path).",
   "For that notepad PID, report handle count (count only).",
   "For that notepad PID, list loaded DLL module names (names only).",
   "Dump cmd.exe and then show its loaded DLL module names (names only)."
]

SNAPSHOT_PATH = "/home/student/projects/lanchain-project/lang-graph-basic/vol3-tools/WindowsSnapshot4.vmem"


def _slugify(text: str, max_len: int = 80) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    if not slug:
        slug = "query"
    return slug[:max_len].rstrip("-")


def _build_output_dir(base_dir: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = base_dir / "experiment_outputs" / stamp
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _run_single_query(
    query: str,
    *,
    cwd: Path,
    timeout_seconds: int,
    max_steps: int,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        "-m",
        "app.console",
        "--debug",
        "--max-steps",
        str(max_steps),
    ]
    query_with_snapshot = f"Memory snapshot: {SNAPSHOT_PATH}. {query}"
    stdin_text = f"{query_with_snapshot}\nquit\n"

    print(f"Launching subprocess: {' '.join(cmd)}")
    print("Subprocess stdin:")
    print(query_with_snapshot)
    print("quit")
    print("Streaming subprocess output:")

    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(cwd),
        bufsize=1,
    )

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    process.stdin.write(stdin_text)
    process.stdin.close()

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    deadline = time.monotonic() + timeout_seconds

    try:
        while selector.get_map():
            remaining = max(0.0, deadline - time.monotonic())
            if remaining == 0.0:
                raise subprocess.TimeoutExpired(
                    cmd=cmd,
                    timeout=timeout_seconds,
                    output="".join(stdout_chunks),
                    stderr="".join(stderr_chunks),
                )

            events = selector.select(timeout=min(0.2, remaining))
            if not events:
                if process.poll() is not None:
                    break
                continue

            for key, _ in events:
                stream = key.fileobj
                line = stream.readline()
                if line == "":
                    selector.unregister(stream)
                    continue
                if stream is process.stdout:
                    stdout_chunks.append(line)
                    print(line, end="")
                else:
                    stderr_chunks.append(line)
                    print(line, end="", file=sys.stderr)

        process.wait(timeout=max(0.1, deadline - time.monotonic()))

        for stream in (process.stdout, process.stderr):
            remainder = stream.read()
            if not remainder:
                continue
            if stream is process.stdout:
                stdout_chunks.append(remainder)
                print(remainder, end="")
            else:
                stderr_chunks.append(remainder)
                print(remainder, end="", file=sys.stderr)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise subprocess.TimeoutExpired(
            cmd=cmd,
            timeout=timeout_seconds,
            output="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
        ) from exc
    finally:
        selector.close()

    return subprocess.CompletedProcess(
        cmd,
        returncode=process.returncode,
        stdout="".join(stdout_chunks),
        stderr="".join(stderr_chunks),
    )


def _write_transcript(
    output_path: Path,
    *,
    query: str,
    cmd: list[str],
    result: subprocess.CompletedProcess[str],
) -> None:
    sections = [
        f"Query: {query}",
        f"Command: {' '.join(cmd)}",
        f"Return code: {result.returncode}",
        "",
        "=== STDOUT ===",
        result.stdout.rstrip(),
        "",
        "=== STDERR ===",
        result.stderr.rstrip(),
        "",
    ]
    output_path.write_text("\n".join(sections), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the console app in debug mode for a fixed query set and save transcripts.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=600,
        help="Per-query timeout for the console process.",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=6,
        help="Planner max steps passed through to app.console.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent
    output_dir = _build_output_dir(repo_root)
    cmd = [
        sys.executable,
        "-m",
        "app.console",
        "--debug",
        "--max-steps",
        str(args.max_steps),
    ]

    manifest: list[dict[str, object]] = []

    for index, query in enumerate(QUERIES, start=1):
        slug = _slugify(query)
        transcript_path = output_dir / f"{index:02d}_{slug}.txt"
        query_with_snapshot = f"Memory snapshot: {SNAPSHOT_PATH}. {query}"

        print(f"[{index}/{len(QUERIES)}] Executing query:")
        print(query)

        try:
            result = _run_single_query(
                query,
                cwd=repo_root,
                timeout_seconds=args.timeout_seconds,
                max_steps=args.max_steps,
            )
            _write_transcript(
                transcript_path,
                query=query_with_snapshot,
                cmd=cmd,
                result=result,
            )
            print(f"Saved output to: {transcript_path}")
            manifest.append(
                {
                    "index": index,
                    "query": query,
                    "query_with_snapshot": query_with_snapshot,
                    "output_file": str(transcript_path),
                    "return_code": result.returncode,
                    "timed_out": False,
                }
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            timed_out_result = subprocess.CompletedProcess(
                cmd,
                returncode=-1,
                stdout=stdout,
                stderr=stderr + f"\nTimed out after {args.timeout_seconds} seconds.",
            )
            _write_transcript(
                transcript_path,
                query=query_with_snapshot,
                cmd=cmd,
                result=timed_out_result,
            )
            print(f"Saved output to: {transcript_path}")
            manifest.append(
                {
                    "index": index,
                    "query": query,
                    "query_with_snapshot": query_with_snapshot,
                    "output_file": str(transcript_path),
                    "return_code": -1,
                    "timed_out": True,
                }
            )

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Wrote transcripts to: {output_dir}")
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
