import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.json_parsing import extract_first_json_value

ALLOWED_ACTIONS: set[str] = {
    "windows.pslist",
    "windows.info",
    "windows.netscan",
    "windows.netstat_by_pid",
    "windows.handles_by_pid",
    "windows.dlllist_by_pid",
    "windows.cmdline",
    "windows.cmdline_by_pid",
    "windows.registry.printkey",
    "windows.registry.printkey_by_key",
    "windows.vadyarascan_all",
    "windows.memmap_dump_by_pid",
    "final",
}

TOOL_DESCRIPTIONS: dict[str, str] = {
    "windows.pslist": "List running processes from memory snapshot.",
    "windows.info": "Get Windows/kernel/build information from memory snapshot.",
    "windows.netscan": "List network sockets and connections from memory snapshot.",
    "windows.netstat_by_pid": (
        "Get network entries filtered by PID from windows.netstat. "
        "Args can include pid or process_name."
    ),
    "windows.handles_by_pid": (
        "Retrieves all open kernel object handles for a specified Windows process from memory. "
        "Enumerates files, registry keys, processes, threads, sections, mutexes, tokens, named pipes, "
        "and other objects the target PID is interacting with. "
        "Uses windows.handles --pid <PID>. Args: pid (required)."
    ),
    "windows.dlllist_by_pid": (
        "Lists all Dynamic Link Libraries (DLLs) loaded into the address space of a specified "
        "process (PID) from a Windows memory image. Useful for detecting DLL injection, suspicious "
        "or unsigned modules, malicious libraries loaded from unusual paths, and identifying process "
        "memory tampering during forensic analysis. Uses windows.dlllist --pid <PID>. "
        "Args: pid (required)."
    ),
    "windows.cmdline": (
        "Extracts the full command-line arguments used to launch processes from a Windows memory image. "
        "Useful for identifying malicious execution patterns, encoded PowerShell commands, LOLBins abuse, "
        "and suspicious process invocation during forensic analysis."
    ),
    "windows.cmdline_by_pid": (
        "Retrieve command-line arguments filtered for a specific PID using windows.cmdline. "
        "Args: pid (required)."
    ),
    "windows.registry.printkey": (
        "Extract registry key/value information from memory using windows.registry.printkey."
    ),
    "windows.registry.printkey_by_key": (
        "Extract registry key/value information for a specific key path using "
        "windows.registry.printkey --key <KEY_PATH>. Args: key (required)."
    ),
    "windows.vadyarascan_all": (
        "Run windows.vadyarascan across all YARA rule files (.yar/.yara) in the configured rules "
        "directory. Uses one plugin run per rule file with --yara-file."
    ),
    "windows.memmap_dump_by_pid": (
        "Dump process memory map using windows.memmap --dump --pid <PID> with a fixed output "
        "directory. Reuses existing <PID>.dmp when already present."
    ),
}

TOOL_ARG_SCHEMAS: dict[str, dict[str, Any]] = {
    "windows.pslist": {"required": [], "optional": ["memory_snapshot_location"]},
    "windows.info": {"required": [], "optional": ["memory_snapshot_location"]},
    "windows.netscan": {"required": [], "optional": ["memory_snapshot_location"]},
    "windows.cmdline": {"required": [], "optional": ["memory_snapshot_location"]},
    "windows.netstat_by_pid": {
        "required_one_of": [["pid", "process_name"]],
        "optional": ["memory_snapshot_location", "pid", "process_name"],
    },
    "windows.handles_by_pid": {
        "required": ["pid"],
        "optional": ["memory_snapshot_location", "pid"],
    },
    "windows.dlllist_by_pid": {
        "required": ["pid"],
        "optional": ["memory_snapshot_location", "pid"],
    },
    "windows.cmdline_by_pid": {
        "required_one_of": [["pid", "process_name"]],
        "optional": ["memory_snapshot_location", "pid", "process_name"],
    },
    "windows.registry.printkey": {
        "required": [],
        "optional": ["memory_snapshot_location"],
    },
    "windows.registry.printkey_by_key": {
        "required": ["key"],
        "optional": ["memory_snapshot_location", "key"],
    },
    "windows.vadyarascan_all": {
        "required": [],
        "optional": ["memory_snapshot_location", "yara_rules_dir"],
    },
    "windows.memmap_dump_by_pid": {
        "required": ["pid"],
        "optional": ["memory_snapshot_location", "pid"],
    },
}


def default_snapshot() -> str:
    return str((Path(__file__).resolve().parent.parent / "vol3-tools" / "windows_snapshot4.vmem").resolve())


def extract_snapshot_path(text: str) -> str | None:
    match = re.search(r"(/[^\s]+\.vmem)\b", text)
    return match.group(1) if match else None


def resolve_vol_command(conda_env: str | None) -> list[str]:
    vol_path = shutil.which("vol")
    if vol_path:
        return [vol_path]

    if conda_env:
        conda_path = shutil.which("conda")
        if conda_path:
            return [conda_path, "run", "-n", conda_env, "vol"]

    raise RuntimeError(
        "`vol` command not found in PATH. "
        "Install Volatility or set VOL_CONDA_ENV to an env where `vol` exists."
    )


def run_vol_plugin(plugin: str, memory_snapshot_location: str, extra_args: list[str] | None = None) -> Any:
    snapshot_path = Path(memory_snapshot_location).expanduser().resolve()
    if not snapshot_path.exists() or not snapshot_path.is_file():
        raise FileNotFoundError(f"Memory snapshot not found: {snapshot_path}")

    conda_env = os.getenv("VOL_CONDA_ENV", "custom-agent-4")
    cmd = resolve_vol_command(conda_env) + [
        "-f",
        str(snapshot_path),
        "-r",
        "json",
        plugin,
    ]
    if extra_args:
        cmd.extend(extra_args)

    timeout_seconds = int(os.getenv("VOL_TOOL_TIMEOUT_SECONDS", "180"))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Volatility command timed out after {timeout_seconds}s for plugin '{plugin}'."
        ) from exc
    if result.returncode != 0:
        stderr = result.stderr.strip() or "No stderr output."
        raise RuntimeError(f"Volatility command failed ({result.returncode}): {stderr}")

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError("Volatility returned empty output.")

    parsed = extract_first_json_value(stdout)
    if parsed is None:
        raise RuntimeError("Volatility did not return valid JSON.")
    return parsed


def extract_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("records", "rows", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def filter_records_by_pid(records: list[dict[str, Any]], pid: str) -> list[dict[str, Any]]:
    wanted = str(pid)
    output: list[dict[str, Any]] = []
    for row in records:
        for key in ("PID", "Pid", "pid", "ProcessId"):
            value = row.get(key)
            if value is not None and str(value) == wanted:
                output.append(row)
                break
    return output


def find_pids_by_process_name(snapshot: str, process_name: str) -> list[str]:
    payload = run_vol_plugin("windows.pslist", snapshot)
    records = extract_records(payload)
    needle = process_name.strip().lower()
    needle = needle.rsplit("\\", 1)[-1]
    if needle.endswith(".exe"):
        needle = needle[:-4]
    pids: list[str] = []

    for row in records:
        names = [
            str(row.get("ImageFileName", "")),
            str(row.get("Name", "")),
            str(row.get("Process", "")),
        ]
        normalized_names: list[str] = []
        for raw_name in names:
            n = raw_name.strip().lower().rsplit("\\", 1)[-1]
            if n.endswith(".exe"):
                n = n[:-4]
            normalized_names.append(n)

        if any(
            needle
            and (
                needle in n
                or n in needle
                or n.startswith(needle)
                or needle.startswith(n)
            )
            for n in normalized_names
        ):
            for key in ("PID", "Pid", "pid", "ProcessId"):
                pid_value = row.get(key)
                if pid_value is not None:
                    pid_text = str(pid_value)
                    if pid_text not in pids:
                        pids.append(pid_text)
                    break
    return pids


def run_netstat_by_pid(snapshot: str, pid: str) -> list[dict[str, Any]]:
    payload = run_vol_plugin("windows.netstat", snapshot)
    records = extract_records(payload)
    return filter_records_by_pid(records, pid)


def run_handles_by_pid(snapshot: str, pid: str) -> Any:
    return run_vol_plugin("windows.handles", snapshot, extra_args=["--pid", str(pid)])


def run_dlllist_by_pid(snapshot: str, pid: str) -> Any:
    return run_vol_plugin("windows.dlllist", snapshot, extra_args=["--pid", str(pid)])


def run_cmdline(snapshot: str) -> Any:
    return run_vol_plugin("windows.cmdline", snapshot)


def run_cmdline_by_pid(snapshot: str, pid: str) -> Any:
    payload = run_cmdline(snapshot)
    records = extract_records(payload)
    filtered = filter_records_by_pid(records, str(pid))
    return {"pid": str(pid), "records": filtered}


def run_registry_printkey(snapshot: str) -> Any:
    return run_vol_plugin("windows.registry.printkey", snapshot)


def run_registry_printkey_by_key(snapshot: str, key: str) -> Any:
    return run_vol_plugin("windows.registry.printkey", snapshot, extra_args=["--key", key])


def memmap_dump_dir() -> Path:
    return (Path(__file__).resolve().parent.parent / "vol3-tools" / "memmap-dumps").resolve()


def _run_vol_raw(
    plugin: str,
    memory_snapshot_location: str,
    *,
    out_dir: Path | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    snapshot_path = Path(memory_snapshot_location).expanduser().resolve()
    if not snapshot_path.exists() or not snapshot_path.is_file():
        raise FileNotFoundError(f"Memory snapshot not found: {snapshot_path}")

    conda_env = os.getenv("VOL_CONDA_ENV", "custom-agent-4")
    cmd = resolve_vol_command(conda_env) + ["-f", str(snapshot_path)]
    if out_dir is not None:
        cmd.extend(["-o", str(out_dir)])
    cmd.append(plugin)
    if extra_args:
        cmd.extend(extra_args)

    timeout_seconds = int(os.getenv("VOL_TOOL_TIMEOUT_SECONDS", "180"))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Volatility command timed out after {timeout_seconds}s for plugin '{plugin}'."
        ) from exc
    if result.returncode != 0:
        stderr = result.stderr.strip() or "No stderr output."
        raise RuntimeError(f"Volatility command failed ({result.returncode}): {stderr}")
    return result


def run_memmap_dump_by_pid(snapshot: str, pid: str) -> Any:
    dump_dir = memmap_dump_dir()
    dump_dir.mkdir(parents=True, exist_ok=True)

    pid_text = str(pid)
    target_dump = dump_dir / f"{pid_text}.dmp"
    if target_dump.exists() and target_dump.is_file():
        return {
            "pid": pid_text,
            "dump_dir": str(dump_dir),
            "dump_file": str(target_dump),
            "cached": True,
        }

    before_files = {p.resolve() for p in dump_dir.glob("*.dmp") if p.is_file()}
    result = _run_vol_raw(
        "windows.memmap",
        snapshot,
        out_dir=dump_dir,
        extra_args=["--dump", "--pid", pid_text],
    )

    after_files = [p.resolve() for p in dump_dir.glob("*.dmp") if p.is_file()]
    new_files = [p for p in after_files if p not in before_files]

    candidate: Path | None = None
    pid_named_candidates = [
        p for p in after_files if pid_text in p.name and p.suffix.lower() == ".dmp"
    ]
    if pid_named_candidates:
        pid_named_candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        candidate = pid_named_candidates[0]
    elif new_files:
        new_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        candidate = new_files[0]

    if candidate is None:
        raise RuntimeError(
            "windows.memmap completed but no dump file was found in output directory."
        )

    if candidate != target_dump:
        try:
            if target_dump.exists():
                target_dump.unlink()
            candidate.rename(target_dump)
        except OSError:
            # Fallback to copy+remove if atomic rename fails across filesystem boundaries.
            shutil.copy2(candidate, target_dump)
            candidate.unlink(missing_ok=True)

    return {
        "pid": pid_text,
        "dump_dir": str(dump_dir),
        "dump_file": str(target_dump),
        "cached": False,
        "stdout": (result.stdout or "").strip()[-2000:],
    }


def default_yara_rules_dir() -> str:
    root = Path(__file__).resolve().parent.parent
    candidates = [
        root / "app" / "yara-rules",
        root / "app" / "Yara-rules",
        root / "vol3-tools" / "yara-rules",
        root / "vol3-tools" / "Yara-rules",
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return str(candidate.resolve())

    for base in (root / "app", root / "vol3-tools"):
        if not base.exists() or not base.is_dir():
            continue
        for child in base.iterdir():
            if child.is_dir() and child.name.lower() == "yara-rules":
                return str(child.resolve())

    return str((root / "app" / "yara-rules").resolve())


def _list_yara_rule_files(yara_rules_dir: str) -> list[Path]:
    rules_dir = Path(yara_rules_dir).expanduser().resolve()
    if not rules_dir.exists() or not rules_dir.is_dir():
        raise FileNotFoundError(f"YARA rules directory not found: {rules_dir}")

    rule_files = sorted(
        [p for p in rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".yar", ".yara"}]
    )
    if not rule_files:
        raise RuntimeError(f"No .yar or .yara files found in directory: {rules_dir}")
    return rule_files


def run_vadyarascan_all(snapshot: str, yara_rules_dir: str | None = None) -> Any:
    rules_dir = yara_rules_dir or os.getenv("VOL_YARA_RULES_DIR") or default_yara_rules_dir()
    rule_files = _list_yara_rule_files(rules_dir)
    debug_enabled = os.getenv("APP_DEBUG", "0") == "1"

    results_by_rule: dict[str, Any] = {}
    errors_by_rule: dict[str, str] = {}

    for rule_file in rule_files:
        key = str(rule_file)
        if debug_enabled:
            print(f"[debug][tool] windows.vadyarascan --yara-file {key}", flush=True)
        try:
            results_by_rule[key] = run_vol_plugin(
                "windows.vadyarascan",
                snapshot,
                extra_args=["--yara-file", key],
            )
        except Exception as exc:
            errors_by_rule[key] = str(exc)

    return {
        "yara_rules_dir": str(Path(rules_dir).expanduser().resolve()),
        "total_rule_files": len(rule_files),
        "successful_rule_runs": len(results_by_rule),
        "failed_rule_runs": len(errors_by_rule),
        "results_by_rule": results_by_rule,
        "errors_by_rule": errors_by_rule,
    }


def _normalize_snapshot_arg(args: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(args)
    snapshot_value = (
        normalized.get("memory_snapshot_location")
        or normalized.get("snapshot")
        or normalized.get("image")
    )
    if snapshot_value:
        normalized["memory_snapshot_location"] = str(snapshot_value)
    normalized.pop("snapshot", None)
    normalized.pop("image", None)
    return normalized


def _is_valid_pid(value: Any) -> bool:
    return isinstance(value, int) or (isinstance(value, str) and value.isdigit())


def validate_and_normalize_tool_args(action: str, args: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    schema = TOOL_ARG_SCHEMAS.get(action)
    if schema is None:
        return {}, f"No argument schema found for action '{action}'."

    normalized = _normalize_snapshot_arg(args)
    allowed_keys = set(schema.get("required", [])) | set(schema.get("optional", []))
    unknown_keys = [k for k in normalized.keys() if k not in allowed_keys]
    if unknown_keys:
        return {}, f"Unknown argument(s) for {action}: {', '.join(unknown_keys)}"

    for required_key in schema.get("required", []):
        if required_key not in normalized:
            return {}, f"Missing required argument '{required_key}' for {action}"

    for one_of_group in schema.get("required_one_of", []):
        if not any(k in normalized for k in one_of_group):
            return {}, f"One of {one_of_group} is required for {action}"

    if "pid" in normalized:
        if not _is_valid_pid(normalized["pid"]):
            return {}, f"Argument 'pid' must be an integer for {action}"
        normalized["pid"] = str(normalized["pid"])

    if "process_name" in normalized:
        if not isinstance(normalized["process_name"], str) or not normalized["process_name"].strip():
            return {}, f"Argument 'process_name' must be a non-empty string for {action}"
        normalized["process_name"] = normalized["process_name"].strip()

    if "key" in normalized:
        if not isinstance(normalized["key"], str) or not normalized["key"].strip():
            return {}, f"Argument 'key' must be a non-empty string for {action}"
        normalized["key"] = normalized["key"].strip()

    if "yara_rules_dir" in normalized:
        if not isinstance(normalized["yara_rules_dir"], str) or not normalized["yara_rules_dir"].strip():
            return {}, f"Argument 'yara_rules_dir' must be a non-empty string for {action}"
        normalized["yara_rules_dir"] = normalized["yara_rules_dir"].strip()

    return normalized, None


def execute_tool_action(action: str, args: dict[str, Any], snapshot: str) -> Any:
    if action == "windows.pslist":
        return run_vol_plugin("windows.pslist", snapshot)
    if action == "windows.info":
        return run_vol_plugin("windows.info", snapshot)
    if action == "windows.netscan":
        return run_vol_plugin("windows.netscan", snapshot)
    if action == "windows.netstat_by_pid":
        pid = args.get("pid")
        process_name = args.get("process_name")
        if pid is not None:
            return {
                "pid": str(pid),
                "records": run_netstat_by_pid(snapshot, str(pid)),
            }
        if process_name:
            pids = find_pids_by_process_name(snapshot, str(process_name))
            results: dict[str, Any] = {}
            for found_pid in pids:
                results[found_pid] = run_netstat_by_pid(snapshot, found_pid)
            return {
                "process_name": str(process_name),
                "matched_pids": pids,
                "results_by_pid": results,
            }
        return {"error": "windows.netstat_by_pid requires pid or process_name"}
    if action == "windows.handles_by_pid":
        pid = args.get("pid")
        if pid is None:
            return {"error": "windows.handles_by_pid requires pid"}
        return {"pid": str(pid), "records": run_handles_by_pid(snapshot, str(pid))}
    if action == "windows.dlllist_by_pid":
        pid = args.get("pid")
        if pid is None:
            return {"error": "windows.dlllist_by_pid requires pid"}
        return {"pid": str(pid), "records": run_dlllist_by_pid(snapshot, str(pid))}
    if action == "windows.cmdline":
        return run_cmdline(snapshot)
    if action == "windows.registry.printkey":
        return run_registry_printkey(snapshot)
    if action == "windows.registry.printkey_by_key":
        key = args.get("key")
        if key is None:
            return {"error": "windows.registry.printkey_by_key requires key"}
        return {"key": str(key), "records": run_registry_printkey_by_key(snapshot, str(key))}
    if action == "windows.vadyarascan_all":
        yara_rules_dir = args.get("yara_rules_dir")
        return run_vadyarascan_all(snapshot, str(yara_rules_dir) if yara_rules_dir else None)
    if action == "windows.memmap_dump_by_pid":
        pid = args.get("pid")
        if pid is None:
            return {"error": "windows.memmap_dump_by_pid requires pid"}
        return run_memmap_dump_by_pid(snapshot, str(pid))
    if action == "windows.cmdline_by_pid":
        pid = args.get("pid")
        process_name = args.get("process_name")

        if pid is not None and str(pid).isdigit():
            return run_cmdline_by_pid(snapshot, str(pid))

        if process_name:
            pids = find_pids_by_process_name(snapshot, str(process_name))
            results: dict[str, Any] = {}
            for found_pid in pids:
                results[found_pid] = run_cmdline_by_pid(snapshot, found_pid)
            return {
                "process_name": str(process_name),
                "matched_pids": pids,
                "results_by_pid": results,
            }

        return {"error": "windows.cmdline_by_pid requires pid or process_name"}
    return {"error": f"Unsupported action: {action}"}
