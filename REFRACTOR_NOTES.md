# Refactor Notes

## Current System Snapshot

- Entry point: `app/console.py`
- Graph orchestration: `app/graph.py`
- Tool execution + arg validation: `app/tools.py`
- Standalone Volatility helpers: `vol3-tools/*.py`

Architecture is agentic:
- `plan -> execute -> replan -> finalize`
- Planner returns one JSON action per step
- Executor validates args before tool call
- Finalizer formats concrete outputs for some high-value tools (process list, handles files, registry)

## Implemented Planner Actions

- `windows.pslist`
- `windows.info`
- `windows.netscan`
- `windows.netstat_by_pid`
- `windows.handles_by_pid`
- `windows.dlllist_by_pid`
- `windows.cmdline`
- `windows.cmdline_by_pid`
- `windows.registry.printkey`
- `final`

## Argument Validation Layer

- Location: `app/tools.py` (`TOOL_ARG_SCHEMAS`, `validate_and_normalize_tool_args`)
- Validation currently checks:
  - required / optional keys
  - unknown keys
  - `required_one_of`
  - PID type (must be int/numeric string)
  - snapshot arg normalization (`snapshot` / `image` -> `memory_snapshot_location`)

## Debug Behavior

- `python -m app.console --debug`
  - streams live events (not just post-run dump)
  - prints node completion, tool selected, tool completed, status transitions
- Optional full dump:
  - `--debug-history`

## Timeouts / Reliability

- Per-tool timeout via `VOL_TOOL_TIMEOUT_SECONDS` (default 180)
- Tool execution errors are captured in observation/history and replanned

## Known Gaps / Next Refactor Targets

1. Deduplicate `vol3-tools/*.py` scripts
- Many scripts repeat command resolution, JSON parsing, filtering patterns.
- Create shared utility module for helper scripts.

2. Consolidate finalization formatters
- `app/graph.py` has formatting logic for process list / handles files / registry.
- Consider moving formatting helpers to a dedicated module.

3. Normalize naming consistency
- Script `run_widows_info.py` has typo in filename (`widows` vs `windows`).
- Keep backward compatibility if renaming.

4. Improve planner schema strictness
- Add richer schema constraints (e.g. min/max length, PID bounds).
- Optionally force planner correction prompt on repeated validation failures.

5. Add tests
- Unit tests for `validate_and_normalize_tool_args`
- Unit tests for process-name -> PID resolution
- Smoke tests for tool execution dispatch with mocked `run_vol_plugin`

## Safe Commands

- Compile check:
  - `python -m compileall app vol3-tools`
- Debug run:
  - `python -m app.console --debug`

## Last Confirmed Working Behaviors

- Registry query now returns concrete entries (not generic summary).
- Process-name passed as `pid` for cmdline path is now rejected by validator and replanned.
- DLL list path works with `--pid` in this environment.
- Fake `registry.printkey_by_pid` action was removed (plugin has no true PID mode).
