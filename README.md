# LangGraph DFIR Console (Ollama + Volatility 3)

A console-first DFIR assistant that uses:
- `LangGraph` for agentic planning (`plan -> execute -> replan -> finalize`)
- `Ollama` for local LLM reasoning
- `Volatility 3` plugins for memory forensics actions

The assistant decides which forensic tool to run, executes it, collects observations, and returns an answer.

## Features

- Agentic multi-step execution (not one-shot routing)
- Volatility tool integration with JSON output
- Process-name and PID-based workflows
- Live debug tracing of planner/tool execution
- Configurable tool timeout and step limits
- Console workflow (no API server required)

## Project Structure

- `app/console.py`: interactive CLI entrypoint
- `app/graph.py`: planning/execution/finalization graph
- `app/tools.py`: all Volatility tool definitions and execution logic
- `vol3-tools/`: standalone helper scripts for direct plugin runs

## Prerequisites

- Conda
- Ollama running locally
- Volatility CLI available (directly or via conda env)
- Python 3.10+

Example model pull:

```bash
ollama pull qwen2.5:32b
```

## Setup

```bash
conda create -n langgraph-basic python=3.11 -y
conda activate langgraph-basic
pip install -r requirements.txt
cp .env.example .env
```

## Run

Normal mode:

```bash
python -m app.console
```

Live debug mode:

```bash
python -m app.console --debug
```

Debug + full post-run history dump:

```bash
python -m app.console --debug --debug-history
```

Custom max planner steps:

```bash
python -m app.console --max-steps 8
```

## How The System Works

For each user query:

1. `plan` node asks the LLM to output one JSON action.
2. `execute` node validates tool args against per-tool schemas, then runs exactly one tool.
3. Graph loops to `plan` with updated observations.
4. Planner returns `final`, then `finalize` node formats final answer.

### Planner Output Contract

Planner must emit JSON with this shape:

```json
{
  "action": "windows.pslist|windows.info|windows.netscan|windows.netstat_by_pid|windows.handles_by_pid|windows.dlllist_by_pid|windows.cmdline|windows.cmdline_by_pid|windows.registry.printkey|final",
  "args": {},
  "reason": "short reason",
  "answer": "only when action=final"
}
```

## Tool Catalog

Defined in `app/tools.py`.

1. `windows.pslist`
- Lists running processes from the memory snapshot.

2. `windows.info`
- Collects Windows/kernel/build metadata.

3. `windows.netscan`
- Lists network sockets and connections.

4. `windows.netstat_by_pid`
- Runs `windows.netstat` and filters by PID.
- Accepts `pid` or `process_name`.

5. `windows.handles_by_pid`
- Runs `windows.handles --pid <PID>`.
- Enumerates process handles (files, keys, threads, tokens, etc.).

6. `windows.dlllist_by_pid`
- Runs `windows.dlllist --pid <PID>`.
- Lists modules loaded in a process.
- Useful for DLL injection and suspicious module analysis.

7. `windows.cmdline`
- Runs `windows.cmdline`.
- Retrieves command-line arguments for processes.

8. `windows.cmdline_by_pid`
- Runs `windows.cmdline` and filters by PID.
- Supports command-line lookup for a specific process.

9. `windows.registry.printkey`
- Runs `windows.registry.printkey`.
- Extracts registry key/value information from memory.


## Environment Variables

Set in `.env`.

- `OLLAMA_BASE_URL` (default: `http://localhost:11434`)
- `OLLAMA_MODEL` (default in code: `qwen2.5:32b`)
- `OLLAMA_TEMPERATURE` (default: `0`)
- `VOL_DEFAULT_SNAPSHOT` (default: `vol3-tools/citadeldc01.mem`)
- `VOL_CONDA_ENV` (default: `custom-agent-4`)
- `VOL_TOOL_TIMEOUT_SECONDS` (default: `180`)

## Debug Output (Live)

With `--debug`, you will see events while execution is happening:

- pipeline start
- node completion (`plan`, `execute`, `finalize`)
- tool selected + args
- tool execution completed
- status transitions (`planned`, `executing`, `completed`, `failed`, `finalized`)

## Example Queries

- `Find all processes in the memory image.`
- `Show Windows build and kernel information.`
- `List suspicious network connections.`
- `Show netstat for PID 1368.`
- `Show netstat for process dns.exe.`
- `Show handles for PID 3472.`
- `Show loaded DLLs for PID 3472.`
- `Show command line for PID 3472.`
- `Show registry printkey details.`

## Standalone Volatility Helper Scripts

These are useful for direct execution without the planner.

1. Process list

```bash
python vol3-tools/run_pslist.py
```

2. Windows info

```bash
python vol3-tools/run_widows_info.py
```

3. Netstat by PID

```bash
python vol3-tools/run_netstat_by_pid.py 1368
```

4. Handles by PID

```bash
python vol3-tools/run_handles_by_pid.py 1368
```

5. DLL list by PID

```bash
python vol3-tools/run_dlllist_by_pid.py 3472
```

All helpers support optional snapshot path and `--conda-env` overrides.

## Notes

- Some plugins are heavier (`netscan`, `dlllist`, `handles`) and may take longer.
- If output is large, history/debug view may truncate observation text for readability.
- Finalization uses full tool output (not truncated debug text) for deterministic formatting paths.

## Troubleshooting

1. Model not found

```bash
ollama pull qwen2.5:32b
```

2. `vol` not found
- Ensure `VOL_CONDA_ENV` points to env where `vol` is installed.

3. Long-running plugin
- Increase timeout:

```bash
VOL_TOOL_TIMEOUT_SECONDS=300 python -m app.console --debug
```

4. Verbose diagnostics

```bash
python -m app.console --debug --debug-history --max-steps 8
```

## Volatility 3 helper (windows.cmdline)

Script path: `vol3-tools/run_cmdline.py`

Runs:

```bash
vol -f <memory-snapshot> -r json windows.cmdline
```

Usage:

```bash
python vol3-tools/run_cmdline.py
```

## Volatility 3 helper (windows.cmdline by PID)

Script path: `vol3-tools/run_cmdline_by_pid.py`

Runs and filters:

```bash
vol -f <memory-snapshot> -r json windows.cmdline
```

Usage:

```bash
python vol3-tools/run_cmdline_by_pid.py 3472
```

In chat, ask for cmdline info, for example:

- `Show command lines for all processes`
- `Show command line for PID 3472`

## Volatility 3 helper (windows.registry.printkey)

Script path: `vol3-tools/run_registry_printkey.py`

Runs:

```bash
vol -f <memory-snapshot> -r json windows.registry.printkey
```

Usage:

```bash
python vol3-tools/run_registry_printkey.py
```

In chat, ask for registry printkey info, for example:

- `Show registry printkey details`
