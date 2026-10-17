# LangGraph DFIR Assistant: System Description

## 1. Overall System

This project is a console-based DFIR (Digital Forensics and Incident Response) assistant that combines:

- **LangGraph** for iterative agent control flow (`plan -> execute -> replan -> finalize`)
- **Ollama-hosted LLMs** for planning and answer generation
- **Volatility 3** plugins for memory forensics actions on Windows memory snapshots

Instead of one-shot tool routing, the assistant plans one step at a time, executes one tool, observes results, and decides the next step until it has enough evidence to finalize an answer.

---

## 2. High-Level Architecture

Core modules are under `app/`:

- `console.py`: interactive CLI entrypoint and debug streaming
- `graph.py`: agent state machine and decision workflow
- `tools.py`: tool catalog, argument validation, and Volatility execution
- `relevant_field_selector.py`: LLM-based field projection for JSON records
- `tool_output_summarizer.py`: optional reason-aware output summarization

Supporting assets:

- `vol3-tools/`: memory snapshots, helper scripts, and YARA rule sets
- `README.md`: setup and usage guide

---

## 3. Component Breakdown

### 3.1 `app/console.py` (User Interaction Layer)

Responsibilities:

- Runs a REPL-style chat loop in terminal
- Builds initial graph state per user query
- Invokes LangGraph pipeline (`graph.invoke` or `graph.stream` in debug mode)
- Prints final assistant answer
- Shows detailed timeline/debug events when `--debug` is enabled

Key behavior:

- Tracks lifecycle events like planner decision, selected tool, execution completion
- Handles common runtime failures (for example, missing Ollama model)
- Exposes `--max-steps` to cap iterative planning loops

---

### 3.2 `app/graph.py` (Agent Orchestration Layer)

Responsibilities:

- Defines `AgentState` (query, history, next action, observations, completion flags, etc.)
- Implements three graph nodes:
  - `plan_node`
  - `execute_node`
  - `finalize_node`
- Compiles the LangGraph state machine and loop transitions

Node behavior summary:

1. **Plan node**
   - Builds planner prompt with tool catalog, rules, query, history, and step budget
   - Calls LLM to produce strict JSON action (`tool` or `final`)
   - Applies guardrails for certain request types (registry/YARA/memmap) to prevent premature finalization

2. **Execute node**
   - Validates tool arguments against schemas from `tools.py`
   - Executes exactly one tool action
   - Records observations in history and increments step count
   - Stores full observation JSON for deterministic final-answer generation

3. **Finalize node**
   - Attempts grounded final answer from latest observation
   - Uses specialized formatting for process-list style queries
   - Falls back to planner answer, then generic final LLM synthesis if needed

Graph transitions:

- `START -> plan`
- `plan -> execute` (if not done)
- `plan -> finalize` (if done/final)
- `execute -> plan` (loop)
- `finalize -> END`

---

### 3.3 `app/tools.py` (Forensic Tool Execution Layer)

Responsibilities:

- Defines allowed tool actions and tool descriptions
- Defines per-tool argument schemas (`required`, `optional`, `required_one_of`)
- Normalizes and validates arguments before execution
- Resolves and runs Volatility commands
- Parses Volatility JSON output and exposes action-specific wrappers

Primary tool actions:

- `windows.pslist`
- `windows.info`
- `windows.netscan`
- `windows.netstat_by_pid` (by PID or process name)
- `windows.handles_by_pid`
- `windows.dlllist_by_pid`
- `windows.cmdline`
- `windows.cmdline_by_pid`
- `windows.registry.printkey`
- `windows.registry.printkey_by_key`
- `windows.vadyarascan_all` (iterates all `.yar/.yara` files)
- `windows.memmap_dump_by_pid` (supports dump-file reuse/caching)

Execution model:

- Resolve `vol` binary directly from PATH, else via `conda run -n <env> vol`
- Enforce timeout via `VOL_TOOL_TIMEOUT_SECONDS`
- Raise clear errors for missing snapshot, command failures, invalid JSON, and timeouts

---

### 3.4 `app/relevant_field_selector.py` (Output Projection Helper)

Responsibilities:

- Analyzes a sample JSON record schema
- Prompts LLM to select only relevant top-level fields for a given reason
- Projects record arrays to only those selected fields

Purpose:

- Reduces noise in large tool outputs
- Keeps downstream reasoning focused on relevant indicators (for example PID/name/key fields)

---

### 3.5 `app/tool_output_summarizer.py` (Optional Summarization Helper)

Responsibilities:

- Summarizes tool output according to execution reason
- Splits large outputs into chunks
- Summarizes each chunk and merges summaries into one concise result

Purpose:

- Scale LLM processing for very large JSON outputs
- Preserve actionable findings while reducing verbosity

Note:

- The summarizer path is currently present and partially integrated; key invocation points are available for future tuning.

---

## 4. End-to-End Workflow

For each user query:

1. User enters request in console.
2. Initial state is created (query, defaults, counters, empty history).
3. `plan_node` asks LLM for next JSON action.
4. If action is a tool:
   - `execute_node` validates args
   - Executes one tool via Volatility wrapper
   - Stores observation and loops back to planner
5. If action is `final`:
   - `finalize_node` composes final grounded response
6. Response is printed to user.

This loop continues until:

- planner returns final, or
- max step count is reached.

---

## 5. State and Data Flow

Important state fields:

- `query`: original user prompt
- `memory_snapshot_location`: chosen snapshot path (default or extracted)
- `steps_taken` / `max_steps`: loop control budget
- `history`: cumulative step log + observations
- `next_action`, `next_args_json`, `next_reason`: planner output
- `last_action`, `last_observation_json`, `last_observation_full_json`: latest execution artifacts
- `planner_answer`, `final_answer`: final-response candidates
- `done`: whether planning loop should stop

Design intent:

- Keep full forensic outputs for accuracy
- Keep condensed history for planner continuity and debug visibility

---

## 6. Configuration and Runtime Dependencies

Main environment variables:

- `OLLAMA_BASE_URL`
- `OLLAMA_MODEL`
- `OLLAMA_TEMPERATURE`
- `VOL_DEFAULT_SNAPSHOT`
- `VOL_CONDA_ENV`
- `VOL_TOOL_TIMEOUT_SECONDS`
- `VOL_YARA_RULES_DIR` (optional override)

Dependencies:

- Python runtime
- LangGraph / LangChain-Ollama stack
- Local Ollama server with installed model
- Volatility 3 CLI and accessible memory snapshot

---

## 7. Error Handling and Guardrails

Built-in safeguards include:

- Strict action allow-list
- Argument schema validation with clear errors
- One-tool-per-step execution discipline
- Tool timeout enforcement
- Fallback finalization strategies if planner output is generic or malformed
- Request-type guardrails that force relevant tool execution before final answers (registry/YARA/memmap use-cases)

---

## 8. Extensibility

To add a new forensic capability:

1. Add action name to `ALLOWED_ACTIONS`
2. Add human-readable entry in `TOOL_DESCRIPTIONS`
3. Add argument schema in `TOOL_ARG_SCHEMAS`
4. Implement execution path in `execute_tool_action`
5. Update planner JSON contract/rules in `graph.py`
6. Optionally add specialized final formatter in `finalize_node`

This pattern keeps planning, validation, and execution aligned.

---

## 9. Practical Characteristics

Strengths:

- Iterative, evidence-driven agent flow
- Strong separation between orchestration and forensic execution
- Works locally with Ollama and Volatility (no API server required)
- Rich debug timeline for investigation transparency

Current tradeoffs:

- Large outputs can still stress context if not projected/summarized
- Some helper logic is heuristic (for example, process name matching)
- Performance depends on Volatility plugin cost and model latency

