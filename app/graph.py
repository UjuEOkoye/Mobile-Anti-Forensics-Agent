import json
import os
import re
from typing import Any, Literal, TypedDict
from app.json_parsing import extract_first_json_object
from app.relevant_field_selector import get_required_fields_from_json_object, projected_json


from dotenv import load_dotenv
from langchain_ollama import ChatOllama
from langgraph.graph import END, START, StateGraph

from app.tools import (
    ALLOWED_ACTIONS,
    TOOL_DESCRIPTIONS,
    default_snapshot,
    execute_tool_action,
    extract_records,
    extract_snapshot_path,
    validate_and_normalize_tool_args,
)
from app.tool_output_summarizer import summarize_tool_output

load_dotenv()


class AgentState(TypedDict):
    query: str
    memory_snapshot_location: str
    steps_taken: int
    max_steps: int
    history: str
    next_action: str
    next_args_json: str
    next_reason: str
    planner_answer: str
    last_action: str
    last_observation_json: str
    last_observation_full_json: str
    final_answer: str
    done: bool


def _build_llm() -> ChatOllama:
    model = os.getenv("OLLAMA_MODEL", "qwen3:32b")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0"))
    return ChatOllama(model=model, base_url=base_url, temperature=temperature)


def _to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    return str(content)


def _extract_json_object(text: str) -> dict[str, Any] | None:
    return extract_first_json_object(text)


def _planner_prompt(state: AgentState) -> str:
    tools_text = "\n".join([f"- {name}: {desc}" for name, desc in TOOL_DESCRIPTIONS.items()])
    return (
        "You are a DFIR planning agent. Decide the next best action.\n"
        "Return ONLY JSON with this schema:\n"
        "{\"action\":\"windows.pslist|windows.info|windows.netscan|windows.netstat_by_pid|windows.handles_by_pid|windows.dlllist_by_pid|windows.cmdline|windows.cmdline_by_pid|windows.registry.printkey|windows.registry.printkey_by_key|windows.vadyarascan_all|windows.memmap_dump_by_pid|final\","
        "\"args\":{...},\"reason\":\"short\",\"answer\":\"only when action=final\"}\n\n"
        f"Tool descriptions:\n{tools_text}\n\n"
        "Rules:\n"
        "- Use at most one tool per step.\n"
        "- Reuse known snapshot path unless user provided a new one.\n"
        "- If user asks netstat by process name, first get PID via windows.pslist (if needed), then run windows.netstat_by_pid.\n"
        "- If user asks for handles of a process, use windows.handles_by_pid with pid.\n"
        "- If user asks for loaded DLL/modules of a process, use windows.dlllist_by_pid with pid.\n"
        "- If user asks for command line of all processes, use windows.cmdline.\n"
        "- If user asks for command line of one process/PID, use windows.cmdline_by_pid with pid.\n"
        "- If user asks about registry keys/values, use windows.registry.printkey.\n"
        "- If a specific registry key path is requested or discovered from previous output, use windows.registry.printkey_by_key with key.\n"
        "- For registry value/entry requests, do not finalize before running windows.registry.printkey_by_key at least once.\n"
        "- If user asks to run YARA scan on VAD regions or scan with YARA rules, use windows.vadyarascan_all.\n"
        "- For YARA scan requests, do not finalize before running windows.vadyarascan_all at least once.\n"
        "- If user asks to dump process memory map by PID, use windows.memmap_dump_by_pid with pid.\n"
        "- For memmap dump requests, do not finalize before running windows.memmap_dump_by_pid at least once.\n"
        "- If enough evidence exists, return action=final with a clear answer.\n"
        "- Do not output markdown, only JSON.\n\n"
        f"User query:\n{state['query']}\n\n"
        f"Default snapshot:\n{state['memory_snapshot_location']}\n\n"
        f"Steps taken: {state['steps_taken']} / {state['max_steps']}\n\n"
        f"History (actions and observations):\n{state['history'] or '(none yet)'}\n"
    )


def _summarize_observation(action: str, observation: Any) -> str:
    if isinstance(observation, list):
        return f"{action} returned list with {len(observation)} items"
    if isinstance(observation, dict):
        return f"{action} returned object with keys: {', '.join(list(observation.keys())[:12])}"
    return f"{action} returned {type(observation).__name__}"


def _extract_projectable_records(observation: Any) -> list[dict[str, Any]]:
    return extract_records(observation)


def _is_generic_answer(text: str) -> bool:
    lowered = text.lower().strip()
    generic_markers = [
        "successfully retrieved",
        "has been retrieved",
        "cannot be answered",
        "no further information",
        "based on the provided data",
    ]
    return not lowered or any(marker in lowered for marker in generic_markers)


def _format_process_list(observation: Any) -> str | None:
    records = extract_records(observation)
    if not records:
        return None

    lines: list[str] = []
    for row in records:
        name = (
            row.get("ImageFileName")
            or row.get("Name")
            or row.get("Process")
            or row.get("File")
            or "unknown"
        )
        pid = row.get("PID") or row.get("Pid") or row.get("pid") or row.get("ProcessId") or "?"
        ppid = (
            row.get("PPID")
            or row.get("Ppid")
            or row.get("ppid")
            or row.get("ParentProcessId")
            or "?"
        )
        lines.append(f"- {name} (PID: {pid}, PPID: {ppid})")

    header = f"Found {len(lines)} processes in the snapshot:"
    return header + "\n" + "\n".join(lines)


def _query_wants_full_process_list(query: str) -> bool:
    q = query.lower()
    list_markers = [
        "all processes",
        "list processes",
        "process list",
        "find all processes",
        "show processes",
        "show running processes",
    ]
    return any(marker in q for marker in list_markers)


def _query_wants_registry_values(query: str) -> bool:
    q = query.lower()
    markers = [
        "registry value",
        "registry values",
        "registry entries",
        "show values",
        "show registry",
        "printkey values",
    ]
    return "registry" in q and any(marker in q for marker in markers)


def _query_wants_yara_scan(query: str) -> bool:
    q = query.lower()
    markers = [
        "yara",
        "vadyarascan",
        "yarascan",
        "scan rule",
        "scan rules",
        "scan with rules",
    ]
    return any(marker in q for marker in markers)


def _query_wants_memmap_dump(query: str) -> bool:
    q = query.lower()
    markers = [
        "memmap",
        "memory map",
        "dump memory",
        "memory dump",
        "vad dump",
        "dump pid",
    ]
    return any(marker in q for marker in markers)


def _history_has_action(history: str, action: str) -> bool:
    return f"action={action}" in history


def _extract_registry_key_from_history(history: str) -> str | None:
    matches = re.findall(r'"Key"\s*:\s*"([^"]+)"', history)
    for key in matches:
        candidate = str(key).strip()
        if "\\" in candidate and len(candidate) >= 5:
            return candidate
    return None


def _truncate_text(value: Any, max_len: int = 5000) -> str:
    text = str(value)
    if len(text) <= max_len:
        return text
    return text[:max_len] + "...<truncated>"


def _reduce_observation_for_llm(
    value: Any,
    *,
    depth: int = 0,
    max_depth: int = 4,
    max_list_items: int = 1200,
    max_dict_items: int = 800,
) -> Any:
    if depth >= max_depth:
        return _truncate_text(value)

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        items = list(value.items())
        for key, item in items[:max_dict_items]:
            out[str(key)] = _reduce_observation_for_llm(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_list_items=max_list_items,
                max_dict_items=max_dict_items,
            )
        if len(items) > max_dict_items:
            out["__truncated_keys__"] = len(items) - max_dict_items
        return out

    if isinstance(value, list):
        out_list = [
            _reduce_observation_for_llm(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_list_items=max_list_items,
                max_dict_items=max_dict_items,
            )
            for item in value[:max_list_items]
        ]
        if len(value) > max_list_items:
            out_list.append({"__truncated_items__": len(value) - max_list_items})
        return out_list

    if isinstance(value, (str, int, float, bool)) or value is None:
        return _truncate_text(value)

    return _truncate_text(value)


def _validate_grounded_answer_doc(doc: dict[str, Any], observation_text: str) -> tuple[str | None, str | None]:
    answer = doc.get("answer")
    if not isinstance(answer, str) or not answer.strip():
        return None, "grounded answer missing non-empty 'answer'"

    snippets = doc.get("evidence_snippets", [])
    if not isinstance(snippets, list) or not snippets:
        return None, "grounded answer missing non-empty 'evidence_snippets'"

    normalized_observation = observation_text.lower()
    snippet_hits = 0
    for snippet in snippets[:5]:
        snippet_text = str(snippet).strip()
        if not snippet_text:
            continue
        if snippet_text.lower() in normalized_observation:
            snippet_hits += 1

    if snippet_hits == 0:
        return None, "none of the provided evidence snippets were found in observation"

    return answer.strip(), None


def _llm_grounded_answer_from_observation(query: str, action: str, observation: Any) -> tuple[str | None, str | None]:
    reduced = _reduce_observation_for_llm(observation)
    observation_text = json.dumps(reduced, ensure_ascii=False)

    llm = _build_llm()
    prompt = (
        "You are a DFIR assistant. Answer the query using ONLY the provided tool observation.\n"
        "Return ONLY JSON with this schema:\n"
        "{\"answer\":\"...\",\"confidence\":\"high|medium|low\","
        "\"evidence_snippets\":[\"exact snippets copied from observation\"]}\n"
        "Rules:\n"
        "- Use only evidence present in the observation; do not invent fields.\n"
        "- Include 1 to 5 exact evidence snippets copied from the observation JSON.\n"
        "- If observation is insufficient, clearly say so in answer.\n"
        "- Do not include markdown.\n\n"
        f"User query:\n{query}\n\n"
        f"Last tool action:\n{action}\n\n"
        f"Observation JSON:\n{observation_text}\n"
    )
    first = llm.invoke(prompt)
    first_doc = _extract_json_object(_to_text(first.content))
    if first_doc:
        answer, error = _validate_grounded_answer_doc(first_doc, observation_text)
        if answer:
            return answer, None
        if error:
            repair_reason = error
        else:
            repair_reason = "invalid structure"
    else:
        repair_reason = "invalid JSON"

    repair_prompt = (
        "Your previous response did not satisfy requirements "
        f"({repair_reason}). Return only valid JSON with schema:\n"
        "{\"answer\":\"...\",\"confidence\":\"high|medium|low\","
        "\"evidence_snippets\":[\"...\"]}\n\n"
        f"User query:\n{query}\n\n"
        f"Last tool action:\n{action}\n\n"
        f"Observation JSON:\n{observation_text}\n"
    )
    second = llm.invoke(repair_prompt)
    second_doc = _extract_json_object(_to_text(second.content))
    if not second_doc:
        return None, "grounded answer JSON parse failed"
    answer, error = _validate_grounded_answer_doc(second_doc, observation_text)
    if answer:
        return answer, None
    return None, error or "grounded answer validation failed"


def _format_handles_files(observation: Any, max_items: int = 500) -> str | None:
    if not isinstance(observation, dict):
        return None
    records = observation.get("records")
    if not isinstance(records, list):
        return None

    file_names: list[str] = []
    for row in records:
        if not isinstance(row, dict):
            continue
        row_type = str(row.get("Type", "")).lower()
        if row_type != "file":
            continue
        name = row.get("Name")
        if isinstance(name, str) and name.strip():
            file_names.append(name.strip())

    if not file_names:
        return None

    unique_files = list(dict.fromkeys(file_names))
    shown = unique_files[:max_items]
    lines = [f"- {path}" for path in shown]
    suffix = ""
    if len(unique_files) > max_items:
        suffix = f"\n...and {len(unique_files) - max_items} more file handles."
    return (
        f"Found {len(unique_files)} unique file handles for the process:\n"
        + "\n".join(lines)
        + suffix
    )


def _format_registry_printkey(observation: Any, max_items: int = 200) -> str | None:
    records = extract_records(observation)
    if not records:
        return None

    lines: list[str] = []
    for row in records[:max_items]:
        key = row.get("Key", "unknown")
        name = row.get("Name", "unknown")
        rtype = row.get("Type", "unknown")
        data = row.get("Data", "")
        if isinstance(data, str) and len(data) > 120:
            data = data[:120] + "...<truncated>"
        line = f"- Key: {key} | Name: {name} | Type: {rtype}"
        if data not in ("", None):
            line += f" | Data: {data}"
        lines.append(line)

    suffix = ""
    if len(records) > max_items:
        suffix = f"\n...and {len(records) - max_items} more entries."

    return f"Found {len(records)} registry entries:\n" + "\n".join(lines) + suffix


def plan_node(state: AgentState) -> AgentState:
    if not state.get("memory_snapshot_location"):
        from_query = extract_snapshot_path(state["query"])
        state["memory_snapshot_location"] = from_query or os.getenv("VOL_DEFAULT_SNAPSHOT", default_snapshot())

    if state["steps_taken"] >= state["max_steps"]:
        state["done"] = True
        state["planner_answer"] = (
            "Reached maximum planning steps. Based on collected observations: "
            f"{state['history'][-3000:]}"
        )
        state["history"] = (
            state["history"]
            + f"\nStep {state['steps_taken'] + 1}: status=finalized reason=max_steps_reached\n"
        )
        state["next_action"] = "final"
        state["next_args_json"] = "{}"
        return state

    llm = _build_llm()
    planner_reply = llm.invoke(_planner_prompt(state))
    planner_text = _to_text(planner_reply.content)
    action_doc = _extract_json_object(planner_text)

    if not action_doc:
        state["done"] = True
        state["planner_answer"] = (
            "Planner output was invalid JSON. Please restate your request with clear tool intent "
            "(processes, system info, network, or netstat by pid/process)."
        )
        state["history"] = (
            state["history"]
            + f"\nStep {state['steps_taken'] + 1}: status=failed stage=plan reason=invalid_json\n"
        )
        state["next_action"] = "final"
        state["next_args_json"] = "{}"
        return state

    action = str(action_doc.get("action", "")).strip()
    args = action_doc.get("args", {})
    reason = str(action_doc.get("reason", "")).strip()
    if not isinstance(args, dict):
        args = {}

    if action not in ALLOWED_ACTIONS:
        action = "final"
        action_doc["answer"] = "Planner chose an unknown action. Please rephrase the request."

    if action == "final" and _query_wants_registry_values(state.get("query", "")):
        has_by_key = _history_has_action(state.get("history", ""), "windows.registry.printkey_by_key")
        if not has_by_key:
            inferred_key = _extract_registry_key_from_history(state.get("history", ""))
            if inferred_key:
                action = "windows.registry.printkey_by_key"
                args = {"key": inferred_key}
            else:
                action = "windows.registry.printkey"
                args = {}
            reason = (reason + "; " if reason else "") + "force_registry_values_drilldown"

    if action == "final" and _query_wants_yara_scan(state.get("query", "")):
        has_yara_scan = _history_has_action(state.get("history", ""), "windows.vadyarascan_all")
        if not has_yara_scan:
            action = "windows.vadyarascan_all"
            args = {}
            reason = (reason + "; " if reason else "") + "force_yara_scan_execution"

    if action == "final" and _query_wants_memmap_dump(state.get("query", "")):
        has_memmap_dump = _history_has_action(state.get("history", ""), "windows.memmap_dump_by_pid")
        if not has_memmap_dump:
            action = "windows.memmap_dump_by_pid"
            reason = (reason + "; " if reason else "") + "force_memmap_dump_execution"

    if action == "final":
        state["done"] = True
        state["planner_answer"] = str(action_doc.get("answer", "Unable to produce a final answer."))
        state["history"] = (
            state["history"]
            + f"\nStep {state['steps_taken'] + 1}: status=finalized stage=plan reason={reason or 'planner_final'}\n"
        )
        state["next_action"] = "final"
        state["next_args_json"] = "{}"
        state["next_reason"] = reason
        return state

    state["next_action"] = action
    state["next_args_json"] = json.dumps(args, ensure_ascii=False)
    state["next_reason"] = reason
    state["history"] = (
        state["history"]
        + f"\nStep {state['steps_taken'] + 1}: status=planned action={action} args={state['next_args_json']} reason={reason}\n"
    )
    return state


def execute_node(state: AgentState) -> AgentState:
    print("executing node")
    action = state["next_action"]
    reason = state.get("next_reason", "")
    raw_args = _extract_json_object(state["next_args_json"]) or {}
    args, validation_error = validate_and_normalize_tool_args(action, raw_args)

    if validation_error:
        observation = {
            "validation_error": validation_error,
            "provided_args": raw_args,
        }
        state["history"] = (
            state["history"]
            + f"Step {state['steps_taken'] + 1}: status=failed stage=validate action={action} error={validation_error}\n"
        )
    else:
        snapshot = str(args.get("memory_snapshot_location") or state["memory_snapshot_location"])
        state["history"] = (
            state["history"]
            + f"Step {state['steps_taken'] + 1}: status=executing action={action}\n"
        )
        try:
            observation = execute_tool_action(action, args, snapshot)
            print("observation output per tool call")
            print(observation)
            print("Actual Tool output length: ", len(json.dumps(observation, ensure_ascii=False)))
            records = _extract_projectable_records(observation)
            if records:
                sample_obj = records[0]
                try:
                    relevant_fields = get_required_fields_from_json_object(sample_obj, reason)
                    print(relevant_fields)
                    projected_records = projected_json(records, relevant_fields)
                    print(projected_records)
                    if isinstance(observation, list):
                        observation = projected_records
                    elif isinstance(observation, dict):
                        compressed_observation = dict(observation)
                        for key in ("records", "rows", "data", "results"):
                            if isinstance(compressed_observation.get(key), list):
                                compressed_observation[key] = projected_records
                                observation = compressed_observation
                                break
                    print("After compression Tool output length: ", len(json.dumps(observation, ensure_ascii=False)))
                except Exception:
                    pass
        except Exception as exc:
            observation = {"error": str(exc)}
            state["history"] = (
                state["history"]
                + f"Step {state['steps_taken'] + 1}: status=failed stage=execute action={action} error={str(exc)}\n"
            )

    summary = _summarize_observation(action, observation)
    full_json = json.dumps(observation, ensure_ascii=False)
    compact = full_json
    if len(compact) > 5000:
        compact = compact[:5000] + "...<truncated>"
    compact = full_json
    
    state["history"] = (
        state["history"]
        + f"Step {state['steps_taken'] + 1}: status=completed action={action}\n"
        + f"Summary: {summary}\n"
        + f"Observation: {compact}\n"
    )
    state["last_action"] = action
    state["last_observation_json"] = compact
    state["last_observation_full_json"] = full_json

    # try:
    #     print("Summarizing module called")
    #     summary_text = summarize_tool_output(reason=reason, action=action, observation=observation)
    #     if summary_text:
    #         print(f"[tool-summary][{action}] {summary_text}", flush=True)
    # except Exception as exc:
    #     print(f"[tool-summary][{action}] failed: {str(exc)}", flush=True)

    state["steps_taken"] += 1
    return state


def finalize_node(state: AgentState) -> AgentState:
    planner_answer = state.get("planner_answer", "")
    last_action = state.get("last_action", "")
    last_obs_json = state.get("last_observation_full_json", "") or state.get("last_observation_json", "")

    if last_action == "windows.pslist" and last_obs_json:
        try:
            parsed = json.loads(last_obs_json)
            if _query_wants_full_process_list(state.get("query", "")):
                rendered = _format_process_list(parsed)
                if rendered:
                    state["final_answer"] = rendered
                    return state
        except json.JSONDecodeError:
            pass

    if last_obs_json:
        try:
            parsed = json.loads(last_obs_json)
            grounded_answer, grounded_error = _llm_grounded_answer_from_observation(
                query=state.get("query", ""),
                action=last_action or "unknown",
                observation=parsed,
            )
            if grounded_answer:
                state["final_answer"] = grounded_answer
                return state
            if grounded_error:
                state["history"] = (
                    state["history"]
                    + f"Step {state['steps_taken'] + 1}: status=failed stage=finalize action={last_action or 'unknown'} "
                    f"error={grounded_error}\n"
                )
        except json.JSONDecodeError:
            pass

    if planner_answer and not _is_generic_answer(planner_answer):
        state["final_answer"] = planner_answer
        return state

    llm = _build_llm()
    prompt = (
        "You are a DFIR assistant. Produce a concrete final answer from the collected observations.\n"
        "Always include specific details (names, PIDs, ports, counts) from the observations.\n"
        "Do not reply with generic status-only text.\n\n"
        f"User query:\n{state['query']}\n\n"
        f"Collected history:\n{state['history']}\n"
    )
    response = llm.invoke(prompt)
    state["final_answer"] = _to_text(response.content)
    return state


def _after_plan(state: AgentState) -> Literal["execute", "finalize"]:
    return "finalize" if state["done"] else "execute"


def build_graph():
    builder = StateGraph(AgentState)
    builder.add_node("plan", plan_node)
    builder.add_node("execute", execute_node)
    builder.add_node("finalize", finalize_node)

    builder.add_edge(START, "plan")
    builder.add_conditional_edges("plan", _after_plan, {"execute": "execute", "finalize": "finalize"})
    builder.add_edge("execute", "plan")
    builder.add_edge("finalize", END)
    return builder.compile()


graph = build_graph()
