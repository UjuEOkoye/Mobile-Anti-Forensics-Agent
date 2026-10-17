import json
import os
from typing import Any
from app.relevant_field_selector import get_required_fields_from_json_object, projected_json

from dotenv import load_dotenv
from langchain_ollama import ChatOllama

load_dotenv()


def _build_llm() -> ChatOllama:
    model = os.getenv("OLLAMA_MODEL", "qwen3:32b")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0"))
    return ChatOllama(model=model, base_url=base_url, temperature=temperature)


def _full_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _build_summary_prompt(
    reason: str,
    action: str,
    output_json: str,
    *,
    chunk_index: int | None = None,
    total_chunks: int | None = None,
) -> str:
    chunk_context = ""
    if chunk_index is not None and total_chunks is not None:
        chunk_context = f"Chunk: {chunk_index}/{total_chunks}\n\n"

    return (
        "You are a DFIR tool-output summarizer.\n"
        "Given the reason for running a tool and the tool output, return only information relevant "
        "to that reason.\n"
        "Rules:\n"
        "- Base the response only on the tool output.\n"
        "- Use reason-driven filtering: ignore fields not needed to answer the reason.\n"
        "- Keep it concise and directly useful for the next forensic step.\n"
        "- If reason asks for process names, output only process names (one per line or comma-separated).\n"
        "- If reason asks for counts, return count only.\n"
        "- If reason asks for identifiers (PID, port, key path), return only those identifiers.\n"
        "- Do not dump full raw records unless explicitly required by the reason.\n"
        "- If output is insufficient for the reason, say exactly what is missing.\n"
        "- No markdown, no code fences, no preamble.\n\n"
        f"Tool action:\n{action}\n\n"
        f"Reason for calling this tool:\n{reason or 'No reason provided.'}\n\n"
        f"{chunk_context}"
        f"Tool output (JSON):\n{output_json}\n"
    )


def _invoke_text(llm: ChatOllama, prompt: str) -> str:
    reply = llm.invoke(prompt)
    content = reply.content
    if isinstance(content, str):
        return content.strip()
    return str(content).strip()


def _extract_chunkable_list(observation: Any) -> tuple[list[Any], Any] | None:
    if isinstance(observation, list):
        return observation, None
    if isinstance(observation, dict):
        for key in ("records", "rows", "data", "results"):
            value = observation.get(key)
            if isinstance(value, list):
                return value, key
    return None


def _with_chunk(observation: Any, list_key: Any, chunk_items: list[Any]) -> Any:
    if list_key is None:
        return chunk_items
    wrapped = dict(observation)
    wrapped[str(list_key)] = chunk_items
    return wrapped


def _split_observation_into_chunks(observation: Any, max_items_per_chunk: int = 100) -> list[Any]:
    chunkable = _extract_chunkable_list(observation)
    if not chunkable:
        return [observation]

    items, list_key = chunkable
    if max_items_per_chunk <= 0:
        max_items_per_chunk = 100

    chunks: list[Any] = []
    for i in range(0, len(items), max_items_per_chunk):
        chunk_items = items[i : i + max_items_per_chunk]
        chunks.append(_with_chunk(observation, list_key, chunk_items))

    return chunks or [observation]


def _merge_chunk_summaries(llm: ChatOllama, reason: str, action: str, chunk_summaries: list[str]) -> str:
    prompt = (
        "You are a DFIR output reducer.\n"
        "Merge multiple chunk-level summaries into one final answer aligned to the reason.\n"
        "Rules:\n"
        "- Keep only info relevant to the reason.\n"
        "- Deduplicate repeated entities (process names, PIDs, ports, key paths).\n"
        "- Preserve concrete findings and omit noise.\n"
        "- If reason asks for process names, output only process names.\n"
        "- If reason asks for counts, output count only.\n"
        "- If insufficient data exists, state what is missing.\n"
        "- No markdown, no code fences, no preamble.\n\n"
        f"Tool action:\n{action}\n\n"
        f"Reason for calling this tool:\n{reason or 'No reason provided.'}\n\n"
        f"Chunk summaries:\n{json.dumps(chunk_summaries, ensure_ascii=False)}\n"
    )
    return _invoke_text(llm, prompt)


def summarize_tool_output(reason: str, action: str, observation: Any) -> str:
    llm = _build_llm()

    records = None
    if isinstance(observation, list):
        records = observation
    elif isinstance(observation, dict):
        for key in ("records", "rows", "data", "results"):
            value = observation.get(key)
            if isinstance(value, list):
                records = value
                break

    if records:
        sample_obj = records[0]
        try:
            relevant_fields = get_required_fields_from_json_object(sample_obj, reason)
            print(relevant_fields)
            print(projected_json(records, relevant_fields))
        except Exception:
            pass

    max_items_per_chunk = int(os.getenv("TOOL_SUMMARY_MAX_ITEMS_PER_CHUNK", "20"))
    chunks = _split_observation_into_chunks(observation, max_items_per_chunk=max_items_per_chunk)
    if len(chunks) == 1:
        prompt = _build_summary_prompt(reason=reason, action=action, output_json=_full_json(chunks[0]))
        return _invoke_text(llm, prompt)

    chunk_summaries: list[str] = []
    total_chunks = len(chunks)
    for idx, chunk in enumerate(chunks, start=1):
        prompt = _build_summary_prompt(
            reason=reason,
            action=action,
            output_json=_full_json(chunk),
            chunk_index=idx,
            total_chunks=total_chunks,
        )
        obtained_summary = _invoke_text(llm, prompt)
        chunk_summaries.append(obtained_summary)

    return _merge_chunk_summaries(llm, reason, action, chunk_summaries)
