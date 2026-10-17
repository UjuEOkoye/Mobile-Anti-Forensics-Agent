import json
import os
from typing import Any

from dotenv import load_dotenv
from langchain_ollama import ChatOllama
from app.json_parsing import extract_first_json_object

load_dotenv()


def _build_llm() -> ChatOllama:
    model = os.getenv("OLLAMA_MODEL", "qwen3:32b")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0"))
    return ChatOllama(model=model, base_url=base_url, temperature=temperature)


def _extract_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("records", "rows", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    return []


def _schema_of(value: Any, depth: int = 0, max_depth: int = 3) -> Any:
    if depth >= max_depth:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): _schema_of(v, depth + 1, max_depth) for k, v in value.items()}
    if isinstance(value, list):
        if not value:
            return ["empty_list"]
        return [_schema_of(value[0], depth + 1, max_depth)]
    return type(value).__name__


def _extract_json_object(text: str) -> dict[str, Any] | None:
    return extract_first_json_object(text)


def _pick_fields_with_llm(
    reason: str,
    object_schema: dict[str, Any],
    candidate_fields: list[str],
) -> list[str]:
    llm = _build_llm()
    prompt = (
        "You are a DFIR field selector.\n"
        "Select only the most relevant top-level field names needed to answer the reason.\n"
        "Return ONLY valid JSON in this exact shape:\n"
        "{\"relevant_fields\":[\"field1\",\"field2\"]}\n\n"
        "Rules:\n"
        "- Choose from candidate fields only.\n"
        "- Return top-level fields only.\n"
        "- Keep minimal fields required for the reason.\n"
        "- If reason asks for process names, prefer process-name field(s).\n"
        "- If reason asks for PIDs, include PID-like fields.\n"
        "- Do not include explanation text.\n\n"
        f"Reason:\n{reason}\n\n"
        f"Candidate fields:\n{json.dumps(candidate_fields, ensure_ascii=False)}\n\n"
        f"Object schema:\n{json.dumps(object_schema, ensure_ascii=False)}\n"
    )
    reply = llm.invoke(prompt)
    parsed = _extract_json_object(str(reply.content))
    if not parsed:
        return []

    fields = parsed.get("relevant_fields", [])
    if not isinstance(fields, list):
        return []

    allowed = set(candidate_fields)
    out: list[str] = []
    for field in fields:
        field_name = str(field).strip()
        if field_name in allowed and field_name not in out:
            out.append(field_name)
    return out


def get_required_fields_from_json_object(
    json_object: dict[str, Any],
    reason: str,
) -> list[str]:
    candidate_fields = list(json_object.keys())
    object_schema = _schema_of(json_object)
    return _pick_fields_with_llm(
        reason=reason,
        object_schema=object_schema if isinstance(object_schema, dict) else {},
        candidate_fields=candidate_fields,
    )


def projected_json(
    json_objects: list[dict[str, Any]],
    fields: list[str],
) -> list[dict[str, Any]]:
    wanted = [str(field) for field in fields]
    reduced: list[dict[str, Any]] = []
    for obj in json_objects:
        filtered = {key: obj[key] for key in wanted if key in obj}
        reduced.append(filtered)
    return reduced
