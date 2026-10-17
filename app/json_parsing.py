import json
from typing import Any


_JSON_VALUE_START_CHARS = set('{["-0123456789tfn')


def extract_first_json_value(text: str) -> Any | None:
    candidate_text = text.strip()
    if not candidate_text:
        return None

    try:
        return json.loads(candidate_text)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    length = len(text)

    for index, char in enumerate(text):
        if char.isspace() or char not in _JSON_VALUE_START_CHARS:
            continue
        try:
            value, end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if index + end <= length:
            return value

    return None


def extract_first_json_object(text: str) -> dict[str, Any] | None:
    value = extract_first_json_value(text)
    if isinstance(value, dict):
        return value
    return None
