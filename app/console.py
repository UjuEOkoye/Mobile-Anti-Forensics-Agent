import argparse
import os
from datetime import datetime

from app.graph import graph


def _print_debug_timeline(history: str) -> None:
    lines = [line.strip() for line in history.splitlines() if line.strip()]
    status_lines = [line for line in lines if "status=" in line]
    if not status_lines:
        return
    print("[debug] timeline:")
    for line in status_lines:
        print(line)


def _latest_summary_line(history: str) -> str:
    for line in reversed(history.splitlines()):
        line = line.strip()
        if line.startswith("Summary:"):
            return line
    return ""


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def run_chat_loop(debug: bool, debug_history: bool, max_steps: int) -> None:
    os.environ["APP_DEBUG"] = "1" if debug else "0"
    print("LangGraph + Ollama + Volatility tools console")
    print("Type 'exit' or 'quit' to stop.")
    print(
        "Tools: windows.pslist, windows.info, windows.netscan, windows.netstat_by_pid, "
        "windows.handles_by_pid, windows.dlllist_by_pid, windows.cmdline, windows.cmdline_by_pid, "
        "windows.registry.printkey, windows.registry.printkey_by_key, windows.vadyarascan_all, "
        "windows.memmap_dump_by_pid"
    )
    if debug:
        print("Debug mode: ON")

    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not user_input:
            continue

        if user_input.lower() in {"exit", "quit"}:
            print("Bye.")
            break

        initial_state = {
            "query": user_input,
            "memory_snapshot_location": "",
            "steps_taken": 0,
            "max_steps": max_steps,
            "history": "",
            "next_action": "",
            "next_args_json": "{}",
            "next_reason": "",
            "planner_answer": "",
            "last_action": "",
            "last_observation_json": "",
            "last_observation_full_json": "",
            "final_answer": "",
            "done": False,
        }

        try:
            if debug:
                print(f"[{_ts()}][debug] pipeline started")
                result = dict(initial_state)
                printed_status_lines = 0
                for event in graph.stream(initial_state, stream_mode="updates"):
                    for node_name, update in event.items():
                        print(f"[{_ts()}][debug] node completed: {node_name}")
                        result.update(update)

                        if node_name == "plan":
                            action = result.get("next_action", "")
                            args = result.get("next_args_json", "{}")
                            done = result.get("done", False)
                            if action and action != "final" and not done:
                                print(f"[{_ts()}][debug] tool selected: {action} args={args}")
                            elif action == "final":
                                print(f"[{_ts()}][debug] planner decided to finalize response")

                        if node_name == "execute":
                            last_action = result.get("last_action", "")
                            if last_action:
                                print(f"[{_ts()}][debug] tool execution completed: {last_action}")
                                summary = _latest_summary_line(result.get("history", ""))
                                if summary:
                                    print(f"[{_ts()}][debug] {summary}")

                        history = result.get("history", "")
                        if history:
                            status_lines = [
                                line.strip()
                                for line in history.splitlines()
                                if line.strip() and "status=" in line
                            ]
                            for line in status_lines[printed_status_lines:]:
                                print(f"[{_ts()}][debug] {line}")
                            printed_status_lines = len(status_lines)
            else:
                result = graph.invoke(initial_state)
        except Exception as exc:
            model = os.getenv("OLLAMA_MODEL", "qwen2.5:32b")
            error_text = str(exc)
            if "not found" in error_text and "model" in error_text:
                print(f"Model '{model}' is not available in Ollama.")
                print(f"Run: ollama pull {model}")
                print("Or set OLLAMA_MODEL in .env to an installed model.")
                continue
            print(f"Request failed: {error_text}")
            continue

        answer = result.get("final_answer", "No assistant response was generated.")
        print(f"Assistant: {answer}")
        if debug:
            print("\n[debug] steps_taken:", result.get("steps_taken"))
            print("[debug] done:", result.get("done"))
            print("[debug] next_action:", result.get("next_action"))
            print("[debug] next_args_json:", result.get("next_args_json"))
            if debug_history:
                history = result.get("history", "").strip()
                if history:
                    _print_debug_timeline(history)
                    print("[debug] history:")
                    print(history)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LangGraph + Ollama + Volatility console")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print live planning/execution events for each query.",
    )
    parser.add_argument(
        "--debug-history",
        action="store_true",
        help="Also print full accumulated history after each query (verbose).",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=6,
        help="Maximum planner-executor iterations per query (default: 6).",
    )
    args = parser.parse_args()
    run_chat_loop(debug=args.debug, debug_history=args.debug_history, max_steps=args.max_steps)
