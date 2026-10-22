"""Append and page transcript events; IDs are the reconnect cursor.

Only operator-visible events are written, not spinner heartbeats. This leaves
the tool execution hot path and its observation ingestion unchanged.
"""
import json
from typing import Any

from sqlalchemy import select

from osprey.db.session import SessionLocal
from osprey.models.chat_event import ChatEventRow


TRANSIENT_EVENTS = {"status", "llm_call_start", "llm_still_waiting", "compaction"}


def append_event(eid: str, run_id: str, event: str, data: dict[str, Any]) -> dict[str, Any]:
    with SessionLocal() as db:
        row = ChatEventRow(
            engagement_id=eid, run_id=run_id, event=event,
            data_json=json.dumps(data, ensure_ascii=False),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return _encode(row)


def page_events(eid: str, after: int = 0, limit: int = 500) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(ChatEventRow).where(
                ChatEventRow.engagement_id == eid, ChatEventRow.id > after,
            ).order_by(ChatEventRow.id).limit(min(1000, max(1, limit)))
        ).all()
        return [_encode(row) for row in rows]


def _encode(row: ChatEventRow) -> dict[str, Any]:
    return {
        "id": row.id, "run_id": row.run_id, "event": row.event,
        "data": json.loads(row.data_json), "created_at": row.created_at.isoformat(),
    }


def record_answer(eid: str, question_id: str, answer: str) -> None:
    with SessionLocal() as db:
        rows = db.scalars(select(ChatEventRow).where(
            ChatEventRow.engagement_id == eid, ChatEventRow.event == "question",
        ).order_by(ChatEventRow.id.desc())).all()
        for row in rows:
            if json.loads(row.data_json).get("id") == question_id:
                append_event(eid, row.run_id, "question_answer", {"id": question_id, "answer": answer})
                return


def latest_event(eid: str) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.scalar(select(ChatEventRow).where(ChatEventRow.engagement_id == eid)
                        .order_by(ChatEventRow.id.desc()).limit(1))
        return _encode(row) if row else None


def accepted_input(eid: str, request_id: str) -> dict[str, Any] | None:
    if not request_id:
        return None
    with SessionLocal() as db:
        rows = db.scalars(select(ChatEventRow).where(
            ChatEventRow.engagement_id == eid, ChatEventRow.event == "run_start",
        ).order_by(ChatEventRow.id.desc()))
        for row in rows:
            if json.loads(row.data_json).get("request_id") == request_id:
                return _encode(row)
    return None


def admit_input(eid: str, run_id: str, prompt: str, request_id: str) -> dict[str, Any]:
    """The user message and its executable run marker commit together."""
    from osprey.models.conversation import ConversationMessageRow

    with SessionLocal() as db:
        message = ConversationMessageRow(engagement_id=eid, role="user", content=prompt)
        db.add(message)
        db.flush()
        row = ChatEventRow(engagement_id=eid, run_id=run_id, event="run_start", data_json=json.dumps({
            "prompt": prompt, "message_id": message.id, "run_id": run_id, "request_id": request_id,
        }, ensure_ascii=False))
        db.add(row)
        db.commit()
        db.refresh(row)
        return _encode(row)


def restore_history(eid: str, *, exclude_run: str = "") -> list[dict[str, Any]]:
    """Rebuild provider-valid root tool exchanges from the durable transcript.

    Worker events remain visible in chat, but their independent conversations
    must not be inserted into the commander's model history. A partial batch is
    repaired with explicit unknown-outcome results, never re-executed on replay.
    """
    from osprey.services.conversation_store import get_history

    first = page_events(eid, limit=1)
    boundary = first[0]["data"].get("message_id") if first else None
    messages = [{"role": m["role"], "content": m["content"]}
                for m in get_history(eid, before_id=boundary)] if not first or boundary else []
    if not first:
        return messages
    calls: list[dict[str, Any]] = []
    results: dict[str, str] = {}
    narration = ""

    def flush() -> None:
        nonlocal narration
        if calls:
            messages.append({"role": "assistant", "content": narration, "tool_calls": list(calls)})
            for call in calls:
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": results.get(
                    call["id"], "Execution was interrupted before its result was recorded. Check durable jobs/artifacts before repeating this action.")})
            calls.clear()
            results.clear()
        elif narration:
            messages.append({"role": "assistant", "content": narration})
        narration = ""

    cursor = 0
    while page := page_events(eid, cursor):
        cursor = page[-1]["id"]
        for record in page:
            if record["run_id"] == exclude_run:
                continue
            name, data = record["event"], record["data"]
            if data.get("source", "commander") != "commander" or str(data.get("tool_call_id", "")).startswith("worker-"):
                continue
            if name == "run_start":
                flush()
                messages.append({"role": "user", "content": data["prompt"]})
            elif name == "assistant":
                flush()
                narration = data.get("content", "")
            elif name == "tool_start":
                if calls and results:
                    flush()
                calls.append({"id": data["tool_call_id"], "type": "function", "function": {
                    "name": data["tool_name"], "arguments": data.get("arguments") or "{}"}})
            elif name == "tool_end":
                result = data.get("result", "")
                if len(result) > 16000:
                    result = (result[:8000] + f"\n[Full recorded result: platform_artifact(path='chat-event:{record['id']}', engagement_id='{eid}', offset=0, limit=16000).]\n" + result[-2000:])
                results[data["tool_call_id"]] = result
            elif name in {"done", "cancelled"}:
                flush()
    flush()
    return messages
