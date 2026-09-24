"""Tool registry with policy-aware, human-approved execution."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    fn: Callable[..., str]
    wants_notify: bool = False
    risk_level: str = "low"
    requires_approval: bool = False

    def to_api(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


class ToolRegistry:
    def __init__(
        self, conn: sqlite3.Connection | None = None, enforce_approval: bool = False
    ) -> None:
        self._tools: dict[str, Tool] = {}
        self.conn = conn
        self.enforce_approval = enforce_approval

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def schemas(self) -> list[dict[str, Any]]:
        return [t.to_api() for t in self._tools.values()]

    def execute(self, name: str, args: dict[str, Any], notify=None) -> str:
        tool = self._tools.get(name)
        if tool is None:
            return f"Error: unknown tool '{name}'"
        if self.enforce_approval and tool.requires_approval:
            if self.conn is None:
                return f"Error: approval is required for '{name}', but no approval store is configured."
            cur = self.conn.execute(
                "INSERT INTO pending_actions (tool_name, arguments, risk_level) VALUES (?,?,?)",
                (name, json.dumps(args, ensure_ascii=False), tool.risk_level),
            )
            self.conn.commit()
            action_id = cur.lastrowid
            self._audit(action_id, tool, args, "requested", "pending", "")
            return (
                f"Approval required for {tool.risk_level}-risk tool '{name}'. "
                f"Pending action #{action_id}. The human must run /approve {action_id} "
                f"or /reject {action_id}; the action has not executed."
            )
        return self._invoke(tool, args, notify=notify, decision="automatic")

    def approve(self, action_id: int, notify=None) -> str:
        row = self._pending(action_id)
        if row is None:
            return f"No pending action #{action_id}."
        tool = self._tools.get(row["tool_name"])
        if tool is None:
            return f"Cannot approve #{action_id}: tool '{row['tool_name']}' is unavailable."
        args = json.loads(row["arguments"])
        result = self._invoke(tool, args, notify=notify, audit=False)
        status = "error" if result.startswith("Error") else "executed"
        self.conn.execute(
            "UPDATE pending_actions SET status='approved', resolved_at=datetime('now'), result=? WHERE id=?",
            (result, action_id),
        )
        self.conn.commit()
        self._audit(action_id, tool, args, "approved", status, result)
        return result

    def reject(self, action_id: int) -> str:
        row = self._pending(action_id)
        if row is None:
            return f"No pending action #{action_id}."
        tool = self._tools.get(row["tool_name"])
        args = json.loads(row["arguments"])
        self.conn.execute(
            "UPDATE pending_actions SET status='rejected', resolved_at=datetime('now'), result=? WHERE id=?",
            ("Rejected by user", action_id),
        )
        self.conn.commit()
        if tool is not None:
            self._audit(action_id, tool, args, "rejected", "not_executed", "Rejected by user")
        return f"Rejected pending action #{action_id}. Nothing was executed."

    def pending(self) -> list[sqlite3.Row]:
        if self.conn is None:
            return []
        return self.conn.execute(
            "SELECT id, tool_name, arguments, risk_level, created_at FROM pending_actions WHERE status='pending' ORDER BY id"
        ).fetchall()

    def _pending(self, action_id: int):
        if self.conn is None:
            return None
        return self.conn.execute(
            "SELECT * FROM pending_actions WHERE id=? AND status='pending'", (action_id,)
        ).fetchone()

    def _invoke(
        self,
        tool: Tool,
        args: dict[str, Any],
        notify=None,
        decision: str = "automatic",
        audit: bool = True,
    ) -> str:
        try:
            result = (
                tool.fn(**args, _notify=notify or (lambda kind, ev: None))
                if tool.wants_notify
                else tool.fn(**args)
            )
        except Exception as exc:
            result = f"Error running {tool.name}: {exc}"
        if audit:
            self._audit(
                None,
                tool,
                args,
                decision,
                "error" if result.startswith("Error") else "executed",
                result,
            )
        return result

    def _audit(
        self,
        action_id: int | None,
        tool: Tool,
        args: dict[str, Any],
        decision: str,
        status: str,
        result: str,
    ) -> None:
        if self.conn is None:
            return
        self.conn.execute(
            "INSERT INTO tool_audit (action_id, tool_name, arguments, risk_level, decision, status, result) VALUES (?,?,?,?,?,?,?)",
            (
                action_id,
                tool.name,
                json.dumps(_redact(args), ensure_ascii=False),
                tool.risk_level,
                decision,
                status,
                result[:2000],
            ),
        )
        self.conn.commit()


_SENSITIVE_KEYS = ("token", "secret", "password", "api_key", "authorization")


def _redact(value: Any, key: str = "") -> Any:
    if any(marker in key.lower() for marker in _SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    return value
