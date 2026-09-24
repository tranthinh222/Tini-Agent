"""Deterministic safety evals for human-approved tool execution."""

import json

from tini.db import connect
from tini.tools.registry import Tool, ToolRegistry


def _registry(tmp_path, called):
    home = tmp_path / "home"
    home.mkdir()
    conn = connect(home)
    registry = ToolRegistry(conn=conn, enforce_approval=True)
    registry.register(
        Tool(
            "publish_message",
            "Publish",
            {"type": "object"},
            lambda body, api_key="": called.append(body) or f"published: {body}",
            risk_level="high",
            requires_approval=True,
        )
    )
    return registry, conn


def test_sensitive_tool_is_queued_not_executed(tmp_path):
    called = []
    registry, conn = _registry(tmp_path, called)
    output = registry.execute("publish_message", {"body": "hello", "api_key": "secret"})
    assert called == [] and "Approval required" in output
    assert conn.execute("SELECT status FROM pending_actions").fetchone()[0] == "pending"


def test_human_approval_executes_exactly_once(tmp_path):
    called = []
    registry, _conn = _registry(tmp_path, called)
    registry.execute("publish_message", {"body": "hello"})
    assert registry.approve(1) == "published: hello" and called == ["hello"]
    assert registry.approve(1) == "No pending action #1." and called == ["hello"]


def test_rejection_never_invokes_tool(tmp_path):
    called = []
    registry, _conn = _registry(tmp_path, called)
    registry.execute("publish_message", {"body": "do not send"})
    assert "Nothing was executed" in registry.reject(1) and called == []


def test_audit_log_redacts_secrets(tmp_path):
    called = []
    registry, conn = _registry(tmp_path, called)
    registry.execute("publish_message", {"body": "hello", "api_key": "top-secret"})
    audit = conn.execute("SELECT arguments FROM tool_audit ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert json.loads(audit)["api_key"] == "[REDACTED]" and "top-secret" not in audit


def test_low_risk_tool_runs_without_approval(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    conn = connect(home)
    registry = ToolRegistry(conn=conn, enforce_approval=True)
    registry.register(Tool("lookup", "Read", {"type": "object"}, lambda query: f"found {query}"))
    assert registry.execute("lookup", {"query": "docs"}) == "found docs"
    assert registry.pending() == []
    assert tuple(conn.execute("SELECT decision, status FROM tool_audit").fetchone()) == (
        "automatic",
        "executed",
    )
