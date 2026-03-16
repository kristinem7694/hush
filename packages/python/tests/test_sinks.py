from __future__ import annotations

import json
from hushspec.evaluate import Decision
from hushspec.receipt import (
    ActionSummary,
    DecisionReceipt,
    PolicySummary,
    RuleEvaluation,
)
from hushspec.sinks import (
    CallbackSink,
    FileReceiptSink,
    FilteredSink,
    MultiSink,
    NullSink,
    StderrReceiptSink,
)



# Helpers



def _make_receipt(decision: Decision = Decision.ALLOW) -> DecisionReceipt:
    return DecisionReceipt(
        receipt_id="test-receipt-001",
        timestamp="2026-03-15T00:00:00.000Z",
        hushspec_version="0.1.0",
        action=ActionSummary(
            type="tool_call",
            target="test_tool",
            content_redacted=False,
        ),
        decision=decision,
        matched_rule="rules.tool_access.allow",
        reason="tool is explicitly allowed",
        rule_trace=[
            RuleEvaluation(
                rule_block="tool_access",
                outcome="allow",
                matched_rule="rules.tool_access.allow",
                reason="tool is explicitly allowed",
                evaluated=True,
            ),
        ],
        policy=PolicySummary(
            name="test-policy",
            version="0.1.0",
            content_hash="abc123",
        ),
        evaluation_duration_us=42,
    )



# FileReceiptSink



class TestFileReceiptSink:
    def test_writes_json_lines(self, tmp_path):
        path = str(tmp_path / "receipts.jsonl")
        sink = FileReceiptSink(path)

        sink.send(_make_receipt(Decision.ALLOW))
        sink.send(_make_receipt(Decision.DENY))

        with open(path, "r") as f:
            lines = f.read().strip().split("\n")

        assert len(lines) == 2

        parsed1 = json.loads(lines[0])
        assert parsed1["receipt_id"] == "test-receipt-001"

        parsed2 = json.loads(lines[1])
        assert parsed2["decision"] == "deny"

    def test_appends_not_overwrites(self, tmp_path):
        path = str(tmp_path / "receipts.jsonl")
        sink = FileReceiptSink(path)

        sink.send(_make_receipt())
        sink.send(_make_receipt())
        sink.send(_make_receipt())

        with open(path, "r") as f:
            lines = f.read().strip().split("\n")

        assert len(lines) == 3



# StderrReceiptSink



class TestStderrReceiptSink:
    def test_does_not_crash(self):
        sink = StderrReceiptSink()
        # Should not raise.
        sink.send(_make_receipt(Decision.ALLOW))
        sink.send(_make_receipt(Decision.DENY))



# FilteredSink



class TestFilteredSink:
    def test_deny_only_forwards_deny(self):
        collected: list[Decision] = []
        inner = CallbackSink(lambda r: collected.append(r.decision))
        filtered = FilteredSink.deny_only(inner)

        filtered.send(_make_receipt(Decision.ALLOW))
        filtered.send(_make_receipt(Decision.WARN))
        filtered.send(_make_receipt(Decision.DENY))
        filtered.send(_make_receipt(Decision.ALLOW))
        filtered.send(_make_receipt(Decision.DENY))

        assert len(collected) == 2
        assert collected[0] == Decision.DENY
        assert collected[1] == Decision.DENY

    def test_filters_by_custom_decisions(self):
        collected: list[Decision] = []
        inner = CallbackSink(lambda r: collected.append(r.decision))
        filtered = FilteredSink(inner, ["allow", "warn"])

        filtered.send(_make_receipt(Decision.ALLOW))
        filtered.send(_make_receipt(Decision.DENY))
        filtered.send(_make_receipt(Decision.WARN))

        assert len(collected) == 2
        assert collected[0] == Decision.ALLOW
        assert collected[1] == Decision.WARN



# MultiSink



class TestMultiSink:
    def test_sends_to_all_sinks(self):
        count1 = [0]
        count2 = [0]

        def inc1(_r):
            count1[0] += 1

        def inc2(_r):
            count2[0] += 1

        multi = MultiSink([CallbackSink(inc1), CallbackSink(inc2)])
        multi.send(_make_receipt())
        multi.send(_make_receipt())

        assert count1[0] == 2
        assert count2[0] == 2

    def test_continues_after_error(self):
        count = [0]

        def failing(_r):
            raise RuntimeError("test error")

        def counting(_r):
            count[0] += 1

        multi = MultiSink([CallbackSink(failing), CallbackSink(counting)])
        # Should not raise even though first sink fails.
        multi.send(_make_receipt())
        assert count[0] == 1



# CallbackSink



class TestCallbackSink:
    def test_invokes_callback(self):
        received: list[DecisionReceipt] = []
        sink = CallbackSink(lambda r: received.append(r))

        sink.send(_make_receipt(Decision.ALLOW))
        sink.send(_make_receipt(Decision.DENY))

        assert len(received) == 2
        assert received[0].decision == Decision.ALLOW
        assert received[1].decision == Decision.DENY



# NullSink



class TestNullSink:
    def test_does_not_crash(self):
        sink = NullSink()
        # Should not raise.
        sink.send(_make_receipt(Decision.ALLOW))
        sink.send(_make_receipt(Decision.DENY))
        sink.send(_make_receipt(Decision.WARN))
