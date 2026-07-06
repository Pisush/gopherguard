"""The gopherguard Python analysis sub-agent (M5 polyglot A2A).

A deterministic ADK custom agent: no LLM, no API key, no egress. It scores a
piece of text for prompt-injection indicators and returns a small report.
Determinism matters here for the same reason it does in the Go evals — the
cross-language demo must be reproducible and runnable headless.

The agent stamps ``agent.hop = coordinator->python-analysis`` (the same
attribute vocabulary as internal/telemetry/trust.go on the Go side) onto the
current OTel span, so the hop is visible from both runtimes in one trace.
Keep the hop string in sync with internal/a2aremote/a2aremote.go.
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.genai import types
from opentelemetry import trace

AGENT_HOP = "coordinator->python-analysis"

# Deterministic prompt-injection indicators: (label, pattern, weight).
# These are teaching-grade heuristics for the demo, not a production
# injection classifier — the point of M5 is the cross-runtime plumbing.
_INDICATORS: list[tuple[str, re.Pattern[str], int]] = [
    ("ignore-previous-instructions", re.compile(r"ignore (all |any )?(previous|prior|above) (instructions|rules)", re.I), 40),
    ("role-override", re.compile(r"you are now|act as (the )?(system|admin|root)", re.I), 30),
    ("system-prompt-probe", re.compile(r"(reveal|print|show|repeat).{0,20}(system prompt|hidden instructions)", re.I), 30),
    ("exfiltration-verb", re.compile(r"exfiltrat|send .{0,30}(to|@) ", re.I), 25),
    ("secret-hunting", re.compile(r"api[_ -]?key|password|credential|secret", re.I), 20),
    ("encoded-payload", re.compile(r"base64|\\x[0-9a-f]{2}|%[0-9a-f]{2}%[0-9a-f]{2}", re.I), 15),
    ("shell-fragment", re.compile(r"curl |wget |rm -rf|/etc/passwd", re.I), 15),
]


def analyze(text: str) -> str:
    """Return a deterministic analysis report for *text*."""
    words = text.split()
    sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]

    hits = [(label, weight) for label, pattern, weight in _INDICATORS if pattern.search(text)]
    score = min(100, sum(weight for _, weight in hits))
    if score >= 60:
        verdict = "likely-injection"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "benign"

    summary = sentences[0].strip() if sentences else ""
    if len(summary) > 120:
        summary = summary[:117] + "..."

    lines = [
        "python-analysis report",
        f"  size: {len(text)} chars, {len(words)} words, {len(sentences)} sentences",
        f"  injection-risk: {score}/100 ({verdict})",
        f"  indicators: {', '.join(label for label, _ in hits) if hits else 'none'}",
        f"  summary: {summary!r}",
    ]
    return "\n".join(lines)


class AnalysisAgent(BaseAgent):
    """Deterministic text-analysis agent, exposed over A2A via ``to_a2a``."""

    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        # Mirror the Go side's hop attribute onto whatever span is current in
        # the Python runtime, so the receiving half of the hop is queryable.
        span = trace.get_current_span()
        if span.is_recording():
            span.set_attribute("agent.hop", AGENT_HOP)
            span.set_attribute("trust.untrusted_input", True)

        text = _user_text(ctx)
        report = analyze(text) if text else "python-analysis report\n  error: empty input"
        yield Event(
            invocation_id=ctx.invocation_id,
            author=self.name,
            content=types.Content(role="model", parts=[types.Part(text=report)]),
        )


def _user_text(ctx: InvocationContext) -> str:
    content = ctx.user_content
    if content is None or not content.parts:
        return ""
    return " ".join(p.text for p in content.parts if p.text).strip()


root_agent = AnalysisAgent(
    name="python_analysis",
    description="Deterministic text analysis: prompt-injection risk score and summary.",
)
