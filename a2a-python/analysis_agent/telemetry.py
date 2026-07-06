"""OpenTelemetry wiring for the Python analysis sub-agent.

Mirrors the Go side's keyless-by-default posture:

- ``OTEL_EXPORTER_OTLP_ENDPOINT`` set -> OTLP/HTTP export (e.g. the M3 trace
  stack from ``make trace-up``), where the spans land in the SAME Tempo trace
  as the Go coordinator's.
- unset (default) -> compact one-line console spans, so the demo can show the
  shared trace ID without any infrastructure.
"""

from __future__ import annotations

import os

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

SERVICE_NAME = "gopherguard-python-analysis"


def _console_line(span: ReadableSpan) -> str:
    ctx = span.get_span_context()
    hop = span.attributes.get("agent.hop", "") if span.attributes else ""
    hop_part = f" agent.hop={hop}" if hop else ""
    return f"[otel] span={span.name!r} trace_id={ctx.trace_id:032x}{hop_part}\n"


def setup_tracing() -> None:
    """Install a global tracer provider; call once, before serving."""
    provider = TracerProvider(
        resource=Resource.create({"service.name": SERVICE_NAME})
    )
    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        # Endpoint/headers/protocol are all picked up from the standard
        # OTEL_EXPORTER_OTLP_* environment variables.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    else:
        provider.add_span_processor(
            BatchSpanProcessor(ConsoleSpanExporter(formatter=_console_line))
        )
    trace.set_tracer_provider(provider)
