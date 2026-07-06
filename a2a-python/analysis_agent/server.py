"""A2A server entrypoint for the Python analysis sub-agent.

Run from the a2a-python/ directory:

    .venv/bin/python -m analysis_agent.server

Serves the agent card at /.well-known/agent-card.json and JSON-RPC at /.
The ASGI OpenTelemetry middleware extracts the W3C ``traceparent`` header
that the Go coordinator's A2A client injects, so every request's spans join
the caller's trace — one trace, two runtimes.
"""

from __future__ import annotations

import os

import uvicorn
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware

from .agent import AGENT_HOP, root_agent
from .telemetry import setup_tracing

HOST = os.environ.get("A2A_HOST", "127.0.0.1")
PORT = int(os.environ.get("A2A_PORT", "8091"))


def _stamp_hop(span, scope) -> None:
    """Stamp the hop on the inbound server span itself.

    The a2a-sdk may execute the agent outside the request's OTel context, so
    the server span is the guaranteed carrier of the hop attribute within the
    shared trace; the agent stamps its own span too when it can.
    """
    if span.is_recording() and scope.get("path") == "/":
        span.set_attribute("agent.hop", AGENT_HOP)


setup_tracing()

# to_a2a needs host/port up front: they are baked into the agent card URL.
app = OpenTelemetryMiddleware(
    to_a2a(root_agent, host=HOST, port=PORT),
    server_request_hook=_stamp_hop,
)


def main() -> None:
    print(f"gopherguard python-analysis A2A agent on http://{HOST}:{PORT}")
    print(f"agent card: http://{HOST}:{PORT}/.well-known/agent-card.json")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
