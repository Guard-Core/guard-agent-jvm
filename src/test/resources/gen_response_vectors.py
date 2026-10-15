"""Generate response-semantics vectors from the reference Python agent.

Usage: python gen_response_vectors.py > response_vectors.json
Run with the guard-agent venv (guard_agent importable). Each case is served
to the real HTTPTransport through httpx.MockTransport and the observable
verdict, request count and circuit breaker failure count are recorded.
"""
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone

import httpx

from guard_agent.models import AgentConfig, AgentStatus, SecurityEvent
from guard_agent.transport import HTTPTransport

logging.disable(logging.CRITICAL)

CASES = [
    (200, '{"success":true}', {}),
    (200, '{"success":false}', {}),
    (200, '{"success":false,"errors":["quota"]}', {}),
    (200, '{"errors":["quota"]}', {}),
    (200, '{"errors":[]}', {}),
    (200, '{"errors":""}', {}),
    (200, '{"errors":0}', {}),
    (200, '{"errors":{"a":1}}', {}),
    (200, '{"errors":true}', {}),
    (200, '{"errors":null}', {}),
    (200, '{"errors":1}', {}),
    (200, '{}', {}),
    (200, '{"message":"ok"}', {}),
    (200, '[]', {}),
    (200, '[1]', {}),
    (200, 'null', {}),
    (200, '"ok"', {}),
    (200, 'true', {}),
    (200, 'not json', {}),
    (200, '', {}),
    (201, '', {}),
    (202, '', {}),
    (204, '', {}),
    (301, '', {"Location": "http://other/"}),
    (302, '', {}),
    (400, 'bad', {}),
    (401, 'no', {}),
    (403, 'no', {}),
    (404, 'gone', {}),
    (405, '', {}),
    (408, '', {}),
    (413, 'big', {}),
    (422, 'bad', {}),
    (429, '', {"Retry-After": "0"}),
    (500, 'boom', {}),
    (502, 'boom', {}),
]


def build_config():
    return AgentConfig(
        api_key="test-api-key-123",
        endpoint="http://mock.invalid",
        project_id="proj",
        retry_attempts=2,
        backoff_factor=0.001,
        compression_enabled=False,
    )


async def run_case(kind, status, body, headers):
    transport = HTTPTransport(build_config())
    count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal count
        count += 1
        return httpx.Response(status, content=body.encode(), headers=headers)

    transport._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
    now = datetime.now(timezone.utc)
    if kind == "events":
        result = await transport.send_events(
            [SecurityEvent(timestamp=now, event_type="x")]
        )
        verdict = bool(result)
    elif kind == "status":
        result = await transport.send_status(
            AgentStatus(
                timestamp=now, status="healthy", uptime=1.0, events_sent=0,
                events_failed=0, buffer_size=0,
            )
        )
        verdict = bool(result)
    else:
        result = await transport.fetch_dynamic_rules()
        verdict = result is not None
    return {
        "kind": kind,
        "status": status,
        "body": body,
        "headers": headers,
        "confirmed": verdict,
        "requests": count,
        "breaker_failures": transport.circuit_breaker.failure_count,
    }


async def main():
    out = []
    for kind in ("events", "status", "rules"):
        for status, body, headers in CASES:
            out.append(await run_case(kind, status, body, headers))
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


asyncio.run(main())
