"""Generate the reference wire shape (model_dump key -> JSON type) for a
batch, an event, a metric and a status, from the reference Python agent.

Usage: python gen_wire_shape.py > wire_shape.json
"""
import json
import sys
from datetime import datetime, timezone

from guard_agent.models import (
    AgentStatus, EventBatch, SecurityEvent, SecurityMetric,
)
from guard_agent.utils import safe_json_serialize
import asyncio


def kinds(d):
    return {k: type(v).__name__ for k, v in d.items()}


async def main():
    now = datetime.now(timezone.utc)
    event = SecurityEvent(timestamp=now, event_type="x")
    metric = SecurityMetric(timestamp=now, metric_type="request_count", value=1.0)
    batch = EventBatch(project_id="p", events=[event], batch_id="b", created_at=now)
    status = AgentStatus(
        timestamp=now, status="healthy", uptime=1.0, events_sent=0,
        events_failed=0, buffer_size=0,
    )
    wire = json.loads(await safe_json_serialize(batch.model_dump()))
    out = {
        "batch": kinds(wire),
        "event": kinds(wire["events"][0]),
        "metric": kinds(json.loads(await safe_json_serialize(metric.model_dump()))),
        "status": kinds(json.loads(await safe_json_serialize(status.model_dump()))),
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


asyncio.run(main())
