"""
FastAPI backend for the vulnscope web interface.

This is a thin HTTP shell around the same engine, scope, and reporting modules
the CLI uses - it does not duplicate any scanning logic. A scan submitted here
runs on a background thread (see store.py); the page watches it over
Server-Sent Events and reads the finished report as JSON or standalone HTML.

Authorization is not optional here either: authorized_by and at least one
scope 'allow' line are required, exactly as the CLI requires --authorized-by
and --scope. The web layer is a different way to drive the same governed tool,
not a looser one.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import reporting
from .store import ScanStore

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="vulnscope")
store = ScanStore()


class ScanRequest(BaseModel):
    targets: list[str] = Field(default_factory=list)
    scope: str = ""
    authorized_by: str = ""
    timeout: float = 6.0
    ingest: str | None = None


def _parse_ingest(text):
    data = json.loads(text)
    out = {}
    if isinstance(data, dict) and "findings" in data:
        for f in data["findings"]:
            host = f.get("target") or f.get("host")
            port = f.get("port")
            if host and port:
                out.setdefault(host, set()).add(int(port))
    elif isinstance(data, dict):
        for host, ports in data.items():
            out[host] = {int(p) for p in ports}
    return out


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    if not req.authorized_by.strip():
        raise HTTPException(400, "authorized_by is required")
    if not req.scope.strip():
        raise HTTPException(400, "scope must contain at least one 'allow' line")

    ingest = None
    targets = [t.strip() for t in req.targets if t.strip()]
    if req.ingest:
        try:
            ingest = _parse_ingest(req.ingest)
        except (json.JSONDecodeError, ValueError) as e:
            raise HTTPException(400, f"invalid ingest JSON: {e}")
        if not targets:
            targets = list(ingest.keys())

    if not targets:
        raise HTTPException(400, "no targets given (enter targets or provide --ingest JSON)")

    scan_id = store.start(targets, req.scope, req.authorized_by.strip(), req.timeout, ingest,
                           ingest_text=req.ingest or "")
    return {"id": scan_id}


@app.get("/api/scans")
def list_scans():
    return store.list_recent()


@app.get("/api/scan/{scan_id}")
def scan_status(scan_id: str):
    record = store.get(scan_id)
    if record is None:
        raise HTTPException(404, "unknown scan id")
    return record.summary()


@app.get("/api/scan/{scan_id}/config")
def scan_config(scan_id: str):
    config = store.get_config(scan_id)
    if config is None:
        raise HTTPException(404, "unknown scan id")
    return config


@app.delete("/api/scan/{scan_id}")
def delete_scan(scan_id: str):
    store.delete(scan_id)
    return {"ok": True}


@app.get("/api/scan/{scan_id}/events")
def scan_events(scan_id: str):
    record = store.get(scan_id)
    if record is None:
        raise HTTPException(404, "unknown scan id")

    def stream():
        q = record.subscribe()
        while True:
            msg = q.get()
            if msg is None:
                yield f"event: done\ndata: {json.dumps(record.summary())}\n\n"
                return
            yield f"data: {json.dumps(msg)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/scan/{scan_id}/report")
def scan_report(scan_id: str):
    d = store.load_report_dict(scan_id)
    if d is None:
        raise HTTPException(404, "no report for this scan id (it may still be running)")
    return JSONResponse(d)


@app.get("/api/scan/{scan_id}/report.html", response_class=HTMLResponse)
def scan_report_html(scan_id: str):
    report = store.load_report_object(scan_id)
    if report is None:
        raise HTTPException(404, "no report for this scan id (it may still be running)")
    return reporting.to_html(report)


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
