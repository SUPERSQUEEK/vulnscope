"""
In-process scan registry.

Each scan runs on its own background thread so the HTTP request that starts it
can return immediately with an id; the browser then watches progress over
Server-Sent Events and fetches the report once it is done. Reports are also
written to disk as JSON so scan history survives a server restart - this is a
single-operator tool, so a directory of JSON files is enough; it does not need
a database.
"""

from __future__ import annotations

import json
import queue
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..engine import run_scan
from ..scope import Scope, ScopeError
from .. import reporting

REPORTS_DIR = Path.home() / ".vulnscope" / "reports"


@dataclass
class ScanRecord:
    id: str
    targets: list
    authorized_by: str
    scope_text: str = ""
    timeout: float = 6.0
    ingest_text: str = ""
    status: str = "running"  # running | done | error
    events: list = field(default_factory=list)
    report: object = None
    error: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    _subscribers: list = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def config(self):
        return {
            "targets": self.targets, "scope_text": self.scope_text,
            "authorized_by": self.authorized_by, "timeout": self.timeout,
            "ingest_text": self.ingest_text,
        }

    def emit(self, msg):
        with self._lock:
            self.events.append(msg)
            for q in self._subscribers:
                q.put(msg)

    def subscribe(self):
        q = queue.Queue()
        with self._lock:
            for msg in self.events:
                q.put(msg)
            if self.status != "running":
                q.put(None)  # sentinel: stream already finished
            else:
                self._subscribers.append(q)
        return q

    def finish(self, status):
        with self._lock:
            self.status = status
            for q in self._subscribers:
                q.put(None)
            self._subscribers.clear()

    def summary(self):
        out = {
            "id": self.id, "targets": self.targets, "authorized_by": self.authorized_by,
            "status": self.status, "created_at": self.created_at, "error": self.error,
        }
        if self.report is not None:
            out["counts"] = self.report.counts()
            out["worst"] = self.report.worst()
        return out


class ScanStore:
    def __init__(self):
        self._scans = {}
        self._lock = threading.Lock()
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def start(self, targets, scope_text, authorized_by, timeout, ingest=None, ingest_text=""):
        scan_id = uuid.uuid4().hex[:12]
        record = ScanRecord(id=scan_id, targets=targets, authorized_by=authorized_by,
                             scope_text=scope_text, timeout=timeout, ingest_text=ingest_text)
        with self._lock:
            self._scans[scan_id] = record

        thread = threading.Thread(target=self._run, args=(record, scope_text, timeout, ingest), daemon=True)
        thread.start()
        return scan_id

    def _run(self, record, scope_text, timeout, ingest):
        try:
            scope = Scope.from_lines(scope_text.splitlines())
        except ScopeError as e:
            record.error = f"scope error: {e}"
            record.emit(f"scope error: {e}")
            record.finish("error")
            return
        if scope.is_empty():
            record.error = "scope error: the scope allows nothing. Add at least one 'allow' rule."
            record.emit(record.error)
            record.finish("error")
            return

        scope_summary = (
            f"{len(scope.allow_hosts)} host(s), {len(scope.allow_suffixes)} suffix(es), "
            f"{len(scope.allow_nets)} net(s) allowed"
        )
        try:
            report = run_scan(
                record.targets, scope, authorized_by=record.authorized_by,
                scope_summary=scope_summary, ingest=ingest, timeout=timeout,
                on_event=record.emit,
            )
            record.report = report
            self._persist(record)
            record.finish("done")
        except Exception as e:  # the web layer must never crash the server on a bad scan
            record.error = str(e)
            record.emit(f"scan failed: {e}")
            record.finish("error")

    def _persist(self, record):
        path = REPORTS_DIR / f"{record.id}.json"
        payload = record.report.to_dict()
        payload["id"] = record.id
        payload["config"] = record.config()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    def get(self, scan_id):
        with self._lock:
            return self._scans.get(scan_id)

    def get_config(self, scan_id):
        record = self.get(scan_id)
        if record is not None:
            return record.config()
        path = REPORTS_DIR / f"{scan_id}.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data.get("config")
        return None

    def delete(self, scan_id):
        with self._lock:
            self._scans.pop(scan_id, None)
        path = REPORTS_DIR / f"{scan_id}.json"
        if path.exists():
            path.unlink()

    def list_recent(self, limit=50):
        with self._lock:
            live = sorted(self._scans.values(), key=lambda r: r.created_at, reverse=True)
        seen = {r.id for r in live}
        out = [r.summary() for r in live[:limit]]
        if len(out) < limit:
            for path in sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                if path.stem in seen:
                    continue
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                out.append({
                    "id": data.get("id", path.stem), "targets": data.get("targets", []),
                    "authorized_by": data.get("authorized_by", ""), "status": "done",
                    "created_at": data.get("started_at", ""), "error": "",
                    "counts": data.get("counts", {}), "worst": data.get("worst", "info"),
                })
                if len(out) >= limit:
                    break
        return out

    def load_report_dict(self, scan_id):
        record = self.get(scan_id)
        if record is not None and record.report is not None:
            d = record.report.to_dict()
            d["id"] = record.id
            return d
        path = REPORTS_DIR / f"{scan_id}.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return None

    def load_report_object(self, scan_id):
        record = self.get(scan_id)
        if record is not None and record.report is not None:
            return record.report
        d = self.load_report_dict(scan_id)
        if d is None:
            return None
        return _ReportView(d)


class _ReportView:
    """Read-only stand-in for Report, built from a persisted dict, so an old
    scan's HTML export works after a restart without keeping every Report
    object (and its raw Finding instances) resident in memory forever."""

    def __init__(self, d):
        self._d = d
        self.started_at = d["started_at"]
        self.authorized_by = d["authorized_by"]
        self.scope_summary = d["scope_summary"]
        self.targets = d["targets"]
        self.errors = d["errors"]
        self.findings = [_FindingView(f) for f in d["findings"]]

    def counts(self):
        return self._d["counts"]

    def worst(self):
        return self._d["worst"]

    def by_severity(self):
        return self.findings


class _FindingView:
    def __init__(self, d):
        self.__dict__.update(d)

    def weight(self):
        from ..findings import SEVERITY
        return SEVERITY[self.severity]
