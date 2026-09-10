"""
vulnscope GUI - a tkinter front end.

tkinter because it ships with Python on Windows: the GUI adds zero dependencies,
matching the rest of the tool. Everything the CLI enforces is enforced here too
- an authorization string is required before the Scan button does anything, and
the same fail-closed scope guard runs underneath.

The scan runs on a WORKER THREAD, never the UI thread. tkinter is not
thread-safe, so the worker never touches a widget: it pushes events onto a
queue, and the UI thread drains that queue on a timer with root.after(). This
is the standard, safe tkinter concurrency pattern, and it is why the window
stays responsive (and the progress log keeps scrolling) during a scan instead
of showing the Windows "Not Responding" ghost.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from .scope import Scope, ScopeError
from .engine import run_scan
from . import reporting

# Palette lifted from the amirslm.com portfolio so the tool looks of a piece.
BG      = "#0b0d10"
PANEL   = "#14181d"
BORDER  = "#232a33"
TEXT    = "#e8ecf1"
MUTED   = "#8b95a3"
ACCENT  = "#7aa2ff"
SEV = {
    "critical": "#e2554f",
    "high":     "#e0a33a",
    "medium":   "#7aa2ff",
    "low":      "#6b7684",
    "info":     "#5b6570",
}


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.report = None
        self.scanning = False

        root.title("vulnscope")
        root.configure(bg=BG)
        root.geometry("860x620")
        root.minsize(680, 480)

        self._style()
        self._build()
        self.root.after(80, self._drain)

    # ---------------------------------------------------------------- styling

    def _style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")   # clam is the only built-in theme that fully honours custom colours
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=TEXT, fieldbackground=PANEL,
                     bordercolor=BORDER, font=("Segoe UI", 10))
        st.configure("TFrame", background=BG)
        st.configure("TLabel", background=BG, foreground=TEXT)
        st.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        st.configure("Head.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Semibold", 15))
        st.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, insertcolor=TEXT, bordercolor=BORDER)
        st.configure("TButton", background=PANEL, foreground=TEXT, bordercolor=BORDER, focusthickness=0, padding=6)
        st.map("TButton", background=[("active", "#1f2630"), ("disabled", "#0f1319")],
               foreground=[("disabled", MUTED)])
        st.configure("Accent.TButton", background=ACCENT, foreground="#0b0d10", font=("Segoe UI Semibold", 10))
        st.map("Accent.TButton", background=[("active", "#93b4ff"), ("disabled", "#2a3550")])
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                     bordercolor=BORDER, rowheight=24)
        st.configure("Treeview.Heading", background=BG, foreground=MUTED, relief="flat",
                     font=("Segoe UI", 9))
        st.map("Treeview", background=[("selected", "#26303c")])

    # ----------------------------------------------------------------- layout

    def _build(self):
        pad = {"padx": 14, "pady": 6}

        head = ttk.Frame(self.root)
        head.pack(fill="x", **pad)
        ttk.Label(head, text="vulnscope", style="Head.TLabel").pack(side="left")
        ttk.Label(head, text="governed, non-intrusive vulnerability assessment",
                  style="Muted.TLabel").pack(side="left", padx=10, pady=(6, 0))

        form = ttk.Frame(self.root)
        form.pack(fill="x", **pad)
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Target(s)").grid(row=0, column=0, sticky="w", pady=4)
        self.target = ttk.Entry(form)
        self.target.grid(row=0, column=1, sticky="ew", padx=8, pady=4)
        self.target.insert(0, "amirslm.com")
        ttk.Label(form, text="space-separated hosts", style="Muted.TLabel").grid(row=0, column=2, sticky="w")

        ttk.Label(form, text="Authorized by").grid(row=1, column=0, sticky="w", pady=4)
        self.auth = ttk.Entry(form)
        self.auth.grid(row=1, column=1, sticky="ew", padx=8, pady=4)
        ttk.Label(form, text="required - only scan what you may", style="Muted.TLabel").grid(row=1, column=2, sticky="w")

        bar = ttk.Frame(self.root)
        bar.pack(fill="x", **pad)
        self.scan_btn = ttk.Button(bar, text="Scan", style="Accent.TButton", command=self._start)
        self.scan_btn.pack(side="left")
        self.save_html = ttk.Button(bar, text="Save HTML", command=lambda: self._save("html"), state="disabled")
        self.save_html.pack(side="left", padx=6)
        self.save_json = ttk.Button(bar, text="Save JSON", command=lambda: self._save("json"), state="disabled")
        self.save_json.pack(side="left")
        self.status = ttk.Label(bar, text="ready", style="Muted.TLabel")
        self.status.pack(side="right")

        # counts strip
        self.counts = ttk.Label(self.root, text="", style="Muted.TLabel")
        self.counts.pack(fill="x", padx=14)

        # findings table
        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True, **pad)
        cols = ("sev", "title", "where")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("sev", text="SEVERITY")
        self.tree.heading("title", text="FINDING")
        self.tree.heading("where", text="TARGET")
        self.tree.column("sev", width=90, anchor="w", stretch=False)
        self.tree.column("title", width=430, anchor="w")
        self.tree.column("where", width=200, anchor="w", stretch=False)
        for sev, colour in SEV.items():
            self.tree.tag_configure(sev, foreground=colour)
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

        # detail pane
        self.detail = tk.Text(self.root, height=7, bg=PANEL, fg=TEXT, insertbackground=TEXT,
                              relief="flat", wrap="word", font=("Consolas", 9),
                              padx=10, pady=8, highlightthickness=1, highlightbackground=BORDER)
        self.detail.pack(fill="x", padx=14, pady=(0, 12))
        self.detail.insert("1.0", "Enter a target and an authorization, then Scan. "
                                  "Select a finding to see its evidence and fix.")
        self.detail.configure(state="disabled")

    # ------------------------------------------------------------------ scan

    def _start(self):
        if self.scanning:
            return
        targets = self.target.get().split()
        auth = self.auth.get().strip()
        if not targets:
            messagebox.showwarning("vulnscope", "Enter at least one target host.")
            return
        if not auth:
            messagebox.showwarning("vulnscope", "Authorization is required.\n\n"
                                    "Type who is authorizing this scan. Only scan systems you are allowed to test.")
            self.auth.focus_set()
            return

        # A scope allowing exactly the typed targets. The permanent-deny list and
        # deny-by-default still apply inside the guard.
        scope = Scope.from_lines([f"allow {t}" for t in targets])

        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.save_html.configure(state="disabled")
        self.save_json.configure(state="disabled")
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._set_detail("")
        self.counts.configure(text="")
        self.status.configure(text="starting")

        threading.Thread(target=self._worker, args=(targets, scope, auth), daemon=True).start()

    def _worker(self, targets, scope, auth):
        """Runs off the UI thread. Communicates ONLY via the queue."""
        try:
            summary = f"{len(targets)} target(s)"
            report = run_scan(
                targets, scope, authorized_by=auth, scope_summary=summary,
                on_event=lambda m: self.q.put(("progress", m)),
            )
            self.q.put(("done", report))
        except Exception as e:  # never let the worker die silently
            self.q.put(("error", str(e)))

    def _drain(self):
        """UI-thread timer: apply whatever the worker has queued."""
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "progress":
                    self.status.configure(text=payload)
                elif kind == "done":
                    self._render(payload)
                elif kind == "error":
                    self.scanning = False
                    self.scan_btn.configure(state="normal", text="Scan")
                    self.status.configure(text="error")
                    messagebox.showerror("vulnscope", payload)
        except queue.Empty:
            pass
        self.root.after(80, self._drain)

    # ---------------------------------------------------------------- render

    def _render(self, report):
        self.report = report
        self.scanning = False
        self.scan_btn.configure(state="normal", text="Scan")
        self.save_html.configure(state="normal")
        self.save_json.configure(state="normal")

        c = report.counts()
        self.counts.configure(
            text="   ".join(f"{k}: {c[k]}" for k in ("critical", "high", "medium", "low", "info"))
        )
        self.status.configure(text=f"done - worst: {report.worst()}")

        self._findings = report.by_severity()
        for idx, f in enumerate(self._findings):
            where = f"{f.target}:{f.port}" if f.port else f.target
            self.tree.insert("", "end", iid=str(idx),
                             values=(f.severity.upper(), f.title, where), tags=(f.severity,))
        if report.errors:
            for e in report.errors:
                self.tree.insert("", "end", values=("REFUSED", e, ""), tags=("info",))

    def _show_detail(self, _evt):
        sel = self.tree.selection()
        if not sel:
            return
        try:
            f = self._findings[int(sel[0])]
        except (ValueError, IndexError):
            return
        lines = [f"[{f.severity.upper()}]  {f.title}",
                 f"target: {f.target}" + (f":{f.port}" if f.port else ""),
                 f"check:  {f.check}", "",
                 f.detail]
        if f.evidence:
            lines += ["", f"evidence: {f.evidence}"]
        if f.remediation:
            lines += ["", f"fix: {f.remediation}"]
        if f.reference:
            lines += ["", f.reference]
        self._set_detail("\n".join(lines))

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    # ------------------------------------------------------------------ save

    def _save(self, kind):
        if not self.report:
            return
        ext = ".html" if kind == "html" else ".json"
        path = filedialog.asksaveasfilename(defaultextension=ext,
                                            filetypes=[(kind.upper(), f"*{ext}")],
                                            initialfile=f"vulnscope-report{ext}")
        if not path:
            return
        data = reporting.to_html(self.report) if kind == "html" else reporting.to_json(self.report)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data)
        self.status.configure(text=f"saved {path}")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
