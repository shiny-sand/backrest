import os
import glob
import socket
import json
import subprocess
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from zoneinfo import ZoneInfo
from flask import Flask, render_template, request, redirect, url_for, abort

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

RESTIC_REPOSITORY = os.environ.get("RESTIC_REPOSITORY", "").strip()
STATUS_JSON_PATH = os.environ.get(
    "STATUS_JSON", "/srv/restic/logs/backup_status.json"
)
RESTORE_ROOT = os.environ.get("RESTORE_ROOT", "/restore/dashboard_restores")
TZ_NAME = os.environ.get("TZ", "Europe/Copenhagen")

LOCAL_TZ = ZoneInfo(TZ_NAME)

# Warm tier source root inside snapshots (for browsing)
WARM_SOURCE_ROOT = os.environ.get(
    "WARM_SOURCE_ROOT", "/mnt/backup_sync/warm_tier"
).rstrip("/")

# Display-only schedules for the service overview
JOB_SCHEDULES: Dict[str, str] = {
    "warm_daily": "Daily @ 02:00",
    "warm_weekly": "Weekly Sun @ 04:30",
    "cold_backups": "Daily @ 03:00",
    "cold_photos": "Daily",
}

# Log configuration for each job (for dashboard cards + history)
LOG_CONFIG: Dict[str, Dict[str, Any]] = {
    "warm_daily": {
        "label": "Warm tier – daily backup",
        "card_key": "warm",
        "glob": "/srv/restic/logs/daily_backup_*.log",
        "parser": "restic_daily",
    },
    "warm_weekly": {
        "label": "Warm tier – weekly check",
        "card_key": "warm",
        "glob": "/srv/restic/logs/restic_weekly_check_*.log",
        "parser": "restic_weekly",
    },
    "cold_backups": {
        "label": "Cold tier – Backups sync",
        "card_key": "cold_backups",
        "glob": "/srv/restic/logs/rclone_cold_backups_sync_*.log",
        "parser": "rclone",
    },
    "cold_photos": {
        "label": "Cold tier – Photos_Archive sync",
        "card_key": "cold_photos",
        "glob": "/srv/restic/logs/rclone_cold_photos_*.log",
        "parser": "rclone",
    },
}

# Cold tier remotes (for /browse_cold)
COLD_REMOTES: Dict[str, Dict[str, str]] = {
    "backups": {
        "key": "backups",
        "label": "Cold tier – Backups",
        "remote": "Crypt_BACKUPS:",
    },
    "photos": {
        "key": "photos",
        "label": "Cold tier – Photos_Archive",
        "remote": "CryptCold_QNAP02_Photos_Archive:",
    },
}

# How many bytes of a log file to show in card previews
CARD_LOG_PREVIEW_BYTES = 6000

# How many log entries to show in history
LOG_HISTORY_LIMIT = 20

# ---------------------------------------------------------------------------
# Generic time / text helpers
# ---------------------------------------------------------------------------


def now_local() -> datetime:
    return datetime.now(tz=LOCAL_TZ)


def to_local_from_ts(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=LOCAL_TZ)


def humanize_timedelta(delta: timedelta) -> str:
    total_seconds = int(delta.total_seconds())
    if total_seconds < 0:
        total_seconds = 0

    days, rem = divmod(total_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    parts: List[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")

    return " ".join(parts)


def read_file_tail(path: str, max_bytes: int) -> Optional[str]:
    """Read at most max_bytes from end of file, as UTF-8 text."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size > max_bytes:
                f.seek(-max_bytes, os.SEEK_END)
            else:
                f.seek(0)
            data = f.read()
        return data.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"[error reading log: {exc}]"


def read_file_full(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            data = f.read()
        return data.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"[error reading log: {exc}]"


def find_latest_log(pattern: str) -> Optional[Dict[str, Any]]:
    paths = glob.glob(pattern)
    if not paths:
        return None
    paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    latest = paths[0]
    mtime = to_local_from_ts(os.path.getmtime(latest))
    return {"path": latest, "mtime": mtime}


def list_recent_logs(pattern: str, limit: int) -> List[Dict[str, Any]]:
    paths = glob.glob(pattern)
    paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    result: List[Dict[str, Any]] = []
    for p in paths[:limit]:
        result.append(
            {
                "path": p,
                "name": os.path.basename(p),
                "mtime": to_local_from_ts(os.path.getmtime(p)),
            }
        )
    return result


def classify_status_from_text(
    text: Optional[str], default: str = "UNKNOWN"
) -> str:
    """
    Classify job status based on log text.

    We intentionally look for strong "OK" phrases before generic "error"
    matches so that lines like "0 errors were found" are not treated as
    failures.
    """
    if not text:
        return default

    t = text.lower()

    # Positive / healthy phrases first
    if "no errors were found" in t or "0 errors were found" in t or "0 errors found" in t:
        return "HEALTHY"
    if "integrity check ok" in t or "all checks passed" in t:
        return "HEALTHY"
    if "backup complete" in t or "backup completed" in t:
        return "HEALTHY"

    # Strong failure signals
    if "fatal:" in t or "panic:" in t:
        return "ERROR"

    # Generic error words (avoid catching '0 errors' because handled above)
    if " error" in t or " failed" in t or "failure" in t:
        return "ERROR"

    return "HEALTHY" if default == "HEALTHY" else default


# ---------------------------------------------------------------------------
# Size + path helpers (used by browsing)
# ---------------------------------------------------------------------------


def format_size(size_bytes: Optional[int], is_dir: bool = False) -> str:
    """Human-readable size. Directories are shown as '-' (no aggregate size)."""
    if is_dir:
        return "-"
    if size_bytes is None:
        return "0 B"
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def warm_virtual_to_real(path: str) -> str:
    """
    Map the "virtual" path from the UI (starting at /) to the real path
    inside the restic snapshot under WARM_SOURCE_ROOT.
    """
    p = (path or "").strip()
    if not p or p == "/":
        return WARM_SOURCE_ROOT
    if not p.startswith("/"):
        p = "/" + p
    return WARM_SOURCE_ROOT + p


def warm_real_to_virtual(node_path: str) -> str:
    """
    Map a full path from restic (absolute filesystem path) back to the
    virtual path shown in the UI (with / as the root of WARM_SOURCE_ROOT).
    """
    if not node_path:
        return "/"

    p = node_path
    if p.startswith(WARM_SOURCE_ROOT):
        p = p[len(WARM_SOURCE_ROOT) :]
        if not p:
            return "/"

    if not p.startswith("/"):
        p = "/" + p

    return p


# ---------------------------------------------------------------------------
# Log parsers (for dashboard cards)
# ---------------------------------------------------------------------------


def parse_restic_daily_log(text: str) -> Dict[str, Any]:
    """
    Parse a restic daily backup log:
      - snapshot_id
      - snapshot_time
      - stats_lines
      - duration
    """
    snapshot_id: Optional[str] = None
    snapshot_time: Optional[datetime] = None
    stats_lines: List[str] = []
    duration: Optional[str] = None

    for line in text.splitlines():
        line_stripped = line.strip()

        if line_stripped.startswith("ID: "):
            snapshot_id = line_stripped.split("ID:", 1)[1].strip()

        if line_stripped.startswith("Time: "):
            ts = line_stripped.split("Time:", 1)[1].strip()
            try:
                snapshot_time = datetime.fromisoformat(ts).astimezone(LOCAL_TZ)
            except Exception:
                pass

        if line_stripped.startswith("Date:"):
            ts = line_stripped.split("Date:", 1)[1].strip().split(" ")[0]
            try:
                dt_naive = datetime.fromisoformat(ts)
                snapshot_time = dt_naive.replace(tzinfo=LOCAL_TZ)
            except Exception:
                pass

        if "processed" in line_stripped and "files" in line_stripped:
            stats_lines.append(line_stripped)
            if " in " in line_stripped:
                duration = line_stripped.split(" in ", 1)[1].strip()

        if "Added to the repository:" in line_stripped:
            stats_lines.append(line_stripped)

    status = classify_status_from_text(text, default="HEALTHY")

    return {
        "snapshot_id": snapshot_id,
        "snapshot_time": snapshot_time,
        "stats_lines": stats_lines,
        "duration": duration,
        "status": status,
    }


def parse_restic_weekly_log(text: str) -> Dict[str, Any]:
    summary: Optional[str] = None
    for line in text.splitlines():
        line_l = line.lower()
        if "no errors were found" in line_l or "0 errors found" in line_l:
            summary = "No errors were found in weekly integrity check."
            break
        if "errors were found" in line_l or "fatal:" in line_l:
            summary = line.strip()
            break

    if not summary:
        for line in reversed(text.splitlines()):
            if line.strip():
                summary = line.strip()
                break

    status = classify_status_from_text(text, default="HEALTHY")

    return {
        "summary": summary or "No summary available.",
        "status": status,
    }


def parse_rclone_log(text: str) -> Dict[str, Any]:
    """
    Parse rclone sync log for cold backups/photos:
      - Transferred:
      - Elapsed time:
    """
    transferred: Optional[str] = None
    elapsed: Optional[str] = None

    for line in text.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("Transferred:"):
            transferred = line_stripped.split("Transferred:", 1)[1].strip()
        if line_stripped.startswith("Elapsed time:"):
            elapsed = line_stripped.split("Elapsed time:", 1)[1].strip()

    status = classify_status_from_text(text, default="HEALTHY")

    return {
        "transferred": transferred,
        "elapsed": elapsed,
        "status": status,
    }


def parse_log_for_job(job_key: str, text: str) -> Dict[str, Any]:
    parser_type = LOG_CONFIG[job_key]["parser"]
    if parser_type == "restic_daily":
        return parse_restic_daily_log(text)
    if parser_type == "restic_weekly":
        return parse_restic_weekly_log(text)
    if parser_type == "rclone":
        return parse_rclone_log(text)
    return {"status": classify_status_from_text(text, default="UNKNOWN")}


# ---------------------------------------------------------------------------
# Dashboard data collection
# ---------------------------------------------------------------------------


def build_warm_card(latest_daily: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Builds the "Warm tier (restic)" card using the most recent daily backup log.
    """
    if not latest_daily or "parsed" not in latest_daily:
        return {
            "status": "UNKNOWN",
            "latest_snapshot": None,
            "error": "No snapshot information found in last daily log.",
        }

    parsed = latest_daily["parsed"]
    snapshot_id = parsed.get("snapshot_id")
    snapshot_time = parsed.get("snapshot_time")
    stats_lines = parsed.get("stats_lines", [])
    status = parsed.get("status", "UNKNOWN")

    if not snapshot_id:
        return {
            "status": status,
            "latest_snapshot": None,
            "error": "No snapshot ID found in last daily log.",
        }

    snapshot_info = {
        "id": snapshot_id,
        "time": snapshot_time,
        "stats_lines": stats_lines,
    }

    return {
        "status": status,
        "latest_snapshot": snapshot_info,
        "error": None,
    }


def collect_job_context(job_key: str) -> Optional[Dict[str, Any]]:
    cfg = LOG_CONFIG[job_key]
    latest = find_latest_log(cfg["glob"])
    if not latest:
        return None

    # Short preview for the card
    preview_text = read_file_tail(latest["path"], CARD_LOG_PREVIEW_BYTES) or ""

    # Use the full log for parsing for restic daily jobs so we always see the
    # snapshot ID / stats, even if they are near the top of the log.
    if cfg["parser"] == "restic_daily":
        parse_source = read_file_full(latest["path"]) or preview_text
    else:
        parse_source = preview_text

    parsed = parse_log_for_job(job_key, parse_source)

    age = now_local() - latest["mtime"]
    age_str = humanize_timedelta(age)

    return {
        "job_key": job_key,
        "label": cfg["label"],
        "path": latest["path"],
        "mtime": latest["mtime"],
        "age": age,
        "age_str": age_str,
        "preview": preview_text,
        "parsed": parsed,
    }


def build_dashboard_context() -> Dict[str, Any]:
    host_name = socket.gethostname()
    repo_label = RESTIC_REPOSITORY or "not configured"

    now_ts = now_local()

    warm_daily_ctx = collect_job_context("warm_daily")
    warm_weekly_ctx = collect_job_context("warm_weekly")
    cold_backups_ctx = collect_job_context("cold_backups")
    cold_photos_ctx = collect_job_context("cold_photos")

    warm_card = build_warm_card(warm_daily_ctx)

    services: List[Dict[str, Any]] = []
    for job_key, cfg in LOG_CONFIG.items():
        ctx = None
        if job_key == "warm_daily":
            ctx = warm_daily_ctx
        elif job_key == "warm_weekly":
            ctx = warm_weekly_ctx
        elif job_key == "cold_backups":
            ctx = cold_backups_ctx
        elif job_key == "cold_photos":
            ctx = cold_photos_ctx

        if not ctx:
            services.append(
                {
                    "job_key": job_key,
                    "label": cfg["label"],
                    "schedule": JOB_SCHEDULES.get(job_key, "n/a"),
                    "last_run": None,
                    "age_str": "n/a",
                    "status": "UNKNOWN",
                    "duration": "n/a",
                }
            )
            continue

        parsed = ctx["parsed"]
        duration = "n/a"
        if LOG_CONFIG[job_key]["parser"] == "restic_daily":
            duration = parsed.get("duration") or "n/a"
        elif LOG_CONFIG[job_key]["parser"] == "rclone":
            duration = parsed.get("elapsed") or "n/a"

        services.append(
            {
                "job_key": job_key,
                "label": cfg["label"],
                "schedule": JOB_SCHEDULES.get(job_key, "n/a"),
                "last_run": ctx["mtime"],
                "age_str": ctx["age_str"],
                "status": parsed.get("status", "UNKNOWN"),
                "duration": duration,
            }
        )

    services.sort(
        key=lambda s: ["warm_daily", "warm_weekly", "cold_backups", "cold_photos"].index(
            s["job_key"]
        )
        if s["job_key"] in ["warm_daily", "warm_weekly", "cold_backups", "cold_photos"]
        else 99
    )

    return {
        "brand_name": "Backrest",
        "page_title": "Backrest – backup-dashboard",
        "host_name": host_name,
        "repo_label": repo_label,
        "generated_at": now_ts,
        "warm_card": warm_card,
        "warm_daily": warm_daily_ctx,
        "warm_weekly": warm_weekly_ctx,
        "cold_backups": cold_backups_ctx,
        "cold_photos": cold_photos_ctx,
        "services": services,
    }


# ---------------------------------------------------------------------------
# restic / rclone CLI helpers (for browsing & restore)
# ---------------------------------------------------------------------------


def _restic_env() -> Dict[str, str]:
    env = os.environ.copy()
    if RESTIC_REPOSITORY:
        env.setdefault("RESTIC_REPOSITORY", RESTIC_REPOSITORY)
    return env


def _normalize_error(err: str) -> str:
    err = (err or "").strip()
    if not err:
        return "Unknown restic error"

    if "Load(<key/" in err and "does not exist" in err:
        return (
            "restic reported a repository key error "
            "(Load(<key/...> does not exist)). "
            "If 'restic check' on the host is clean, you can treat this "
            "as a transient/diagnostic issue."
        )

    lines = err.splitlines()
    if len(lines) > 8:
        return "\n".join(lines[:8]) + "\n..."
    return err


def run_restic_text(args: List[str], timeout: int = 600) -> Tuple[bool, str]:
    base_cmd = ["restic", "--no-cache"]
    if RESTIC_REPOSITORY:
        base_cmd += ["-r", RESTIC_REPOSITORY]

    cmd = base_cmd + args

    try:
        proc = subprocess.run(
            cmd,
            env=_restic_env(),
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return False, _normalize_error(f"Exception while running {' '.join(cmd)}: {exc}")

    if proc.returncode != 0:
        err_text = (proc.stderr or "") + (proc.stdout or "")
        return False, _normalize_error(err_text)

    return True, proc.stdout


def run_restic_json(args: List[str], timeout: int = 600) -> Tuple[bool, Any]:
    ok, out = run_restic_text(args + ["--json"], timeout=timeout)
    if not ok:
        return False, out
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        snippet = out[:4000]
        return False, _normalize_error(
            f"Failed to parse restic JSON: {exc}\nRaw output:\n{snippet}"
        )
    return True, data


def run_rclone_json(args: List[str], timeout: int = 600) -> Tuple[bool, Any]:
    cmd = ["rclone"] + args
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"Exception while running {' '.join(cmd)}: {exc}"

    if proc.returncode != 0:
        err_text = (proc.stderr or "") + (proc.stdout or "")
        return False, (err_text.strip() or "Unknown rclone error")

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        snippet = proc.stdout[:4000]
        return False, f"Failed to parse rclone JSON: {exc}\nRaw output:\n{snippet}"
    return True, data


# ---------------------------------------------------------------------------
# Warm tier snapshot browsing helpers
# ---------------------------------------------------------------------------


def load_all_snapshots() -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """
    Load all restic snapshots and return a list of dicts.

    We parse the 'time' field into a timezone-aware datetime so that
    browse.html can safely call snap.time.strftime(...).
    """
    ok, data = run_restic_json(["snapshots"])
    if not ok:
        return None, str(data)

    if not isinstance(data, list):
        return None, "Unexpected restic JSON format for snapshots"

    snapshots: List[Dict[str, Any]] = []

    for s in data:
        time_raw = s.get("time")
        snap_dt: Optional[datetime] = None

        if time_raw:
            try:
                dt = datetime.fromisoformat(time_raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                snap_dt = dt.astimezone(LOCAL_TZ)
            except Exception:
                snap_dt = None

        snapshots.append(
            {
                "id": s.get("short_id") or s.get("id", "")[:8],
                "full_id": s.get("id"),
                "time": snap_dt,
                "time_raw": time_raw,
                "host": s.get("hostname") or s.get("host"),
                "paths": ", ".join(s.get("paths", [])),
            }
        )

    snapshots.sort(key=lambda x: x["time_raw"] or "", reverse=True)
    return snapshots, None


def load_snapshot_path(
    snapshot_id: str,
    path: str,
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """
    Load a directory listing from a snapshot.

    The UI works with "virtual" paths starting at '/', which map to the
    real snapshot paths under WARM_SOURCE_ROOT.
    """
    real_path = warm_virtual_to_real(path)

    ok, out = run_restic_text(["ls", snapshot_id, real_path, "--json"])
    if not ok:
        return None, str(out)

    entries: List[Dict[str, Any]] = []

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            return None, (
                f"Failed to parse restic ls JSON line: {exc}\n"
                f"Line snippet: {line[:400]}"
            )

        if item.get("struct_type") != "node":
            continue

        node = item.get("node", {})
        node_type = node.get("type", "?")
        node_name = node.get("name", "")
        node_path = node.get("path", "")
        node_size = node.get("size", 0)

        virtual_path = warm_real_to_virtual(node_path)

        entries.append(
            {
                "type": node_type,
                "name": node_name,
                "path": virtual_path,
                "size": node_size,
                "size_display": format_size(node_size, is_dir=(node_type == "dir")),
            }
        )

    return entries, None


def ctx_repo_fallback() -> str:
    return RESTIC_REPOSITORY or "RESTIC_REPOSITORY not set"


# ---------------------------------------------------------------------------
# Cold tier browsing helpers
# ---------------------------------------------------------------------------


def load_cold_listing(
    remote_key: str,
    path: str,
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    meta = COLD_REMOTES.get(remote_key)
    if not meta:
        return None, f"Unknown cold remote: {remote_key}"

    remote = meta["remote"]
    rel_path = (path or "").lstrip("/")

    if rel_path:
        target = f"{remote}{rel_path}"
    else:
        target = remote

    ok, data = run_rclone_json(["lsjson", target])
    if not ok:
        return None, str(data)

    if not isinstance(data, list):
        return None, "Unexpected rclone lsjson format"

    entries: List[Dict[str, Any]] = []
    for obj in data:
        is_dir = bool(obj.get("IsDir"))
        name = obj.get("Name") or obj.get("Path", "")
        size = obj.get("Size", 0)

        if rel_path:
            child_rel = f"{rel_path.rstrip('/')}/{name}"
        else:
            child_rel = name

        display_path = "/" + child_rel.lstrip("/")

        entries.append(
            {
                "type": "dir" if is_dir else "file",
                "name": name,
                "path": display_path,
                "size": size,
                "size_display": format_size(size, is_dir=is_dir),
            }
        )

    return entries, None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index() -> str:
    ctx = build_dashboard_context()
    return render_template("index.html", **ctx)


@app.route("/browse", endpoint="browse")
def browse_logs():
    """
    Warm tier (restic) snapshot browser.
    This shares the /browse path but is explicitly named 'browse' for url_for().
    """
    snapshot_id = request.args.get("snapshot", "").strip()
    # Use "/" as the virtual root; we map this to WARM_SOURCE_ROOT internally.
    path = request.args.get("path", "").strip() or "/"
    message = request.args.get("msg", "").strip() or None

    snapshots, snapshot_error = load_all_snapshots()

    entries = None
    path_error = None
    if snapshot_id:
        entries, path_error = load_snapshot_path(snapshot_id, path)

    return render_template(
        "browse.html",
        repo=RESTIC_REPOSITORY or ctx_repo_fallback(),
        snapshots=snapshots or [],
        snapshot_error=snapshot_error,
        selected_snapshot=snapshot_id,
        path=path,
        entries=entries,
        path_error=path_error,
        message=message,
    )


@app.route("/browse_cold")
def browse_cold():
    """Cold tier (rclone) browser."""
    remote_key = request.args.get("remote", "backups")
    if remote_key not in COLD_REMOTES:
        remote_key = "backups"

    raw_path = request.args.get("path", "").strip()
    display_path = raw_path if raw_path.startswith("/") else ("/" + raw_path) if raw_path else "/"
    message = request.args.get("msg", "").strip() or None

    entries, path_error = load_cold_listing(remote_key, raw_path)

    cold_remotes_list = [
        {"key": key, "label": cfg["label"]} for key, cfg in COLD_REMOTES.items()
    ]

    return render_template(
        "browse_cold.html",
        repo="cold tier (rclone)",
        cold_remotes=cold_remotes_list,
        selected_remote=remote_key,
        path=display_path,
        entries=entries,
        path_error=path_error,
        message=message,
    )


@app.post("/restore")
def restore():
    """Restore a file or directory from a warm-tier restic snapshot."""
    snapshot_id = request.form.get("snapshot_id", "").strip()
    path = request.form.get("path", "").strip()
    entry_type = request.form.get("entry_type", "").strip() or "file"

    if not snapshot_id or not path:
        msg = "Restore failed: missing snapshot_id or path."
        return redirect(url_for("browse", snapshot=snapshot_id, path=path, msg=msg))

    if not RESTORE_ROOT:
        msg = "Restore failed: RESTORE_ROOT is not configured."
        return redirect(url_for("browse", snapshot=snapshot_id, path=path, msg=msg))

    os.makedirs(RESTORE_ROOT, exist_ok=True)

    safe_name = path.strip("/").replace("/", "_") or "root"
    restore_dir_name = f"restic_{snapshot_id[:8]}_{safe_name}_{int(time.time())}"
    dest_dir = os.path.join(RESTORE_ROOT, restore_dir_name)
    os.makedirs(dest_dir, exist_ok=True)

    # Map virtual UI path back to real path inside the snapshot
    real_path = warm_virtual_to_real(path)

    ok, out = run_restic_text(
        ["restore", snapshot_id, "--target", dest_dir, "--include", real_path],
        timeout=3600,
    )

    if ok:
        msg = f"Restore OK -> {dest_dir}"
    else:
        msg = f"Restore failed: {out}"

    return redirect(url_for("browse", snapshot=snapshot_id, path=path, msg=msg))


@app.post("/restore_cold")
def restore_cold():
    """Restore a file or directory from a cold-tier rclone remote."""
    remote_key = request.form.get("remote_key", "backups")
    path = request.form.get("path", "").strip()

    if remote_key not in COLD_REMOTES:
        remote_key = "backups"

    meta = COLD_REMOTES[remote_key]
    remote = meta["remote"]

    if not RESTORE_ROOT:
        msg = "Restore failed: RESTORE_ROOT is not configured."
        return redirect(url_for("browse_cold", remote=remote_key, path=path, msg=msg))

    os.makedirs(RESTORE_ROOT, exist_ok=True)

    rel_path = path.lstrip("/")
    source = remote + rel_path if rel_path else remote

    safe_name = rel_path.replace("/", "_") or "root"
    restore_dir_name = f"cold_{remote_key}_{safe_name}_{int(time.time())}"
    dest_dir = os.path.join(RESTORE_ROOT, restore_dir_name)
    os.makedirs(dest_dir, exist_ok=True)

    cmd = ["rclone", "copy", source, dest_dir, "-v"]
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=3600,
        )
        if proc.returncode == 0:
            msg = f"Cold restore OK -> {dest_dir}"
        else:
            err_text = (proc.stderr or "") + (proc.stdout or "")
            msg = f"Cold restore failed: {err_text.strip() or 'unknown error'}"
    except Exception as exc:  # noqa: BLE001
        msg = f"Cold restore failed: {exc}"

    return redirect(url_for("browse_cold", remote=remote_key, path=path, msg=msg))


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # For local debugging only. In Docker we run gunicorn or python app.py externally.
    app.run(host="0.0.0.0", port=8000)
