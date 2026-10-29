"""Run one compiler command with bounded process-group cleanup."""
import os
import math
from pathlib import Path
import signal
import subprocess
import time


def run(command, stdout_path, stderr_path, timeout):
    """Return exit status and cancellation metadata; never use a shell.

    Descendants that create their own process group may escape cleanup. SIGKILL
    to this controller also cannot be handled, so this is not a supervisor.
    """
    try:
        valid_timeout = not isinstance(timeout, bool) and isinstance(timeout, (int, float)) and math.isfinite(timeout) and timeout > 0
    except OverflowError:
        valid_timeout = False
    if not valid_timeout:
        raise ValueError('timeout must be a finite positive number')
    interrupted = [None]
    previous = {}

    def on_signal(signum, _frame):
        if interrupted[0] is None:
            interrupted[0] = signum

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, on_signal)
    proc = None
    started = time.monotonic()
    timed_out = False
    cleanup = None
    try:
        with Path(stdout_path).open("xb") as stdout, Path(stderr_path).open("xb") as stderr:
            if interrupted[0] is not None:
                return {"exit_code": 128 + interrupted[0], "signal": interrupted[0],
                        "cancelled_by": interrupted[0], "timed_out": False, "cleanup": "not_started"}
            proc = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            while True:
                if interrupted[0] is not None or time.monotonic() - started >= timeout:
                    timed_out = interrupted[0] is None
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                        cleanup = "term_sent"
                    except ProcessLookupError:
                        cleanup = "group_not_found"
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                            cleanup = "kill_sent"
                        except ProcessLookupError:
                            pass
                        proc.wait()
                    # The leader may exit while another group member ignores
                    # SIGTERM. Kill any remaining members of this known group.
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                        cleanup = "kill_sent_to_remaining_group"
                    except ProcessLookupError:
                        pass
                    break
                try:
                    proc.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
        child_signal = -proc.returncode if proc.returncode is not None and proc.returncode < 0 else None
        status = (128 + interrupted[0] if interrupted[0] is not None else
                  124 if timed_out else 128 + child_signal if child_signal is not None else proc.returncode)
        return {"exit_code": status, "signal": child_signal, "cancelled_by": interrupted[0], "timed_out": timed_out,
                "cleanup": cleanup, "elapsed_seconds": round(time.monotonic() - started, 3)}
    finally:
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        for signum, old in previous.items():
            signal.signal(signum, old)
