from __future__ import annotations

import subprocess
import sys


def _tk_probe() -> bool:
    """Return True only when tkinter can open a real display window."""
    probe = [
        sys.executable,
        "-c",
        (
            "import tkinter as tk; "
            "root = tk.Tk(); "
            "root.withdraw(); "
            "root.update(); "
            "root.destroy()"
        ),
    ]
    try:
        completed = subprocess.run(
            probe,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def main() -> int:
    if _tk_probe():
        from .gui import main as gui_main

        return gui_main()

    from .terminal_ui import main as terminal_main

    return terminal_main()
