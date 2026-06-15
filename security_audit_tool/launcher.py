from __future__ import annotations

import subprocess
import sys
import traceback


def _tk_probe() -> tuple[bool, str | None]:
    """Return whether tkinter can open a real display window and why not if it can't."""
    probe = (
        "import tkinter as tk\n"
        "root = tk.Tk()\n"
        "root.withdraw()\n"
        "root.update_idletasks()\n"
        "root.update()\n"
        "root.destroy()\n"
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as exc:
        return False, f"tkinter probe failed: {exc}"

    if completed.returncode != 0:
        reason = (completed.stderr or completed.stdout or "tkinter probe exited unexpectedly").strip()
        return False, reason
    return True, None


def main() -> int:
    gui_available, reason = _tk_probe()
    if gui_available:
        try:
            from .gui import main as gui_main

            return gui_main()
        except Exception as exc:
            print(f"GUI launch failed: {exc}", file=sys.stderr)
            print(traceback.format_exc(), file=sys.stderr)
            print("Falling back to the terminal interface.", file=sys.stderr)
    elif reason:
        print(f"GUI unavailable: {reason}", file=sys.stderr)
        print("Falling back to the terminal interface.", file=sys.stderr)

    from .terminal_ui import main as terminal_main

    return terminal_main()

if __name__ == "__main__":
    import sys
    sys.exit(main())
