from __future__ import annotations

import sys
import traceback


def _tk_probe() -> tuple[bool, str | None]:
    """Return whether tkinter can open a real display window and why not if it can't."""
    try:
        import tkinter as tk
    except Exception as exc:
        return False, f"tkinter import failed: {exc}"

    try:
        root = tk.Tk()
        root.withdraw()
        root.update_idletasks()
        root.update()
        root.destroy()
    except Exception as exc:
        return False, str(exc)
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
