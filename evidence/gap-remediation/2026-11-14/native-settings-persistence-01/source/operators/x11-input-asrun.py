from __future__ import annotations

import ctypes
import sys
import subprocess
import time

x11 = ctypes.CDLL("libX11.so.6")
xtst = ctypes.CDLL("libXtst.so.6")
x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
x11.XStringToKeysym.argtypes = [ctypes.c_char_p]
x11.XStringToKeysym.restype = ctypes.c_ulong
x11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
x11.XKeysymToKeycode.restype = ctypes.c_uint
x11.XFlush.argtypes = [ctypes.c_void_p]
xtst.XTestFakeMotionEvent.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
xtst.XTestFakeButtonEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]

display = x11.XOpenDisplay(b":113")
if not display:
    raise SystemExit("X display :113 unavailable")


def flush() -> None:
    x11.XFlush(display)
    time.sleep(0.08)


def click(x: int, y: int, count: int = 1) -> None:
    xtst.XTestFakeMotionEvent(display, -1, x, y, 0)
    flush()
    for _ in range(count):
        xtst.XTestFakeButtonEvent(display, 1, 1, 0)
        flush()
        xtst.XTestFakeButtonEvent(display, 1, 0, 0)
        flush()
        time.sleep(0.15)


def key(name: str, down: bool) -> None:
    code = x11.XKeysymToKeycode(display, x11.XStringToKeysym(name.encode()))
    if not code:
        raise ValueError(name)
    xtst.XTestFakeKeyEvent(display, code, int(down), 0)
    flush()


try:
    if sys.argv[1] == "click":
        click(int(sys.argv[2]), int(sys.argv[3]))
    elif sys.argv[1] == "double":
        click(int(sys.argv[2]), int(sys.argv[3]), 2)
    elif sys.argv[1] == "drag":
        x1, y1, x2, y2 = map(int, sys.argv[2:6])
        xtst.XTestFakeMotionEvent(display, -1, x1, y1, 0)
        flush()
        xtst.XTestFakeButtonEvent(display, 1, 1, 0)
        flush()
        for step in range(1, 21):
            x = x1 + (x2 - x1) * step // 20
            y = y1 + (y2 - y1) * step // 20
            xtst.XTestFakeMotionEvent(display, -1, x, y, 0)
            flush()
        xtst.XTestFakeButtonEvent(display, 1, 0, 0)
        flush()
    elif sys.argv[1] == "snapshot_hold":
        xtst.XTestFakeMotionEvent(display, -1, int(sys.argv[2]), int(sys.argv[3]), 0)
        flush()
        xtst.XTestFakeButtonEvent(display, 1, 1, 0)
        flush()
        time.sleep(0.5)
        subprocess.run(["import", "-display", ":113", "-window", "root", sys.argv[4]], check=True)
        xtst.XTestFakeButtonEvent(display, 1, 0, 0)
        flush()
    elif sys.argv[1] == "down":
        xtst.XTestFakeMotionEvent(display, -1, int(sys.argv[2]), int(sys.argv[3]), 0)
        flush()
        xtst.XTestFakeButtonEvent(display, 1, 1, 0)
        flush()
    elif sys.argv[1] == "up":
        xtst.XTestFakeButtonEvent(display, 1, 0, 0)
        flush()
    elif sys.argv[1] == "move":
        xtst.XTestFakeMotionEvent(display, -1, int(sys.argv[2]), int(sys.argv[3]), 0)
        flush()
    elif sys.argv[1] == "type":
        for char in sys.argv[2]:
            key(char, True)
            key(char, False)
    elif sys.argv[1] == "backspaces":
        for _ in range(int(sys.argv[2])):
            key("BackSpace", True)
            key("BackSpace", False)
    elif sys.argv[1] == "key":
        names = sys.argv[2:]
        for name in names:
            key(name, True)
        for name in reversed(names):
            key(name, False)
    else:
        raise ValueError("Expected click, double or key")
finally:
    x11.XCloseDisplay(display)
