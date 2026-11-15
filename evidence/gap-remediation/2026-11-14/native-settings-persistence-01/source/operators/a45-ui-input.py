#!/usr/bin/env python3
"""Bounded XTest pointer/key input for the isolated A45 display only."""

import argparse
import ctypes
import time

parser = argparse.ArgumentParser()
parser.add_argument("--display", choices=[":113"], required=True)
parser.add_argument("operation", choices=["click", "double", "key"])
parser.add_argument("arguments", nargs="+")
args = parser.parse_args()
x = ctypes.CDLL("libX11.so.6")
t = ctypes.CDLL("libXtst.so.6")
p = ctypes.c_void_p
x.XOpenDisplay.argtypes = [ctypes.c_char_p]
x.XOpenDisplay.restype = p
x.XCloseDisplay.argtypes = [p]
x.XFlush.argtypes = [p]
x.XStringToKeysym.argtypes = [ctypes.c_char_p]
x.XStringToKeysym.restype = ctypes.c_ulong
x.XKeysymToKeycode.argtypes = [p, ctypes.c_ulong]
x.XKeysymToKeycode.restype = ctypes.c_uint
t.XTestFakeMotionEvent.argtypes = [
    p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_ulong,
]
t.XTestFakeButtonEvent.argtypes = [p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
t.XTestFakeKeyEvent.argtypes = [p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
d = x.XOpenDisplay(args.display.encode())
if not d:
    raise SystemExit("A45 display unavailable")
try:
    if args.operation in {"click", "double"}:
        if len(args.arguments) != 2:
            raise SystemExit("pointer requires x y")
        t.XTestFakeMotionEvent(d, -1, int(args.arguments[0]), int(args.arguments[1]), 0)
        x.XFlush(d)
        time.sleep(0.08)
        for _ in range(2 if args.operation == "double" else 1):
            t.XTestFakeButtonEvent(d, 1, 1, 0)
            x.XFlush(d)
            time.sleep(0.12)
            t.XTestFakeButtonEvent(d, 1, 0, 0)
            x.XFlush(d)
            time.sleep(0.14)
    else:
        if len(args.arguments) != 1:
            raise SystemExit("key requires one X keysym")
        code = x.XKeysymToKeycode(d, x.XStringToKeysym(args.arguments[0].encode()))
        if code == 0:
            raise SystemExit("unknown key")
        t.XTestFakeKeyEvent(d, code, 1, 0)
        x.XFlush(d)
        time.sleep(0.12)
        t.XTestFakeKeyEvent(d, code, 0, 0)
        x.XFlush(d)
finally:
    x.XCloseDisplay(d)
