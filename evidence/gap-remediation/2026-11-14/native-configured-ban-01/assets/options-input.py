"""Prepared only: XTest input to the owned :114 display; never blind Save."""
import ctypes
import sys
import time

X = ctypes.CDLL('libX11.so.6')
T = ctypes.CDLL('libXtst.so.6')
P = ctypes.c_void_p
X.XOpenDisplay.argtypes = [ctypes.c_char_p]
X.XOpenDisplay.restype = P
X.XFlush.argtypes = [P]
X.XCloseDisplay.argtypes = [P]
X.XStringToKeysym.argtypes = [ctypes.c_char_p]
X.XStringToKeysym.restype = ctypes.c_ulong
X.XKeysymToKeycode.argtypes = [P, ctypes.c_ulong]
X.XKeysymToKeycode.restype = ctypes.c_ubyte
T.XTestFakeMotionEvent.argtypes = [P, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
T.XTestFakeButtonEvent.argtypes = [P, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
T.XTestFakeKeyEvent.argtypes = [P, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
d = X.XOpenDisplay(b':114')
if not d:
    raise SystemExit('owned display unavailable')

def key(name, down):
    """Press or release a named key on the display."""
    code = X.XKeysymToKeycode(d, X.XStringToKeysym(name.encode()))
    if not code:
        raise SystemExit('unsupported key')
    T.XTestFakeKeyEvent(d, code, int(down), 0)
    X.XFlush(d)
    time.sleep(.035)

def click(x, y):
    """Move the pointer to a position and click the primary button."""
    T.XTestFakeMotionEvent(d, -1, x, y, 0)
    X.XFlush(d)
    time.sleep(.15)
    T.XTestFakeButtonEvent(d, 1, 1, 0)
    X.XFlush(d)
    time.sleep(.12)
    T.XTestFakeButtonEvent(d, 1, 0, 0)
    X.XFlush(d)
    time.sleep(.12)

def type_public(value):
    """Type the address 10.0.2.2, refusing any other value."""
    if value != '10.0.2.2':
        raise SystemExit('unexpected public IP input')
    for char in value:
        name = 'period' if char == '.' else char
        key(name, 1)
        key(name, 0)
        time.sleep(.02)

try:
    op = sys.argv[1]
    if op == 'click' and len(sys.argv) == 4:
        click(int(sys.argv[2]), int(sys.argv[3]))
    elif op == 'type-public' and len(sys.argv) == 3:
        type_public(sys.argv[2])
    else:
        raise SystemExit('expected click x y or type-public 10.0.2.2')
finally:
    X.XFlush(d)
    X.XCloseDisplay(d)
