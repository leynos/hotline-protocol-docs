"""Send one recorded keyboard or pointer input to display :112 through X11 and XTest."""
import ctypes
import sys
import time

x = ctypes.CDLL('libX11.so.6')
t = ctypes.CDLL('libXtst.so.6')
p = ctypes.c_void_p
x.XOpenDisplay.argtypes = [ctypes.c_char_p]
x.XOpenDisplay.restype = p
x.XFlush.argtypes = [p]
x.XCloseDisplay.argtypes = [p]
x.XStringToKeysym.argtypes = [ctypes.c_char_p]
x.XStringToKeysym.restype = ctypes.c_ulong
x.XKeysymToKeycode.argtypes = [p, ctypes.c_ulong]
x.XKeysymToKeycode.restype = ctypes.c_ubyte
t.XTestFakeMotionEvent.argtypes = [p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
t.XTestFakeButtonEvent.argtypes = [p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
t.XTestFakeKeyEvent.argtypes = [p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
d = x.XOpenDisplay(b':112')
if not d:
    raise SystemExit('display unavailable')
operation = sys.argv[1]
if operation in ('click', 'double-click'):
    t.XTestFakeMotionEvent(d, -1, int(sys.argv[2]), int(sys.argv[3]), 0)
    x.XFlush(d)
    time.sleep(.1)
    for _ in range(2 if operation == 'double-click' else 1):
        t.XTestFakeButtonEvent(d, 1, 1, 0)
        x.XFlush(d)
        time.sleep(.12)
        t.XTestFakeButtonEvent(d, 1, 0, 0)
        x.XFlush(d)
        time.sleep(.14)
elif operation == 'key':
    code = x.XKeysymToKeycode(d, x.XStringToKeysym(sys.argv[2].encode()))
    t.XTestFakeKeyEvent(d, code, 1, 0)
    x.XFlush(d)
    time.sleep(.1)
    t.XTestFakeKeyEvent(d, code, 0, 0)
    x.XFlush(d)
else:
    raise SystemExit('unknown operation')
x.XCloseDisplay(d)
