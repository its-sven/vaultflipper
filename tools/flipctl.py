# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""Drive a Flipper Zero over USB RPC: press keys and take PNG screenshots.

Run `make protos` once, then:

  uv run --no-project --with protobuf --with pyserial tools/flipctl.py shot out.png
  ... tools/flipctl.py keys "U U D D OK" out.png [--wait 1.5]
  ... tools/flipctl.py launch /ext/apps/Tools/vaultflipper.fap out.png

Keys: U D L R OK BACK, and BACKLONG for a long press.
`keys` only sends when the VaultFlipper title bar is on screen, so stray
presses never reach the Flipper desktop; --any skips that check.
Never send a key that starts typing while another window has focus.
"""
import glob
import struct
import sys
import time
import zlib

sys.path.insert(0, __file__.rsplit("/", 1)[0] + "/.proto-gen")
import serial  # noqa: E402

import flipper_pb2  # noqa: E402
import gui_pb2  # noqa: E402

KEYS = {"U": gui_pb2.UP, "D": gui_pb2.DOWN, "L": gui_pb2.LEFT, "R": gui_pb2.RIGHT, "OK": gui_pb2.OK, "BACK": gui_pb2.BACK}


class Rpc:
    def __init__(self):
        ports = sorted(glob.glob("/dev/cu.usbmodemflip_*") + glob.glob("/dev/serial/by-id/*Flipper*"))
        if not ports:
            sys.exit("No Flipper found - connect it and quit qFlipper.")
        port = ports[0]
        self.s = serial.Serial(port, 230400, timeout=3)
        time.sleep(0.2)
        # end a stale RPC session, then wait for the CLI prompt
        stop = flipper_pb2.Main(command_id=999, stop_session=flipper_pb2.StopSession()).SerializeToString()
        self.s.write(bytes([len(stop)]) + stop)
        time.sleep(0.3)
        self.s.reset_input_buffer()
        self.s.write(b"\r")
        if not self.s.read_until(b">: ").endswith(b">: "):
            raise RuntimeError("no CLI prompt")
        self.s.write(b"start_rpc_session\r")
        self.s.read_until(b"\n")
        self.cid = 0
        self.last_frame = None

    def _varint(self, n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out

    def send(self, **kw):
        self.cid += 1
        m = flipper_pb2.Main(command_id=self.cid, **kw)
        data = m.SerializeToString()
        self.s.write(self._varint(len(data)) + data)
        return self.cid

    def read_msg(self, timeout=3):
        self.s.timeout = timeout
        shift, n = 0, 0
        while True:
            b = self.s.read(1)
            if not b:
                return None
            n |= (b[0] & 0x7F) << shift
            shift += 7
            if not b[0] & 0x80:
                break
        data = b""
        while len(data) < n:  # read() may return less than asked for
            part = self.s.read(n - len(data))
            if not part:
                return None
            data += part
        m = flipper_pb2.Main()
        m.ParseFromString(data)
        if m.HasField("gui_screen_frame"):
            self.last_frame = m.gui_screen_frame.data
        return m

    def wait_reply(self, cid, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            m = self.read_msg(timeout=end - time.time())
            if m is None:
                break
            if m.command_id == cid and not m.HasField("gui_screen_frame"):
                return m
        raise TimeoutError(f"no reply to {cid}")

    def pump(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self.read_msg(timeout=max(0.05, end - time.time()))

    def key(self, name):
        long = name.endswith("LONG")
        k = KEYS[name.removesuffix("LONG")]
        seq = [gui_pb2.PRESS, gui_pb2.LONG if long else gui_pb2.SHORT, gui_pb2.RELEASE]
        for t in seq:
            cid = self.send(gui_send_input_event_request=gui_pb2.SendInputEventRequest(key=k, type=t))
            self.wait_reply(cid)
            if long and t == gui_pb2.PRESS:
                time.sleep(0.4)

    def close(self):
        try:
            self.send(stop_session=flipper_pb2.StopSession())
            time.sleep(0.2)
        finally:
            self.s.close()


def save_png(frame, path, scale=4):
    w, h = 128, 64
    px = [[0] * w for _ in range(h)]
    for page in range(8):
        for x in range(w):
            b = frame[page * w + x]
            for bit in range(8):
                px[page * 8 + bit][x] = (b >> bit) & 1
    raw = b""
    for y in range(h * scale):
        row = bytearray([0])
        for x in range(w * scale):
            on = px[y // scale][x // scale]
            row += bytes([0x10, 0x10, 0x10] if on else [0xFF, 0x8C, 0x29])
        raw += bytes(row)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w * scale, h * scale, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
    open(path, "wb").write(png)


def grab_frame(r, wait=0.6):
    cid = r.send(gui_start_screen_stream_request=gui_pb2.StartScreenStreamRequest())
    r.wait_reply(cid)
    r.pump(wait)
    cid = r.send(gui_stop_screen_stream_request=gui_pb2.StopScreenStreamRequest())
    try:
        r.wait_reply(cid)
    except TimeoutError:
        pass
    return r.last_frame


def app_on_screen(frame):
    """VaultFlipper screens start with a full-width black title bar (top pixel row lit)."""
    return bool(frame) and all(frame[x] & 1 for x in range(128))


def screenshot(r, path, wait):
    frame = grab_frame(r, wait)
    if frame:
        base = path.removesuffix(".png")
        save_png(frame, base + ".png")
        save_png(frame, base + "_1x.png", scale=1)
        print("screenshot", base + ".png")
    else:
        print("no frame")


def main():
    args = sys.argv[1:]
    wait = 1.0
    guard = "--any" not in args
    args = [a for a in args if a != "--any"]
    if "--wait" in args:
        i = args.index("--wait")
        wait = float(args[i + 1])
        del args[i : i + 2]
    r = Rpc()
    try:
        cmd = args[0]
        if cmd == "shot":
            screenshot(r, args[1], wait)
        elif cmd == "keys":
            if guard and not app_on_screen(grab_frame(r)):
                print("VaultFlipper is not on screen - no keys sent")
                sys.exit(3)
            for k in args[1].split():
                r.key(k)
                time.sleep(0.12)
            screenshot(r, args[2], wait)
        elif cmd == "launch":
            import application_pb2

            cid = r.send(app_start_request=application_pb2.StartRequest(name=args[1], args=""))
            print(r.wait_reply(cid).command_status)
            screenshot(r, args[2], wait)
    finally:
        r.close()


if __name__ == "__main__":
    main()
