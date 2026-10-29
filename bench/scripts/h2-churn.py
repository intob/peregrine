#!/usr/bin/env python3
"""HTTP/2 churn client for bench/verify_server.zig: many connections, mixed
sizes and routes, every byte checked.

Each body is a window into the server's pattern (64-bit LE words, word w =
w*8 | 0xA5<<56), so a byte from another response or connection is caught
and its origin decoded. Connections vary: slow readers (small reads, late
WINDOW_UPDATEs), large or small frame sizes and windows, HEAD, trailers,
RST_STREAM mid-response, PINGs, WebSockets over h2 (extended CONNECT),
GOAWAY, and abrupt closes with output queued.

Usage: h2-churn.py HOST PORT tls|h2c SECONDS CONNS [seed]
Needs python h2 (the peregrine-ws-interop image). Exit status 1 on any
mismatch or unexpected error.
"""
import array
import asyncio
import os
import random
import ssl
import struct
import sys
import time

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings

PATTERN_LEN = 32 * 1024 * 1024
pattern = array.array('Q', (w * 8 | 0xA5 << 56 for w in range(PATTERN_LEN // 8))).tobytes()
assert sys.byteorder == 'little'

SIZES = [0, 1, 13, 100, 1000, 16375, 16384, 16393, 32768, 65536, 65537,
         100_000, 262_144, 300_000, 1_048_576, 3_000_000]

stats = {'requests': 0, 'bytes': 0, 'heads': 0, 'resets': 0, 'ws': 0,
         'ws_msgs': 0, 'aborts': 0, 'goaways': 0, 'conns': 0, 'trailers': 0}
failures = []
live = set()
WS_PROB = float(os.environ.get('WS_PROB', '0.04'))


def fail(msg):
    failures.append(msg)
    print('FAIL', msg, flush=True)


def describe(got, off, length):
    """Where the first wrong byte is, and where it came from."""
    want = pattern[off:off + length]
    if len(got) != len(want):
        prefix = os.path.commonprefix([got, want])
        return f'length {len(got)} != {len(want)}, first {len(prefix)} bytes right'
    for i in range(len(got)):
        if got[i] != want[i]:
            break
    # Decode the word at the wrong byte's position, as the server wrote it.
    a = (off + i) & ~7
    j = a - off
    if j >= 0 and j + 8 <= len(got):
        w = struct.unpack('<Q', got[j:j + 8])[0]
        src = f'word {w:#x}'
        if w >> 56 == 0xA5:
            src += f' (pattern offset {w & ((1 << 56) - 1)}, expected {a})'
    else:
        src = repr(got[i:i + 16])
    return f'first wrong byte at {i} of {length} (offset {off}): {src}'


class Stream:
    def __init__(self, kind, method, off, length, path):
        self.kind, self.method, self.off, self.length, self.path = kind, method, off, length, path
        self.status = None
        self.headers = {}
        self.trailers = None
        self.body = bytearray()
        self.done = asyncio.get_running_loop().create_future()
        self.reset_by_us = False
        self.reset_at = None  # reset after this many body bytes
        self.ws = None


class WsState:
    def __init__(self):
        self.buf = bytearray()
        self.frames = asyncio.Queue()


def ws_frame(opcode, payload):
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        head = struct.pack('!BB', 0x80 | opcode, 0x80 | n)
    elif n < 65536:
        head = struct.pack('!BBH', 0x80 | opcode, 0x80 | 126, n)
    else:
        head = struct.pack('!BBQ', 0x80 | opcode, 0x80 | 127, n)
    if n:
        rep = (mask * (n // 4 + 1))[:n]
        masked = (int.from_bytes(payload, 'big') ^ int.from_bytes(rep, 'big')).to_bytes(n, 'big')
    else:
        masked = b''
    return head + mask + masked


def ws_parse(st):
    """Server frames (unmasked) out of st.buf."""
    b = st.buf
    while len(b) >= 2:
        opcode = b[0] & 0x0f
        n = b[1] & 0x7f
        p = 2
        if b[1] & 0x80:
            raise ValueError('masked server frame')
        if n == 126:
            if len(b) < 4:
                return
            n = struct.unpack('!H', b[2:4])[0]
            p = 4
        elif n == 127:
            if len(b) < 10:
                return
            n = struct.unpack('!Q', b[2:10])[0]
            p = 10
        if len(b) < p + n:
            return
        st.frames.put_nowait((b[0] & 0x80 != 0, opcode, bytes(b[p:p + n])))
        del b[:p + n]


class Client:
    def __init__(self, host, port, tls, rng, deadline):
        self.host, self.port, self.tls, self.rng, self.deadline = host, port, tls, rng, deadline
        self.streams = {}
        self.closed = asyncio.get_running_loop().create_future()
        self.aborting = False
        self.goaway = False
        self.lock = asyncio.Lock()
        r = rng
        self.slow = r.random() < 0.25
        self.read_size = r.choice([512, 1000, 4096]) if self.slow else 65536
        self.slow_sleep = [0.001, 0.005] if self.read_size > 7 else [0]
        self.window = r.choice([65535, 65535, 1 << 20, 1 << 24, 16384, 1000])
        self.max_frame = r.choice([16384, 16384, 16384, 65536, 1 << 20, (1 << 24) - 1])
        self.conc = r.choice([1, 2, 10, 10, 30, 100])
        self.nreq = r.choice([1, 5, 20, 100, 300])
        # FORCE="slow=1,read_size=4096,window=65535,...": fix some choices.
        for kv in filter(None, os.environ.get('FORCE', '').split(',')):
            k, v = kv.split('=')
            setattr(self, k, type(getattr(self, k))(int(v)))
        self.slow_sleep = [0.001, 0.005] if self.slow else [0]

    async def run(self):
        ctx = None
        if self.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2'])
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port, ssl=ctx)
        sock = self.writer.get_extra_info('socket')
        if self.slow and sock is not None:
            import socket
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            except OSError:
                pass
        cfg = h2.config.H2Configuration(client_side=True, header_encoding='utf-8')
        self.conn = h2.connection.H2Connection(config=cfg)
        self.conn.local_settings = h2.settings.Settings(client=True, initial_values={
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: self.window,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: self.max_frame,
            h2.settings.SettingCodes.ENABLE_PUSH: 0,
        })
        # Initial values count as acknowledged in h2's Settings, so the
        # frame size it accepts must be raised by hand.
        self.conn.max_inbound_frame_size = self.max_frame
        self.conn.incoming_buffer.max_frame_size = self.max_frame
        self.conn.initiate_connection()
        if self.rng.random() < 0.5:
            self.conn.increment_flow_control_window((1 << 31) - 1 - 65535)
        await self.flush()
        stats['conns'] += 1
        live.add(self)
        rtask = asyncio.create_task(self.read_loop())
        try:
            await self.workload()
        finally:
            live.discard(self)
            if not self.aborting:
                try:
                    self.conn.close_connection()
                    await self.flush()
                except Exception:
                    pass
            self.writer.close()
            rtask.cancel()
            try:
                await rtask
            except (asyncio.CancelledError, Exception):
                pass

    def windows(self, sid):
        c = self.conn
        try:
            st = c._get_stream_by_id(sid)
            return (f'send: stream {c.local_flow_control_window(sid)} conn {c.outbound_flow_control_window}; '
                    f'recv: stream {st._inbound_window_manager.current_window_size} '
                    f'conn {c._inbound_flow_control_window_manager.current_window_size}; '
                    f'unsent {len(c.data_to_send(0)) if False else self.writer.transport.get_write_buffer_size()}')
        except Exception as e:
            return f'windows: {e}'

    async def flush(self):
        # No drain: blocking on a write while holding the lock would stop
        # reading, and the server doesn't read while its output is unsent.
        data = self.conn.data_to_send()
        if data:
            self.writer.write(data)

    async def read_loop(self):
        try:
            while True:
                data = await self.reader.read(self.read_size)
                if not data:
                    break
                if self.slow:
                    await asyncio.sleep(self.rng.choice([0] * 8 + self.slow_sleep))
                async with self.lock:
                    events = self.conn.receive_data(data)
                    for ev in events:
                        self.on_event(ev)
                    await self.flush()
        except Exception as e:
            if not self.aborting and not self.goaway:
                import traceback
                traceback.print_exc()
                fail(f'read loop: {type(e).__name__}: {e} (slow={self.slow} window={self.window} max_frame={self.max_frame})')
        finally:
            for s in self.streams.values():
                if not s.done.done():
                    s.done.set_result('closed')
            if not self.closed.done():
                self.closed.set_result(True)

    def on_event(self, ev):
        if isinstance(ev, h2.events.ResponseReceived):
            s = self.streams.get(ev.stream_id)
            if s:
                s.headers = dict(ev.headers)
                s.status = s.headers.get(':status')
                if s.ws is not None and s.status != '200':
                    s.done.set_result('ws refused')
        elif isinstance(ev, h2.events.DataReceived):
            s = self.streams.get(ev.stream_id)
            if ev.flow_controlled_length:
                try:
                    self.conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                except h2.exceptions.StreamClosedError:
                    pass
            if not s:
                return
            if s.ws is not None:
                s.ws.buf += ev.data
                try:
                    ws_parse(s.ws)
                except ValueError as e:
                    fail(f'ws stream {ev.stream_id}: {e}')
                return
            s.body += ev.data
            if s.reset_at is not None and len(s.body) >= s.reset_at and not s.reset_by_us:
                s.reset_by_us = True
                try:
                    self.conn.reset_stream(ev.stream_id, 8)
                except h2.exceptions.StreamClosedError:
                    return  # ended in this read: check it whole
                stats['resets'] += 1
                if not s.done.done():
                    s.done.set_result('reset')
        elif isinstance(ev, h2.events.TrailersReceived):
            s = self.streams.get(ev.stream_id)
            if s:
                s.trailers = dict(ev.headers)
        elif isinstance(ev, h2.events.StreamEnded):
            s = self.streams.get(ev.stream_id)
            if s and not s.done.done():
                s.done.set_result('ended')
        elif isinstance(ev, h2.events.StreamReset):
            s = self.streams.get(ev.stream_id)
            if s and not s.done.done():
                s.done.set_result(f'rst {ev.error_code}')
        elif isinstance(ev, h2.events.ConnectionTerminated):
            if not self.goaway:
                fail(f'GOAWAY from server: {ev.error_code} {ev.additional_data}')
            self.goaway = True

    async def workload(self):
        r = self.rng
        sem = asyncio.Semaphore(self.conc)
        abort_after = r.randrange(1, self.nreq + 1) if r.random() < 0.05 else None
        goaway_after = r.randrange(1, self.nreq + 1) if r.random() < 0.03 else None
        tasks = []
        for i in range(self.nreq):
            if time.monotonic() > self.deadline or self.closed.done():
                break
            if abort_after is not None and i == abort_after:
                # Close with responses queued on the server.
                await asyncio.sleep(r.choice([0, 0.001, 0.01]))
                self.aborting = True
                stats['aborts'] += 1
                self.writer.transport.abort()
                break
            if goaway_after is not None and i == goaway_after:
                async with self.lock:
                    self.goaway = True
                    stats['goaways'] += 1
                    self.conn.close_connection()
                    await self.flush()
                break
            await sem.acquire()
            t = asyncio.create_task(self.one(sem))
            tasks.append(t)
            if r.random() < 0.05:
                async with self.lock:
                    self.conn.ping(os.urandom(8))
                    await self.flush()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def one(self, sem):
        try:
            if self.rng.random() < WS_PROB:
                await self.websocket()
            else:
                await self.request()
        except Exception as e:
            if not self.aborting and not self.goaway and not self.closed.done():
                fail(f'stream: {type(e).__name__}: {e}')
        finally:
            sem.release()

    async def request(self):
        r = self.rng
        kind = r.choice('ppppffsstth')
        length = r.choice(SIZES)
        if kind in 'st':
            length = min(length, 1_048_576)
        off = r.randrange(0, PATTERN_LEN - length + 1)
        path = f'/{kind}/{off}/{length}'
        if kind == 'h':
            path += f'/{r.choice([0, 100, 5000, 16000, 20000, 40000, 60000])}'
        method = 'HEAD' if r.random() < 0.1 else 'GET'
        scheme = 'https' if self.tls else 'http'
        async with self.lock:
            if self.closed.done() or self.goaway:
                return
            sid = self.conn.get_next_available_stream_id()
            s = Stream(kind, method, off, length, path)
            if method == 'GET' and length > 0 and r.random() < 0.05:
                s.reset_at = r.randrange(0, length)
            self.streams[sid] = s
            self.conn.send_headers(sid, [(':method', method), (':scheme', scheme), (':path', path),
                                         (':authority', self.host)], end_stream=True)
            await self.flush()
        res = await s.done
        del self.streams[sid]
        if res in ('reset', 'closed') or self.aborting or self.goaway:
            return
        if res != 'ended':
            return fail(f'{method} {path}: {res}')
        stats['requests'] += 1
        if s.status != '200':
            return fail(f'{method} {path}: status {s.status}')
        if method == 'HEAD':
            stats['heads'] += 1
            if s.body:
                fail(f'HEAD {path}: {len(s.body)} body bytes')
            return
        stats['bytes'] += len(s.body)
        if bytes(s.body) != pattern[off:off + length]:
            fail(f'GET {path} (slow={self.slow} window={self.window} max_frame={self.max_frame}): {describe(bytes(s.body), off, length)}')
        if kind == 'h' and len(s.headers.get('x-pad', '')) != int(path.rsplit('/', 1)[1]):
            fail(f'GET {path}: x-pad length {len(s.headers.get("x-pad", ""))}')
        if kind == 't':
            stats['trailers'] += 1
            if not s.trailers or s.trailers.get('x-off') != str(off):
                fail(f'GET {path}: trailers {s.trailers}')

    async def websocket(self):
        r = self.rng
        scheme = 'https' if self.tls else 'http'
        async with self.lock:
            if self.closed.done() or self.goaway:
                return
            sid = self.conn.get_next_available_stream_id()
            s = Stream('ws', 'CONNECT', 0, 0, '/ws')
            s.ws = WsState()
            self.streams[sid] = s
            self.conn.send_headers(sid, [(':method', 'CONNECT'), (':protocol', 'websocket'), (':scheme', scheme),
                                         (':path', '/ws'), (':authority', self.host), ('sec-websocket-version', '13')])
            await self.flush()
        # Wait for the 200.
        for _ in range(500):
            if s.status is not None or s.done.done():
                break
            await asyncio.sleep(0.005)
        if s.status != '200':
            if not s.done.done() and not self.aborting and not self.goaway:
                fail(f'ws: no 200 ({s.status})')
            return
        stats['ws'] += 1
        for _ in range(r.choice([1, 3, 10])):
            n = r.choice([0, 5, 125, 126, 65535, 65536, 300_000])
            off = r.randrange(0, PATTERN_LEN - n)
            payload = pattern[off:off + n]
            frame = ws_frame(2, payload)
            pos = 0
            while pos < len(frame):
                async with self.lock:
                    if s.done.done() or self.closed.done():
                        return
                    room = min(self.conn.local_flow_control_window(sid), self.conn.max_outbound_frame_size)
                    if room > 0:
                        k = min(room, len(frame) - pos)
                        self.conn.send_data(sid, frame[pos:pos + k])
                        pos += k
                    await self.flush()
                if pos < len(frame):
                    await asyncio.sleep(0.002)
            try:
                fin, op, got = await asyncio.wait_for(s.ws.frames.get(), 60)
            except asyncio.TimeoutError:
                if not self.aborting and not self.goaway and not self.closed.done():
                    fail(f'ws: no echo of {n} bytes (slow={self.slow} rs={self.read_size} window={self.window} max_frame={self.max_frame} conc={self.conc} got={len(s.ws.buf)} status={s.status} done={s.done.done() and s.done.result()} {self.windows(sid)})')
                return
            stats['ws_msgs'] += 1
            if op != 2 or got != payload:
                fail(f'ws: echo of {n} bytes wrong (op {op}, {len(got)} bytes)')
        async with self.lock:
            if s.done.done() or self.closed.done():
                return
            if r.random() < 0.5 and self.conn.local_flow_control_window(sid) >= 8:
                self.conn.send_data(sid, ws_frame(8, struct.pack('!H', 1000)))
            self.conn.end_stream(sid)
            await self.flush()
        try:
            await asyncio.wait_for(s.done, 10)
        except asyncio.TimeoutError:
            if not self.aborting and not self.goaway:
                fail('ws: stream did not end')
        self.streams.pop(sid, None)


async def main():
    host, port, mode, secs, conns = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4]), int(sys.argv[5])
    seed = int(sys.argv[6]) if len(sys.argv) > 6 else int.from_bytes(os.urandom(4), 'big')
    print(f'seed {seed}', flush=True)
    master = random.Random(seed)
    deadline = time.monotonic() + secs

    async def lane():
        while time.monotonic() < deadline and len(failures) < 20:
            c = Client(host, port, mode == 'tls', random.Random(master.getrandbits(64)), deadline)
            try:
                await c.run()
            except Exception as e:
                if not c.aborting and not c.goaway:
                    fail(f'connection: {type(e).__name__}: {e}')
    try:
        await asyncio.wait_for(asyncio.gather(*(lane() for _ in range(conns))), secs + 60)
    except asyncio.TimeoutError:
        for c in live:
            pend = [(sid, st.path, st.method, len(st.body), st.status) for sid, st in c.streams.items()]
            fail(f'stuck: slow={c.slow} window={c.window} max_frame={c.max_frame} streams {pend[:10]}')
    print(' '.join(f'{k}={v}' for k, v in stats.items()), f'failures={len(failures)}', flush=True)
    sys.exit(1 if failures else 0)


asyncio.run(main())
