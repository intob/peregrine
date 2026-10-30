#!/usr/bin/env python3
"""WebSocket connections (HTTP/1.1 upgrade) opened at once, each echoing
MSGS messages of SIZE bytes; once every connection has its echoes back it
prints "echoed", stays idle for IDLE seconds (ws-idle.sh samples the
server's memory meanwhile), then echoes again and closes. With `deflate`,
permessage-deflate is offered and compressed echoes inflated.

Usage: ws-burst.py HOST PORT CONNS MSGS SIZE IDLE_S [deflate]
"""
import asyncio
import struct
import sys
import time
import zlib

UPGRADE = (b'GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
           b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n')


def ws_frame(payload, op=2):
    # A zero masking key: the payload goes as it is (masking 1 MiB in
    # Python takes longer than the test).
    n = len(payload)
    if n < 126:
        hdr = bytes([0x80 | op, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x80 | op, 0x80 | 126]) + struct.pack('>H', n)
    else:
        hdr = bytes([0x80 | op, 0x80 | 127]) + struct.pack('>Q', n)
    return hdr + b'\0\0\0\0' + payload


async def read_frame(r):
    h = await r.readexactly(2)
    n = h[1] & 0x7f
    if n == 126:
        n = struct.unpack('>H', await r.readexactly(2))[0]
    elif n == 127:
        n = struct.unpack('>Q', await r.readexactly(8))[0]
    payload = await r.readexactly(n)
    if h[0] & 0x40:
        payload = zlib.decompressobj(-15).decompress(payload + b'\0\0\xff\xff')
    return h[0] & 0x0f, payload


async def echo(r, w, i, rnd, msgs, size):
    sent = []
    for k in range(msgs):
        p = (struct.pack('>IHH', i, rnd, k) * (size // 8 + 1))[:size]
        sent.append(p)
        w.write(ws_frame(p))
    await w.drain()
    for p in sent:
        op, got = await asyncio.wait_for(read_frame(r), 120)
        if got != p:
            raise Exception(f'conn {i} round {rnd}: wrong echo (op {op}, {len(got)} bytes)')


async def one(host, port, i, msgs, size, deflate, echoed, gate):
    try:
        r, w = await asyncio.open_connection(host, port)
        w.write(UPGRADE + (b'Sec-WebSocket-Extensions: permessage-deflate\r\n' if deflate else b'') + b'\r\n')
        await w.drain()
        head = await asyncio.wait_for(r.readuntil(b'\r\n\r\n'), 30)
        if not head.startswith(b'HTTP/1.1 101'):
            raise Exception(f'conn {i}: {head[:40]!r}')
        if deflate and b'permessage-deflate' not in head:
            raise Exception(f'conn {i}: permessage-deflate not agreed')
        await echo(r, w, i, 0, msgs, size)
    finally:
        # Counted failed or not, so that the idle phase still begins.
        echoed()
    await gate.wait()
    await echo(r, w, i, 1, msgs, size)
    w.write(ws_frame(struct.pack('>H', 1000), op=8))
    await w.drain()
    op, _ = await asyncio.wait_for(read_frame(r), 30)
    if op != 8:
        raise Exception(f'conn {i}: no close, op {op}')
    w.close()


async def main():
    host, port, n, msgs, size, idle = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), float(sys.argv[6])
    deflate = len(sys.argv) > 7 and sys.argv[7] == 'deflate'
    gate = asyncio.Event()
    all_echoed = asyncio.Event()
    left = [n]

    def echoed():
        left[0] -= 1
        if left[0] == 0:
            all_echoed.set()

    t0 = time.time()
    tasks = [asyncio.create_task(one(host, port, i, msgs, size, deflate, echoed, gate)) for i in range(n)]
    await all_echoed.wait()
    print(f'echoed after {time.time() - t0:.1f} s', flush=True)
    await asyncio.sleep(idle)
    gate.set()
    res = await asyncio.gather(*tasks, return_exceptions=True)
    bad = [r for r in res if isinstance(r, Exception)]
    for r in bad[:10]:
        print('FAIL', repr(r), flush=True)
    print(f'done after {time.time() - t0:.1f} s: {n - len(bad)} ok, {len(bad)} failed', flush=True)
    sys.exit(1 if bad else 0)


asyncio.run(main())
