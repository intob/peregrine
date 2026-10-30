# HTTP/3 stress client for PMTU discovery runs (bench/scripts/h3-pmtu-stress.sh):
# on one aioquic connection, keeps C requests in flight for DUR seconds:
# GETs of PATH, or POSTs of -d BYTES (uploads), optionally asking for a key
# update every --ku seconds. Prints one line per second (requests done that
# second, the largest datagram received that second) and a summary:
#   done N failed F secs S largest L keyupdates K
# A request that takes longer than --timeout counts as failed (a stall).
# --mds sets aioquic's max_datagram_size (it sends at that size whatever we
# advertise, so --mds 2049+ sends datagrams larger than our receive limit).
# Usage: pmtu_stress.py HOST PORT [--path /1m] [-d BYTES] [-c 4] [--dur 10] [--ku 0] [--mds 1200]
import asyncio, ssl, time, argparse
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration

class Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3Connection(self._quic)
        self.waiters = {}
        self.resp = {}
        self.largest = 0
        self.tick_largest = 0
    def datagram_received(self, data, addr):
        self.largest = max(self.largest, len(data))
        self.tick_largest = max(self.tick_largest, len(data))
        super().datagram_received(data, addr)
    def quic_event_received(self, event):
        for e in self.h3.handle_event(event):
            if isinstance(e, (HeadersReceived, DataReceived)):
                r = self.resp.setdefault(e.stream_id, {'headers': [], 'n': 0})
                if isinstance(e, HeadersReceived):
                    if not r['headers']: r['headers'] = e.headers
                else: r['n'] += len(e.data)
                if e.stream_ended:
                    w = self.waiters.pop(e.stream_id, None)
                    self.resp.pop(e.stream_id, None)
                    if w and not w.done(): w.set_result(r)
    async def request(self, authority, path, body, timeout):
        sid = self._quic.get_next_available_stream_id()
        hdrs = [(b':method', b'POST' if body else b'GET'), (b':scheme', b'https'),
                (b':authority', authority.encode()), (b':path', path.encode())]
        self.h3.send_headers(sid, hdrs, end_stream=not body)
        if body: self.h3.send_data(sid, body, end_stream=True)
        fut = self._loop.create_future()
        self.waiters[sid] = fut
        self.transmit()
        return await asyncio.wait_for(fut, timeout)

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host'); ap.add_argument('port', type=int)
    ap.add_argument('--path', default='/1m'); ap.add_argument('-d', type=int, default=0)
    ap.add_argument('-c', type=int, default=4); ap.add_argument('--dur', type=float, default=10)
    ap.add_argument('--ku', type=float, default=0); ap.add_argument('--mds', type=int, default=0)
    ap.add_argument('--timeout', type=float, default=15)
    a = ap.parse_args()
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE,
                            max_data=64 << 20, max_stream_data=16 << 20, idle_timeout=30)
    if a.mds: cfg.max_datagram_size = a.mds
    body = b'u' * a.d if a.d else None
    want = 1 << 20 if a.path == '/1m' else (65536 if a.path == '/64k' else None)
    stats = {'done': 0, 'failed': 0, 'ku': 0, 'sec': 0}
    t0 = time.time()
    async with connect(a.host, a.port, configuration=cfg, create_protocol=Client, wait_connected=True) as c:
        auth = f"{a.host}:{a.port}"
        async def worker():
            while time.time() - t0 < a.dur:
                try:
                    r = await c.request(auth, a.path, body, a.timeout)
                    st = dict(r['headers']).get(b':status')
                    if st != b'200' or (not body and want and r['n'] != want):
                        print("bad", st, r['n'], flush=True); stats['failed'] += 1
                    else:
                        stats['done'] += 1; stats['sec'] += 1
                except asyncio.TimeoutError:
                    print("timeout at %.1fs" % (time.time() - t0), flush=True); stats['failed'] += 1
                    return
        async def ticker():
            last_ku = time.time()
            while time.time() - t0 < a.dur:
                await asyncio.sleep(0.25)
                if a.ku and time.time() - last_ku >= a.ku:
                    try:
                        c._quic.request_key_update(); stats['ku'] += 1; c.transmit()
                    except Exception as e:
                        print("key update refused:", e, flush=True)
                    last_ku = time.time()
                if int((time.time() - t0) * 4) % 4 == 0:
                    print("t=%.0f n=%d max=%d" % (time.time() - t0, stats['sec'], c.tick_largest), flush=True)
                    stats['sec'] = 0; c.tick_largest = 0
        await asyncio.gather(ticker(), *[worker() for _ in range(a.c)])
        largest = c.largest
    print("done %d failed %d secs %.2f largest %d keyupdates %d" % (stats['done'], stats['failed'], time.time() - t0, largest, stats['ku']), flush=True)

asyncio.run(main())
