# Minimal HTTP/3 client on aioquic: GET (or POST with -d SIZE) each path,
# concurrently on one connection; prints status and body length.
# Usage: aioquic_client.py HOST PORT PATH... [-n REPEAT] [-d POST_BYTES]
# (in peregrine-h3load; used by bench/scripts/h3-interop.sh)
import asyncio, sys, ssl, time, argparse
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
    def quic_event_received(self, event):
        for e in self.h3.handle_event(event):
            if isinstance(e, (HeadersReceived, DataReceived)):
                r = self.resp.setdefault(e.stream_id, {'headers': [], 'body': bytearray(), 'trailers': []})
                if isinstance(e, HeadersReceived):
                    if r['headers']: r['trailers'] = e.headers
                    else: r['headers'] = e.headers
                else: r['body'] += e.data
                if e.stream_ended:
                    w = self.waiters.pop(e.stream_id, None)
                    if w and not w.done(): w.set_result(r)
    async def request(self, authority, path, body=None):
        sid = self._quic.get_next_available_stream_id()
        hdrs = [(b':method', b'POST' if body else b'GET'), (b':scheme', b'https'),
                (b':authority', authority.encode()), (b':path', path.encode()), (b'user-agent', b'aioquic')]
        self.h3.send_headers(sid, hdrs, end_stream=not body)
        if body: self.h3.send_data(sid, body, end_stream=True)
        fut = self._loop.create_future()
        self.waiters[sid] = fut
        self.transmit()
        return await asyncio.wait_for(fut, 20)

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host'); ap.add_argument('port', type=int); ap.add_argument('paths', nargs='+')
    ap.add_argument('-d', type=int, default=0); ap.add_argument('-n', type=int, default=1)
    a = ap.parse_args()
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE)
    t0 = time.time()
    async with connect(a.host, a.port, configuration=cfg, create_protocol=Client) as c:
        body = b'b' * a.d if a.d else None
        rs = await asyncio.gather(*[c.request(f"{a.host}:{a.port}", p, body) for p in a.paths * a.n])
        for p, r in zip(a.paths * a.n, rs):
            h = dict(r['headers'])
            print(p, h.get(b':status').decode(), len(r['body']), h.get(b'content-type', b'').decode())
    print("ok %.3fs" % (time.time() - t0))
import logging, os
if os.environ.get("DEBUG"): logging.basicConfig(level=logging.DEBUG)
asyncio.run(main())
