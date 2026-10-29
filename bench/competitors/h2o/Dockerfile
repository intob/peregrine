# comp-h2o23: h2o 2.3.0-DEV (master at d21e7cb, 2026-10-07; h2o has not tagged
# 2.3.0 past beta2) with HTTP/1.1, h2c, TLS h2 and HTTP/3 (quicly), built 2026-10-29:
#   docker build -t comp-h2o23 bench/competitors/h2o
# Run: h2o -c /etc/h2o.conf, with the repository's bench/ mounted at /bench for
# the certificate (bench/scripts/h2-bench.sh does this). h2c on 8080, TLS
# and QUIC on 8443, 6 threads, static files.
FROM alpine:3.21
RUN apk add --no-cache build-base git cmake openssl-dev zlib-dev perl linux-headers util-linux-misc
RUN git clone https://github.com/h2o/h2o /src && cd /src && git checkout d21e7cb56258bc499e16349d398198222e77c9b1
WORKDIR /src/build
# -O3 -march=native as for the other competitors (build type None: Release
# would append h2o's own -O2 after them).
RUN cmake -DCMAKE_BUILD_TYPE=None -DWITH_MRUBY=off -DCMAKE_C_FLAGS="-O3 -march=native" .. && \
    make -j8 h2o && make install
RUN mkdir -p /www && printf 'Hello, World!' > /www/hello.txt && \
    head -c 65536 /dev/zero | tr '\0' x > /www/64k.txt
COPY h2o.conf /etc/h2o.conf
